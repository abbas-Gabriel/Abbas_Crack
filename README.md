# 🔓 Abbas Crack v4.0

<div align="center">

**TUI لوحين · سكان الشبكات + سحب إلى خانة Handshake + كسر تلقائي**
**يعمل على Termux و Kali Linux بدون scapy**

![Version](https://img.shields.io/badge/version-4.0-red)
![Python](https://img.shields.io/badge/python-3.7%2B-blue)
![Platform](https://img.shields.io/badge/platform-Kali%20%7C%20Termux-black)
![License](https://img.shields.io/badge/license-تعليمي-orange)

**المبرمج: جنرال عباس 🇮🇶**

📸 [Instagram: @s.nfu](https://instagram.com/s.nfu)

</div>

---

## 📖 نظرة عامة

**Abbas Crack v4.0** أداة متكاملة لكسر شبكات WiFi المحمية بـ WPA/WPA2 PSK،
بواجهة **TUI من لوحين** بأسلوب Wifite:

```
لوح يسار:  قائمة الشبكات المكتشفة (سكان مباشر)
لوح يمين:  خانة Handshake — تسحب الشبكة إليها فتبدأ الهجوم والكسر
```

الأداة تقرأ ملفات `.pcap` **بدون scapy** — تعمل بسلاسة على Termux و Kali
والأجهزة ذات الموارد المحدودة.

---

## 👤 عن المبرمج

- **الاسم:** جنرال عباس
- **الدولة:** العراق 🇮🇶
- **التخصص:** أمن الشبكات اللاسلكية، اختبار اختراق WiFi
- **Instagram:** [@s.nfu](https://instagram.com/s.nfu)

---

## 🌐 سكان الشبكات في Kali Linux

هذه الميزة الأساسية — **جلب الشبكات المحيطة (Network Fetching)**.
تعمل عبر `airodump-ng` في monitor mode، تقرأ ملف CSV الناتج، تحلّله،
وتعرضه في قائمة مرقمة.

### كيف يعمل السكان؟

```
1. تفعيل monitor mode عبر airmon-ng
2. تشغيل airodump-ng لمدة محددة (25 ثانية افتراضياً)
3. قراءة ملف CSV الناتج
4. تحليل: BSSID · القناة · قوة الإشارة · التشفير · اسم الشبكة
5. ترتيب حسب قوة الإشارة
6. عرض في اللوح الأيسر من الـ TUI
```

### شرط أساسي: أدابتر يدعم Monitor Mode

```bash
# تفعيل monitor mode
sudo airmon-ng check kill
sudo airmon-ng start wlan0

# تحقق
iw dev
```

---

## ⚙️ المتطلبات

### الأنظمة المدعومة
- **Kali Linux** (موصى به)
- **Ubuntu / Debian**
- **Termux** (root + أدابتر خارجي)
- **Parrot OS**

### البرمجيات
```bash
sudo apt update
sudo apt install -y aircrack-ng python3 python3-pip wireless-tools iw
```

### العتاد
- **كرت شبكة يدعم Monitor Mode + Packet Injection**
- الموصى بها:
  - Alfa AWUS036NHA (Atheros AR9271)
  - Alfa AWUS036ACH (Realtek RTL8812AU)
  - TP-Link TL-WN722N **v1 فقط** (AR9271)
  - RTL8187 (Monitor Mode in-place)

> ⚠️ الكروت الداخلية للابتوب غالباً لا تدعم Packet Injection.
> ⚠️ داخل VM، يجب تمرير أدابتر USB للـ VM.

---

## 🚀 التثبيت

```bash
# 1. احفظ الكود في ملف
nano abbas_crack.py

# 2. اجعله قابل للتنفيذ
chmod +x abbas_crack.py

# 3. أنشئ قائمة كلمات السر
mkdir -p ~/abbas_crack/hs
echo -e "12345678\npassword\nadmin123\nqwerty" > ~/abbas_crack/pass123.txt

# 4. أو انسخ rockyou كامل
cp /usr/share/wordlists/rockyou.txt ~/abbas_crack/pass123.txt
```

---

## 📚 أوامر التنفيذ

| الأمر | الوصف |
|------|-------|
| `sudo python3 abbas_crack.py` | TUI لوحين كامل |
| `sudo python3 abbas_crack.py --iface wlan0mon` | تحديد واجهة يدوياً |
| `sudo python3 abbas_crack.py --wordlist /path/wl.txt` | قائمة كلمات مخصصة |
| `sudo python3 abbas_crack.py --scan-time 60` | مدة سكان 60s |
| `sudo python3 abbas_crack.py --attack-timeout 300` | مدة هجوم 300s |
| `sudo python3 abbas_crack.py -j 4` | 4 معالجات |
| `sudo python3 abbas_crack.py --single` | معالج مفرد |
| `sudo python3 abbas_crack.py --no-tui` | بدون curses (Termux) |

---

## 🎮 دليل الـ TUI

```
┌─ Networks ──────────────┐  ┌─ Handshake Slot ────────────┐
│▶ TP-Link_E054   -52dBm │  │   [ فارغ — اسحب شبكة ]      │
│  IraqNet_5G     -68dBm │  │                             │
│  ZainRouter     -74dBm │  │                             │
└─────────────────────────┘  └─────────────────────────────┘
 [S]سكان  [↑/↓]تنقل  [D]سحب  [C]كسر  [R]إعادة  [Q]خروج
```

### الخطوات

1. **`S`** — سكان 25s، الشبكات تظهر في اللوح الأيسر.
2. **`↑` / `↓`** — تنقل بين الشبكات.
3. **`D`** — اسحب الشبكة للخانة اليمنى، يبدأ deauth + capture تلقائياً.
4. **Handshake يُلتقط** — اسم الملف يظهر في الخانة.
5. **`C`** — كسر بـ `pass123.txt`، progress live.
6. **كلمة السر تظهر** — شريط حالة أخضر + `cracked.json`.
7. **`R`** — تصفير. **`Q`** — خروج.

---

## 🧩 خيارات سطر الأوامر

| الخيار | الوصف | الافتراضي |
|--------|-------|-----------|
| `--iface` | واجهة WiFi | كشف تلقائي |
| `--wordlist` | قائمة الكلمات | `~/abbas_crack/pass123.txt` |
| `--scan-time` | مدة السكان | `25` |
| `--attack-timeout` | أقصى مدة هجوم | `180` |
| `-j`, `--workers` | عدد المعالجات | `cpu_count - 1` |
| `--single` | معالج مفرد | معطّل |
| `--no-tui` | بدون curses | معطّل |

---

## 📁 هيكل الملفات

```
~/abbas_crack/
├── abbas.log               # سجل العمليات
├── state.json              # الالتقاطات
├── cracked.json            # كلمات السر المُكتشفة
├── pass123.txt             # قائمة الكلمات الافتراضية
├── hs/                     # ملفات Handshake
└── dumps/                  # ملفات سكان مؤقتة
```

---

## 🔬 آلية الكسر

### 1. PMK
```
PMK = PBKDF2-HMAC-SHA1(password, SSID, 4096 تكرار, 32 بايت)
```

### 2. PTK
```
PTK = PRF-512(PMK, "Pairwise key expansion",
              min(AP_MAC, STA_MAC) || max(AP_MAC, STA_MAC) ||
              min(ANonce, SNonce) || max(ANonce, SNonce))
```

### 3. MIC
```
MIC = HMAC-SHA1(PTK[0:16], EAPOL_M2 مع MIC مصفّر)[0:16]
```

### 4. المقارنة
إذا طابق MIC المُحتسب الـ MIC المُلتقط → كلمة السر صحيحة.

بدون scapy — فقط `hashlib`, `hmac`, `struct`.

---

## 🛠️ حل مشاكل السكان في Kali

### `Operation not supported (-95)`
**السبب:** `iw dev wlan0 scan` في monitor mode.
**الحل:** `sudo airodump-ng wlan0mon`

### `Monitor mode already enabled` بدون `wlan0mon`
**السبب:** RTL8187 يحول `wlan0` in-place.
**الحل:** `sudo airodump-ng wlan0`

### السكان يرجع فارغ
1. `sudo airmon-ng check kill` — يوقف NetworkManager
2. تحقق من دعم الأدابتر
3. داخل VM — مرّر أدابتر USB
4. `dmesg | tail -30` للفحص

            
            
# =================  جنرال  =================

