# 🔓 v10/v11 Browser Credential Decryptor — Usage Guide

A research tool for decrypting v10/v11 encrypted browser credentials from Chromium-based browsers.

> ⚠️ **Disclaimer:** This tool is intended strictly for **educational and research purposes**. Only use it on machines and accounts you own or have explicit permission to access.

---

## 📋 Requirements

- **OS:** Windows only (relies on Windows DPAPI via `win32crypt`)
- **Python:** 3.8+

### Install dependencies

```bash
pip install pycryptodome pywin32
```

---

## 🚀 Basic Usage

```bash
python v10-v11_decryptor.py --browser <browser>
```

### Supported Browsers

| Flag | Browser |
|------|---------|
| `chrome` | Google Chrome |
| `edge` | Microsoft Edge |
| `brave` | Brave Browser |

---

## 🏳️ Flags & Options

| Flag | Short | Description |
|------|-------|-------------|
| `--browser` | `-b` | **(Required)** Target browser: `chrome`, `edge`, or `brave` |
| `--passwords` | `-p` | Dump saved passwords |
| `--cards` | `-c` | Dump saved credit cards & autofill data |
| `--all` | `-a` | Dump everything (passwords + cards) |
| `--output` | `-o` | Output file for passwords (default: `Saved_passwords.txt`) |

> If no `--passwords` or `--cards` flag is given, the tool defaults to dumping passwords.

---

## 💡 Examples

**Dump Chrome passwords:**
```bash
python v10-v11_decryptor.py --browser chrome
```

**Dump Edge passwords:**
```bash
python v10-v11_decryptor.py --browser edge --passwords
```

**Dump Brave credit cards only:**
```bash
python v10-v11_decryptor.py --browser brave --cards
```

**Dump everything from Chrome:**
```bash
python v10-v11_decryptor.py --browser chrome --all
```

**Dump Chrome passwords to a custom output file:**
```bash
python v10-v11_decryptor.py --browser chrome --passwords --output my_results.txt
```

**Short-form flags work too:**
```bash
python v10-v11_decryptor.py -b edge -a -o edge_dump.txt
```

---

## 📂 Output

- **Passwords** are printed to the console and saved to `Saved_passwords.txt` (or your custom `--output` file).
- **Credit cards / autofill** are printed to the console only.
- Multiple browser profiles (e.g. `Default`, `Profile 1`, `Profile 2`) are all scanned automatically.

---

## 🔐 Encryption Support

| Version | Supported | Notes |
|---------|-----------|-------|
| `v10` | ✅ | AES-256-GCM with DPAPI master key |
| `v11` | ✅ | Same decryption path as v10 |
| `v20` | 🔬 | App-Bound Encryption — **under active research**, not yet supported |

---

## ❗ Common Errors

**Browser not found:**
```
[!] Could not find Chrome installation on this machine.
```
→ The browser may not be installed, or the profile path is non-standard.

**Decryption failed:**
```
<decryption failed>
```
→ The entry may be corrupted, empty, or encrypted with an unsupported format (e.g. v20).

---

## 📁 Project Structure

```
v10-v11_decryptor.py   # Main script
Saved_passwords.txt    # Output file (auto-generated)
```

---

*Part of an ongoing study into Chromium encryption formats. v20 (App-Bound Encryption) research is in progress.*
