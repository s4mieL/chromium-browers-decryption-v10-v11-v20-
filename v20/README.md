# 🔓 v20 (App-Bound Encryption) Browser Decryptor — Usage Guide

A research tool for decrypting **v20 App-Bound Encrypted** browser credentials and cookies from Chromium-based browsers.

> ⚠️ **Disclaimer:** This tool is intended strictly for **educational and research purposes**. Only use it on machines and accounts you own or have explicit permission to access.

> 🔬 **Research Status:** v20 (App-Bound Encryption) is still under active study. This tool represents current findings and may not cover all edge cases or future Chrome updates.

---

## 📋 Requirements

- **OS:** Windows only
- **Python:** 3.8+
- **Privileges:** ⚡ Must be run as **Administrator** (required for LSASS impersonation and SYSTEM DPAPI)

### Install dependencies

```bash
pip install pycryptodome python-windows-internals
```

> `python-windows-internals` provides the `windows` module used for privilege escalation and DPAPI operations.

---

## 🧠 How v20 Decryption Works

v20 (App-Bound Encryption) is significantly more complex than v10/v11. Here's the chain:

```
Local State (app_bound_encrypted_key)
        ↓
  Base64 decode → strip "APPB" prefix
        ↓
  Decrypt with SYSTEM DPAPI   ← requires LSASS impersonation
        ↓
  Decrypt with User DPAPI
        ↓
  Parse key blob (flag byte determines algorithm)
        ↓
  Derive v20 master key (AES-GCM or ChaCha20)
        ↓
  Decrypt cookies / passwords with master key (AES-256-GCM)
```

### Key Blob Flags

| Flag | Algorithm | Description |
|------|-----------|-------------|
| `1` | AES-GCM | Standard AES key derivation |
| `2` | ChaCha20-Poly1305 | Alternative cipher path |
| `3` | AES-GCM + NCrypt | Uses CNG key store + XOR layer, requires `NCryptDecrypt` |

---

## 🖥️ Supported Browsers

| Browser | Supported | Notes |
|---------|-----------|-------|
| Google Chrome | ✅ | Primary target |
| Brave | ✅ | Paths hardcoded, same v20 format |
| Edge | 🔬 | Under research — may work with path adjustments |

---

## 🚀 Usage

> **Must be run in an elevated (Administrator) terminal.**

```bash
python chrome_v20.py
```

The script will automatically:
1. Read `Local State` to extract the `app_bound_encrypted_key`
2. Impersonate LSASS to perform SYSTEM DPAPI decryption
3. Perform user DPAPI decryption
4. Parse the key blob and derive the v20 master key
5. Decrypt saved passwords, credit cards, and cookies

---

## 📂 Output Files

| File | Contents |
|------|----------|
| `decrypted_cookies.txt` | All decrypted v20 cookies |
| `discord_cookies.txt` | Filtered Discord session cookies |
| `spotify_cookies.txt` | Filtered Spotify session cookies |
| Console output | Saved passwords, autofill, and credit card data |

### Relevant cookies extracted

**Discord:** `__dcfduid`, `__sdcfduid`, `cf_clearance`, `locale`

**Spotify:** `sp_dc`, `sp_key`

---

## ⚙️ Customizing Browser Paths

The script currently targets **Brave** browser paths by default in some functions. To switch to Chrome, update these paths manually:

**Local State:**
```python
# Brave (default in script)
r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Local State"

# Chrome
r"%LOCALAPPDATA%\Google\Chrome\User Data\Local State"
```

**Login Data:**
```python
# Brave
r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Login Data"

# Chrome
r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data"
```

**Cookies:**
```python
# Brave
r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Network\Cookies"

# Chrome
r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies"
```

> 🛠️ CLI flag support (`--browser`) for v20 is planned once research stabilizes.

---

## ❗ Common Errors

**Not running as admin:**
```
This script needs to run as administrator.
```
→ Right-click your terminal and select **"Run as Administrator"**, then re-run.

**App-bound key not found:**
```
KeyError: 'app_bound_encrypted_key'
```
→ The script will fall back to `encrypted_key` automatically. If both fail, the browser version may predate v20.

**LSASS impersonation failed:**
```
AssertionError: NCryptOpenKey failed with status ...
```
→ Ensure you are running as Administrator with `SeDebugPrivilege` available.

**Decryption failed on a cookie/password:**
```
<decryption failed: ...>
```
→ The entry may use a different encryption flag, be corrupted, or belong to a format still under research.

---

## 🔐 Encryption Version Comparison

| Version | Complexity | Key Storage | Privilege Needed |
|---------|-----------|-------------|-----------------|
| `v10` | Low | Local State (DPAPI) | User |
| `v11` | Low | Local State (DPAPI) | User |
| `v20` | High | App-Bound + SYSTEM DPAPI + CNG | **Administrator** |

---

## 📁 Project Structure

```
chrome_v20.py             # Main v20 decryptor script
decrypted_cookies.txt     # Output: all v20 cookies (auto-generated)
discord_cookies.txt       # Output: Discord cookies (auto-generated)
spotify_cookies.txt       # Output: Spotify cookies (auto-generated)
```

---

*Part of an ongoing study into Chromium v20 App-Bound Encryption. Research is active — findings and supported browsers will expand over time.*