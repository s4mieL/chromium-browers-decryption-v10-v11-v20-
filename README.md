# chromium-browers-decryption-v10-v11-v20-
Chromium Browser Decryption (v10, v11, v20) – Educational tools for decrypting saved credentials and data from Chromium-based browsers, designed to study browser encryption methods and security mechanisms.

---

# 🔐 Chrome Cookie Encryption Formats

A quick reference guide to Chromium-based browser encryption versions used for cookies and sensitive data.

---

## Overview

Chromium-based browsers use versioned encryption schemes to protect stored data such as cookies and passwords. Each version reflects an evolution in security posture — from user-session-bound keys to process-bound app encryption.

---

## Encryption Versions

### `v10` — AES-256-GCM with Master Key
- **Introduced:** Chrome ~v80+
- **Mechanism:** Uses a master key stored in the `Local State` file
- **Algorithm:** AES-256-GCM
- **Notes:** The master key is protected by the OS credential store (DPAPI on Windows). This was the standard format for modern Chrome for several years.

---

### `v11` — Legacy / Older Chromium Variants
- **Observed in:** Older Chromium-based browsers (e.g., ~v53 in specific implementations)
- **Use:** Also used for cookie data encryption
- **Notes:** Often referenced alongside `v10` in security analyses of Chromium internals. Less common in current builds.

---

### `v20` — App-Bound Encryption (ABE)
- **Introduced:** Chrome v127 (July 2024)
- **Also known as:** App-Bound Encryption
- **Platform:** Windows
- **Mechanism:** Binds encryption keys to the **specific browser process**, rather than just the user's login session
- **Purpose:** Designed to protect sensitive data (cookies, passwords) from infostealer malware
- **Identifier:** Data encrypted with this scheme carries a `v20` prefix in cookie and data files

> ⚠️ This format significantly raises the bar for credential theft tools that previously relied on DPAPI-only protection.

> 🔬 **Status: Active Research** — Decryption of the `v20` format is still being studied. Due to its process-bound key architecture, reversing or working with this encryption is significantly more complex than previous versions. Findings will be updated as research progresses.

---

## Summary Table

| Version | Chrome Version | Algorithm | Key Binding | Notes |
|---------|---------------|-----------|-------------|-------|
| `v10` | ~80+ | AES-256-GCM | User session (DPAPI) | Long-standing standard |
| `v11` | ~53 (legacy) | Varies | User session | Older Chromium builds |
| `v20` | 127+ (Jul 2024) | AES-256-GCM | Browser process (ABE) | Anti-infostealer hardening |

---

## References

- [Google Security Blog – App-Bound Encryption](https://security.googleblog.com)
- Chromium source: `components/os_crypt/`
- Chrome release notes: v80, v127

---

*Last updated: 2026*
