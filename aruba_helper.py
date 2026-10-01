### Aruba Instant Python Tools
### aruba_helper.py - Helper-Bibliothek für Aruba Instant
### Version 1.0.8 - Abbruch mit Korrekturhinweis bei paramiko >= 5 (kein ssh-rsa mehr)
### Bestandteil der Aruba Instant Python Tools Suite V 2.0.0
### gemacht mit viel Liebe von John (johnlose.de)
import paramiko
import re
import csv
import sys
import time
import json
import os
import importlib.util
from getpass import getpass
import uuid
import hashlib
from datetime import datetime
import threading

SCRIPT_VERSION = "1.0.8"

# --- ABHÄNGIGKEITEN-PRÜFUNG ---
def check_dependencies():
    """
    Liest die requirements.txt, prüft, ob die Pakete installiert sind,
    und beendet das Skript mit einer Anleitung, wenn etwas fehlt.
    """
    print("--- Abhängigkeiten-Prüfung ---")
    requirements_file = "requirements.txt"
    missing_packages = []
    
    package_to_import_map = {
        'pycryptodome': 'Crypto',
        'beautifulsoup4': 'bs4'
    }

    try:
        with open(requirements_file) as f:
            required_packages = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print(f"[✗] FEHLER: Die Datei '{requirements_file}' wurde nicht gefunden.")
        sys.exit(1)

    for package in required_packages:
        package_name = package.split('==')[0].strip()
        import_name = package_to_import_map.get(package_name, package_name)
            
        if importlib.util.find_spec(import_name) is None:
            missing_packages.append(package)
            print(f"[✗] {package} fehlt")
        else:
            print(f"[✓] {package} gefunden")

    # paramiko >= 5 unterstützt den SSH-Hostschlüssel 'ssh-rsa' (SHA-1) nicht mehr, den Aruba Instant 8.10 anbietet
    try:
        import paramiko
        if int(str(paramiko.__version__).split('.')[0]) >= 5:
            print(f"\n[✗] FEHLER: paramiko {paramiko.__version__} ist zu neu für Aruba Instant 8.10!")
            print("    Ab paramiko 5.0 wird der SSH-Hostschlüssel 'ssh-rsa' (SHA-1) nicht mehr unterstützt.")
            print("    Verbindungen scheitern mit: Incompatible ssh peer (no acceptable host key)")
            print("    Korrektur:  pip install --user \"paramiko==4.0.0\"")
            print("    (oder setup.bat erneut ausführen und die Frage zu paramiko mit J beantworten;")
            print("     Hinweise zur Sicherheit stehen in der README, Abschnitt 'SSH-Kompatibilität')")
            sys.exit(1)
    except (ImportError, ValueError):
        pass

    if missing_packages:
        print("\n--- FEHLER: Es fehlen erforderliche Bibliotheken! ---")
        print(f"    pip install -r {requirements_file}")
        sys.exit(1)
    else:
        print("--- Prüfung erfolgreich ---")

# Globale Prüfung, ob Keyring und Crypto verfügbar sind
try:
    import keyring
    KEYRING_AVAILABLE = sys.platform == "win32"
except ImportError: KEYRING_AVAILABLE = False

try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Util.Padding import pad, unpad
    CRYPTO_AVAILABLE = True
except ImportError: CRYPTO_AVAILABLE = False

CRED_FILE = "credentials.bin"

# --- LOGGER-KLASSE (THREAD-SICHER) ---
class Logger:
    def __init__(self, filename="ap_check_log.txt"):
        self.terminal = sys.stdout
        self.logfile = open(filename, 'w', encoding='utf-8')
        self.lock = threading.Lock()

    def write(self, message):
        with self.lock:
            self.terminal.write(message)
            self.logfile.write(message)

    def flush(self):
        with self.lock:
            self.terminal.flush()
            self.logfile.flush()
    
    def write_to_console_only(self, message):
        self.terminal.write(message)
        self.terminal.flush()

    def close(self):
        self.logfile.close()

# --- CRYPTO & CREDENTIAL FUNKTIONEN ---
def get_machine_key():
    mac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
    salt = b'aruba-salt-for-key'
    key = hashlib.pbkdf2_hmac('sha256', mac.encode(), salt, 100000, dklen=32)
    return key

def save_credentials_to_file(credentials):
    if not CRYPTO_AVAILABLE: return
    key = get_machine_key()
    cipher = AES.new(key, AES.MODE_CBC)
    data_to_encrypt = json.dumps(credentials).encode('utf-8')
    ciphered_data = cipher.encrypt(pad(data_to_encrypt, AES.block_size))
    with open(CRED_FILE, "wb") as f:
        f.write(cipher.iv)
        f.write(ciphered_data)

def load_credentials_from_file():
    if not CRYPTO_AVAILABLE or not os.path.exists(CRED_FILE): return {}
    key = get_machine_key()
    with open(CRED_FILE, "rb") as f:
        iv = f.read(16)
        ciphered_data = f.read()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        original_data = unpad(cipher.decrypt(ciphered_data), AES.block_size)
        return json.loads(original_data.decode('utf-8'))
    except (ValueError, KeyError, json.JSONDecodeError):
        print(f"HINWEIS: Die Datei '{CRED_FILE}' ist beschädigt oder nicht kompatibel und wird ignoriert.")
        return {}

def get_credentials_interactively():
    user = input("Bitte SSH-Benutzername eingeben: ")
    password = getpass("Bitte SSH-Passwort eingeben (Eingabe unsichtbar): ")
    return user, password

def get_saved_credentials(target_ip, cfg, pre_check_user=None):
    storage_method = cfg.get('storage_method', 'none')
    if storage_method == 'keyring' and pre_check_user:
        password = keyring.get_password(f"aruba-skript-{target_ip}", pre_check_user)
        if password:
            return pre_check_user, password
    elif storage_method == 'file':
        all_creds = load_credentials_from_file()
        if creds := all_creds.get(target_ip):
            return creds.get('user'), creds.get('pass')
    return None, None

def validate_credentials(target_ip, user, password, timeout):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(target_ip, username=user, password=password, timeout=timeout)
        return True
    except paramiko.AuthenticationException:
        print(f"FEHLER: Authentifizierung für {target_ip} mit den angegebenen Daten fehlgeschlagen.")
        return False
    except Exception as e:
        print(f"FEHLER: Verbindung zu {target_ip} für Validierung fehlgeschlagen: {e}")
        return False
    finally:
        if client: client.close()

def save_credential(target_ip, user, password, cfg):
    storage_method = cfg.get('storage_method', 'none')
    if storage_method == 'keyring':
        keyring.set_password(f"aruba-skript-{target_ip}", user, password)
        print(f"INFO: Anmeldedaten für {target_ip} im Windows Credential Manager gespeichert.")
    elif storage_method == 'file':
        all_creds = load_credentials_from_file()
        all_creds[target_ip] = {'user': user, 'pass': password}
        save_credentials_to_file(all_creds)
        print(f"INFO: Anmeldedaten für {target_ip} in '{CRED_FILE}' gespeichert (nur Basisschutz, KEIN sicherer Tresor - Datei nie weitergeben oder einchecken).")

def delete_credential_for_ip(target_ip, user_for_keyring):
    deleted_from = []
    if KEYRING_AVAILABLE and user_for_keyring:
        try:
            if keyring.get_password(f"aruba-skript-{target_ip}", user_for_keyring) is not None:
                keyring.delete_password(f"aruba-skript-{target_ip}", user_for_keyring)
                deleted_from.append("Windows Credential Manager")
        except Exception:
            pass
    
    if CRYPTO_AVAILABLE and os.path.exists(CRED_FILE):
        all_creds = load_credentials_from_file()
        if target_ip in all_creds:
            del all_creds[target_ip]
            save_credentials_to_file(all_creds)
            deleted_from.append(f"'{CRED_FILE}'")
    
    return deleted_from

# --- SSH & ARUBA FUNKTIONEN ---
def execute_command_on_shell(client, command):
    channel = client.invoke_shell()
    initial_buffer = ""
    stall_count = 0
    while not initial_buffer.strip().endswith('#') and stall_count < 6:
        time.sleep(0.5)
        if channel.recv_ready():
            initial_buffer += channel.recv(65535).decode('utf-8', errors='ignore')
            stall_count = 0
        else: stall_count += 1
    channel.send("no paging\n")
    time.sleep(0.5)
    channel.send(command + "\n")
    output = ""
    stall_count = 0
    max_stalls = 20 if "commit" in command else 10
    while not output.strip().endswith('#') and stall_count < max_stalls: 
        time.sleep(0.5) 
        if channel.recv_ready():
            output += channel.recv(65535).decode('utf-8', errors='ignore')
            stall_count = 0
        else: stall_count += 1
    lines = output.splitlines()
    cleaned_lines = [line for line in lines if command not in line and not line.strip().endswith('#')]
    return "\n".join(cleaned_lines)

def get_conductor_data(conductor_ip, user, pw, timeout, lang):
    with threading.Lock():
        print(f"\n--- Starte Abfrage für Conductor: {conductor_ip} ---")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ap_data, provisioned_macs, conductor_name = {}, set(), "N/A"
    required_vlans = set()
    try:
        client.connect(conductor_ip, username=user, password=pw, timeout=timeout)
        with threading.Lock(): print(f"INFO: Lese Konfiguration (running-config) von {conductor_ip}...")
        config_output = execute_command_on_shell(client, "show running-config")
        
        version_match = re.search(r"^version\s+(.*)", config_output, re.MULTILINE)
        if version_match:
            version_string = version_match.group(1).strip()
            if "-8.10.0" not in version_string:
                with threading.Lock(): print(f"WARNUNG: Inkompatible Conductor-Firmware '{version_string}' bei {conductor_ip}. Erwartet '-8.10.0'. Überspringe Standort.")
                return None, None, None, None, "version_mismatch"
        else:
            with threading.Lock(): print(f"WARNUNG: Firmware-Version konnte für {conductor_ip} nicht ermittelt werden. Führe Prüfung trotzdem durch.")

        provisioned_macs = set(mac.lower() for mac in re.findall(r"allowed-ap ([\da-fA-F:]+)", config_output))
        if name_match := re.search(r"^name\s+(\S+)", config_output, re.MULTILINE):
            conductor_name = name_match.group(1)
        with threading.Lock(): print(f"INFO: {len(provisioned_macs)} provisionierte APs in der Konfiguration für '{conductor_name}' gefunden.")

        ssid_blocks = re.split(r'wlan ssid-profile', config_output)[1:]
        for block in ssid_blocks:
            lines = block.strip().splitlines()
            if 'enable' in lines[1]:
                if vlan_match := re.search(r'vlan\s+(\d+)', block):
                    required_vlans.add(int(vlan_match.group(1)))
        if required_vlans:
             with threading.Lock(): print(f"INFO: Benötigte VLANs aus aktiven SSIDs ermittelt: {sorted(list(required_vlans))}")

        output = execute_command_on_shell(client, "show aps")
        lines = output.splitlines()

        header_found = False
        start_data_index = 0
        for i, line in enumerate(lines):
            if lang['header_serial'] in line and lang['header_ip'] in line:
                start_data_index = i + 2
                header_found = True
                break
        
        if not header_found:
            with threading.Lock(): print(f"FEHLER: Konnte die Header-Zeile in der 'show aps'-Ausgabe für {conductor_ip} nicht finden.")
            return None, None, None, None, "parse_error"

        for line in lines[start_data_index:]:
            if not line.strip() or line.strip().startswith("----"): continue
            
            match = re.search(
                r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\*?\s+(\w+)\s+.*?\s+(\d+)\(.*?\).*?\s+([\dA-Z]+)\s+.*?\s+(?:enable|disable)\s+([\d\w:]+)",
                line
            )
            
            if match:
                ap_ip, mode, ap_type, serial, uptime = match.groups()
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ap_ip):
                     ap_data[ap_ip] = {'serial': serial, 'uptime': uptime, 'ap_type': ap_type, 'mode': mode}
            else:
                 with threading.Lock(): print(f"INFO: Überspringe eine nicht parsebare Zeile: \"{line.strip()}\"")
        
        with threading.Lock(): print(f"INFO: {len(ap_data)} APs (online) zur Überprüfung für {conductor_ip} gefunden.")
        return ap_data, provisioned_macs, conductor_name, required_vlans, "success"
    except paramiko.AuthenticationException:
        with threading.Lock(): print(f"FEHLER: Authentifizierung für {conductor_ip} fehlgeschlagen.")
        return None, None, None, None, "auth_error"
    except Exception as e:
        with threading.Lock(): print(f"FEHLER: Verbindung zum Conductor-AP {conductor_ip} fehlgeschlagen: {e}")
        return None, None, None, None, "conn_error"
    finally:
        if client: client.close()

# --- ALLGEMEINE HELFER ---
def parse_speed(speed_str):
    if "mb/s" in speed_str.lower():
        try: return int(re.search(r'(\d+)', speed_str).group(1))
        except (ValueError, AttributeError): return 0
    return 0
    
### Hier ist das Ende ###