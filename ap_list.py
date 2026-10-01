### Aruba Instant Python Tools
### ap_list.py - Erstellt eine Liste aller APs mit MAC, Seriennummer und Teilenummer
### Version 1.0.4 - Wording für Offline-APs präzisiert
### Bestandteil der Aruba Instant Python Tools Suite V 2.0.0
### gemacht mit viel Liebe von John (johnlose.de)

# Importiere notwendige Bibliotheken
import paramiko
import re
import csv
import sys
import time
import json
import os
import threading
import argparse
from queue import Queue
from datetime import datetime

# Importiere die Helper-Funktionen
from aruba_helper import (
    SCRIPT_VERSION as HELPER_VERSION, check_dependencies, Logger, get_saved_credentials,
    validate_credentials, get_credentials_interactively, save_credential,
    delete_credential_for_ip, 
    KEYRING_AVAILABLE, CRYPTO_AVAILABLE
)

TOOLSUITE_VERSION = "2.0.0"

AP_LIST_VERSION = "1.0.4"
APPARTS_FILE = "apparts.json"
print_lock = threading.Lock()

# --- WARNHINWEIS (Gemäß Anforderung 10. Sept.) ---
# Die folgenden zwei Funktionen (_local_execute_command_on_shell, _local_get_conductor_data)
# sind absichtliche, lokale Duplikate aus aruba_helper.py (v1.0.6).
#
# GRUND: Die Regex in der globalen get_conductor_data (v1.0.6) wird von
# anderen Tools (die hier nicht bekannt sind) verwendet und darf
# NICHT verändert werden ("wäre fatal").
#
# Für ap_list.py (Features --apname, --greenlake) MUSS die Regex jedoch
# angepasst werden, um die "Name"-Spalte (AP-Name) auszulesen.
# --- WARNHINWEIS ENDE ---

def _local_execute_command_on_shell(client, command):
    """
    LOKALE KOPIE aus aruba_helper.py (v1.0.6, Zeile 203)
    """
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

def _local_get_conductor_data(conductor_ip, user, pw, timeout, lang):
    """
    LOKALE KOPIE aus aruba_helper.py (v1.0.6, Zeile 240)
    MODIFIZIERT für ap_list.py v1.0.3:
    - Verwendet das lokale 'print_lock'
    - Regex (Zeile 147) erfasst AP-Namen und überspringt die Client-Spalte
    """
    with print_lock: 
        print(f"\n--- Starte Abfrage für Conductor: {conductor_ip} ---")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ap_data, provisioned_macs, conductor_name = {}, set(), "N/A"
    required_vlans = set() 
    try:
        client.connect(conductor_ip, username=user, password=pw, timeout=timeout)
        with print_lock: print(f"INFO: Lese Konfiguration (running-config) von {conductor_ip}...")
        config_output = _local_execute_command_on_shell(client, "show running-config")
        
        version_match = re.search(r"^version\s+(.*)", config_output, re.MULTILINE)
        if version_match:
            version_string = version_match.group(1).strip()
            if "-8.10.0" not in version_string:
                with print_lock: print(f"WARNUNG: Inkompatible Conductor-Firmware '{version_string}' bei {conductor_ip}. Erwartet '-8.10.0'. Überspringe Standort.")
                return None, None, None, None, "version_mismatch"
        else:
            with print_lock: print(f"WARNUNG: Firmware-Version konnte für {conductor_ip} nicht ermittelt werden. Führe Prüfung trotzdem durch.")

        provisioned_macs = set(mac.lower() for mac in re.findall(r"allowed-ap ([\da-fA-F:]+)", config_output))
        if name_match := re.search(r"^name\s+(\S+)", config_output, re.MULTILINE):
            conductor_name = name_match.group(1)
        with print_lock: print(f"INFO: {len(provisioned_macs)} provisionierte APs in der Konfiguration für '{conductor_name}' gefunden.")
        
        ssid_blocks = re.split(r'wlan ssid-profile', config_output)[1:]
        for block in ssid_blocks:
            lines = block.strip().splitlines()
            if 'enable' in lines[1]:
                if vlan_match := re.search(r'vlan\s+(\d+)', block):
                    required_vlans.add(int(vlan_match.group(1)))

        output = _local_execute_command_on_shell(client, "show aps")
        lines = output.splitlines()

        header_found = False
        start_data_index = 0
        for i, line in enumerate(lines):
            if lang['header_serial'] in line and lang['header_ip'] in line:
                start_data_index = i + 2
                header_found = True
                break
        
        if not header_found:
            with print_lock: print(f"FEHLER: Konnte die Header-Zeile in der 'show aps'-Ausgabe für {conductor_ip} nicht finden.")
            return None, None, None, None, "parse_error"

        for line in lines[start_data_index:]:
            if not line.strip() or line.strip().startswith("----"): continue
            
            # (Regex aus v1.0.3, überspringt Client-Spalte)
            match = re.search(
                r"^(\S+)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\*?\s+(\w+)\s+.*?\s+\d+\s+(\d+\(.*?\))\s+.*?\s+([\dA-Z]+)\s+.*?\s+(?:enable|disable)\s+([\d\w:]+)",
                line
            )
            
            if match:
                ap_name, ap_ip, mode, ap_type, serial, uptime = match.groups()
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ap_ip):
                     ap_data[ap_ip] = {'name': ap_name, 'serial': serial, 'uptime': uptime, 'ap_type': ap_type, 'mode': mode}
            else:
                 with print_lock: print(f"INFO: Überspringe eine nicht parsebare Zeile: \"{line.strip()}\"")
        
        with print_lock: print(f"INFO: {len(ap_data)} APs (online) zur Überprüfung für {conductor_ip} gefunden.")
        return ap_data, provisioned_macs, conductor_name, required_vlans, "success" 
    except paramiko.AuthenticationException:
        with print_lock: print(f"FEHLER: Authentifizierung für {conductor_ip} fehlgeschlagen.")
        return None, None, None, None, "auth_error"
    except Exception as e:
        with print_lock: print(f"FEHLER: Verbindung zum Conductor-AP {conductor_ip} fehlgeschlagen: {e}")
        return None, None, None, None, "conn_error"
    finally:
        if client: client.close()


def get_ap_mac(ip, user, pw, timeout, lang_terms):
    """
    Stellt eine Verbindung zu einem einzelnen AP her, um dessen eth0/bond0 MAC-Adresse abzufragen.
    (Funktion aus v1.0.1)
    """
    with print_lock:
        print(f"INFO: Verbinde mit Member-AP {ip} für MAC-Abfrage...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        client.connect(ip, username=user, password=pw, timeout=timeout)
        interface_output = _local_execute_command_on_shell(client, "show interface")
        
        interface_blocks = re.split(rf"\n(?=(?:eth|bond)\d is up)", '\n' + interface_output)
        
        found_mac = 'N/A'
        for block in interface_blocks:
            name_match = re.search(r"^((?:eth|bond)\d)", block.strip())
            if not name_match: continue
            if_name = name_match.group(1)
            
            if mac_match := re.search(rf"{lang_terms['interface_address']} ([\da-fA-F:]{{17}})", block):
                if if_name == "bond0":
                    return mac_match.group(1) 
                elif if_name == "eth0":
                    found_mac = mac_match.group(1)
        
        return found_mac
        
    except Exception as e:
        with print_lock:
            # Netzwerkfehler (Timeouts) werden hier abgefangen.
            print(f"FEHLER bei AP {ip} (MAC-Abfrage): {e}")
        # --- ANPASSUNG V1.0.4 (Logik-Präzisierung, falls wir es später brauchen) ---
        return "TIMEOUT_ODER_FEHLER"
    finally:
        if client: client.close()

def translate_ap_type(ap_type_raw, part_number_map):
    """
    Übersetzt den rohen AP-Typ (z.B. 315(indoor)) in eine Teilenummer.
    Gibt JWXXX zurück, wenn keine Übersetzung gefunden wird. (Logik aus v1.0.1)
    """
    if not ap_type_raw:
        return "JWXXX"
    model_match = re.search(r"^(\S+?)(?=\(|$)", ap_type_raw)
    if model_match:
        model_key = model_match.group(1)
        return part_number_map.get(model_key, "JWXXX")
    return "JWXXX"

def worker(task_queue, all_results_queue, user, pw, timeout, lang_terms):
    """
    Thread-Worker zur Abfrage der MAC-Adresse von einzelnen APs.
    """
    while True:
        item = task_queue.get()
        if item is None: break
        
        ip, ap_info = item
        
        mac_address = get_ap_mac(ip, user, pw, timeout, lang_terms)
            
        full_result = ap_info.copy()
        full_result['ip'] = ip
        full_result['eth0_mac'] = mac_address
        
        all_results_queue.put(full_result)
        task_queue.task_done()

# === Hauptskript ===
if __name__ == "__main__":
    check_dependencies() 

    original_stdout = sys.stdout
    log_file_handler = None
    
    epilog_text = """
Beispiele:

  # Standard-Liste erstellen
  py ap_list.py 10.1.1.1

  # Liste MIT AP-Namen erstellen
  py ap_list.py 10.1.1.1 --apname
  
  # GreenLake / Aruba Central Migrations-CSV erstellen (NEUES Format)
  py ap_list.py 10.1.1.1 --greenlake

  # Importieren und Log erstellen
  py ap_list.py --importfile C:\\pfad\\zur\\liste.csv --log
"""

    parser = argparse.ArgumentParser(
        description="Erstellt eine AP-Liste (IP, MAC, Serial, Teilenummer) von Aruba Conductors.",
        epilog=epilog_text,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('targets', nargs='*', default=[], help="Optional: Eine oder mehrere Conductor-IPs (kommasepariert).")
    parser.add_argument('--importfile', type=str, help="Pfad zu einer CSV-Datei, aus der Conductor-IPs importiert werden sollen.")
    parser.add_argument('--log', action='store_true', help="Aktiviert das Schreiben der Konsolenausgabe in die Log-Datei im Ergebnisordner.")
    parser.add_argument('--delete-credentials', type=str, help="WERKZEUG: Löscht gespeicherte Anmeldedaten für die angegebenen IPs.")
    parser.add_argument('--apname', action='store_true', help="Fügt den AP-Namen (aus 'show aps') zur Standard-CSV hinzu.")
    parser.add_argument('--greenlake', action='store_true', help="Erstellt eine CSV-Datei im GreenLake/Central-Importformat (überschreibt --apname).")
    
    args = parser.parse_args()

    # Logik für --delete-credentials (unverändert)
    if args.delete_credentials:
        ips_to_delete = args.delete_credentials.split(',')
        print("\nFolgende Anmeldeinformationen sollen gelöscht werden:")
        for ip in set(ips_to_delete): print(f"- {ip}")
        user_for_keyring_deletion = None
        if KEYRING_AVAILABLE:
             user_for_keyring_deletion = input("Bitte geben Sie den Benutzernamen ein, für den die Keyring-Einträge gelöscht werden sollen: ")
        if input("Wollen Sie wirklich fortfahren und diese Einträge löschen? (j/n): ").lower() == 'j':
            for ip in set(ips_to_delete):
                deleted_stores = delete_credential_for_ip(ip, user_for_keyring_deletion)
                if deleted_stores:
                    print(f"INFO: Anmeldedaten für {ip} aus {', '.join(deleted_stores)} gelöscht.")
                else:
                    print(f"INFO: Keine gespeicherten Anmeldedaten für {ip} gefunden.")
            print("\nLöschvorgang abgeschlossen.")
        else:
            print("Aktion abgebrochen.")
        sys.exit(0)

    # Ordner-Setup
    run_timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    output_dir_prefix = "ap_list_greenlake_" if args.greenlake else "ap_list_"
    output_dir = os.path.join(os.getcwd(), output_dir_prefix + run_timestamp)
    os.makedirs(output_dir, exist_ok=True)
    
    if args.log:
        try:
            log_filename = os.path.join(output_dir, "ap_list_log.txt")
            log_file_handler = Logger(filename=log_filename) 
            sys.stdout = log_file_handler
        except Exception as e:
            sys.stdout = original_stdout
            print(f"FEHLER: Log-Datei konnte nicht erstellt werden: {e}")
    
    print(f"ap_list.py Version {AP_LIST_VERSION} wird ausgeführt...")
    print(f"Teil der Aruba Instant Toolsammlung Version {TOOLSUITE_VERSION}")
    print(f"Nutze aruba_helper.py Version {HELPER_VERSION}")
    if args.greenlake:
        print("INFO: Modus 'GreenLake / Aruba Central' Import-CSV (Format v2) wird erstellt.")
    elif args.apname:
        print("INFO: AP-Namen werden in die CSV-Liste aufgenommen.")
    print(f"INFO: Ergebnisse werden im Verzeichnis '{output_dir}' gespeichert.")

    start_time = datetime.now()
    print(f"\n===== Skriptstart: {start_time.strftime('%Y-%m-%d %H:%M:%S')} =====")

    # config.json laden
    try:
        with open("config.json", 'r', encoding='utf-8') as f: config = json.load(f)
    except FileNotFoundError: print("FEHLER: config.json nicht gefunden!"); sys.exit(1)
    except json.JSONDecodeError as e: print(f"FEHLER: Die Datei config.json ist fehlerhaft: {e}"); sys.exit(1)

    # apparts.json laden
    try:
        with open(APPARTS_FILE, 'r', encoding='utf-8') as f:
            part_number_map = json.load(f)
        print(f"INFO: {len(part_number_map) - 2} AP-Teilenummern aus '{APPARTS_FILE}' geladen.") 
    except FileNotFoundError: 
        print(f"FEHLER: {APPARTS_FILE} nicht gefunden!"); sys.exit(1)
    except json.JSONDecodeError as e: 
        print(f"FEHLER: Die Datei {APPARTS_FILE} ist fehlerhaft: {e}"); sys.exit(1)

    # Config extrahieren
    cfg = {
        'timeout': config.get('timeout_seconds', 30),
        'num_threads': config.get('num_threads', 10),
        'lang': config.get('language_terms')
    }
    if not cfg['lang']: print("FEHLER: 'language_terms' fehlt in config.json."); sys.exit(1)

    # Ziel-Logik (unverändert)
    targets = []
    if args.importfile:
        print(f"\nINFO: Importiere Ziele aus Datei: {args.importfile}")
        try:
            offline_targets_from_csv = []
            with open(args.importfile, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                has_type_col = 'Typ' in reader.fieldnames
                has_status_col = 'Status' in reader.fieldnames
                for row in reader:
                    ip = row.get('IP-Adresse')
                    if not ip: continue
                    if has_type_col and row.get('Typ') != 'Aruba Instant Virtual Controller':
                        continue
                    if has_status_col and row.get('Status', '').lower() == 'down':
                        offline_targets_from_csv.append(ip)
                    else:
                        targets.append(ip)
            print(f"INFO: {len(targets) + len(offline_targets_from_csv)} Conductor(s) aus '{args.importfile}' importiert.")
            if offline_targets_from_csv:
                print(f"WARNUNG: {len(offline_targets_from_csv)} Conductor wurden in der CSV als 'Down' gemeldet.")
                if input("Sollen diese 'Down'-Conductor trotzdem am Ende geprüft werden? (j/n): ").lower() == 'j':
                    targets.extend(offline_targets_from_csv)
        except FileNotFoundError:
            print(f"FEHLER: Import-Datei '{args.importfile}' nicht gefunden.")
            sys.exit(1)
        except Exception as e:
            print(f"FEHLER: Konnte Import-Datei nicht verarbeiten: {e}")
            sys.exit(1)
    if args.targets:
        positional_targets = []
        for item in args.targets:
            positional_targets.extend(item.split(','))
        targets.extend(positional_targets)
    if not targets:
        targets = config.get('conductor_ips', [])
    if not targets:
        print("FEHLER: Keine Conductor-IPs angegeben (weder per CLI, Import noch in config.json).")
        parser.print_help()
        sys.exit(1)

    # Anmelde-Logik (unverändert)
    storage_choice = 'none'
    print("\n--- Konfiguration der Anmeldedaten ---")
    if KEYRING_AVAILABLE:
        prompt_text = ( "[1] Windows Credential Manager\n[2] Lokal verschlüsselte Datei\n[3] Manuelle Eingabe\nIhre Wahl: " )
        choice = input(prompt_text)
        if choice == '1': storage_choice = 'keyring'
        elif choice == '2':
            if CRYPTO_AVAILABLE: storage_choice = 'file'
            else: print("HINWEIS: 'pycryptodome' nicht installiert, Fallback auf manuelle Eingabe.")
    elif CRYPTO_AVAILABLE:
        print("\n" +
              ("WARNUNG - Zugangsdaten speichern\n"
               "  * Passwörter werden in der Datei 'credentials.bin' im aktuellen Verzeichnis abgelegt.\n"
               "  * Die Verschlüsselung ist nur ein Basisschutz (Schlüssel aus der MAC-Adresse dieses\n"
               "    Rechners, fester Salt) und KEIN sicherer Tresor: Wer die Datei und Zugriff auf diesen\n"
               "    Rechner hat, kann die Passwörter auslesen.\n"
               "  * Datei niemals weitergeben, in Git einchecken oder in Cloud-/Backup-Ordnern ablegen.\n"
               "  * Sicherer: Windows-Anmeldeinformationsverwaltung (Keyring).\n"))
        if input("Anmeldedaten trotzdem in 'credentials.bin' speichern? (j/n): ").lower() == 'j':
            storage_choice = 'file'
    cfg['storage_method'] = storage_choice

    credentials_store = {}
    targets_without_creds = list(targets)
    print("\n--- Pre-Flight Check: Prüfe gespeicherte Anmeldedaten ---")
    pre_check_user = None
    if cfg['storage_method'] == 'keyring':
        pre_check_user = input("Bitte den zu prüfenden SSH-Benutzernamen eingeben: ")
    found_creds_ips = []
    for ip in targets_without_creds:
        user, password = get_saved_credentials(ip, cfg, pre_check_user)
        if user and password:
            credentials_store[ip] = {'user': user, 'pass': password}
            found_creds_ips.append(ip)
    targets_without_creds = [ip for ip in targets_without_creds if ip not in found_creds_ips]
    if targets_without_creds:
        print(f"\nHINWEIS: Für {len(targets_without_creds)} von {len(targets)} Zielen fehlen Anmeldedaten.")
        use_same_for_all = False
        if len(targets_without_creds) > 1:
            if input("Sind die fehlenden Anmeldedaten für alle diese Ziele identisch? (j/n): ").lower() == 'j':
                use_same_for_all = True
        if use_same_for_all:
            print("\nBitte geben Sie die allgemeinen Anmeldedaten ein.")
            while True:
                user, password = get_credentials_interactively()
                first_target_to_check = targets_without_creds[0]
                if validate_credentials(first_target_to_check, user, password, cfg['timeout']):
                    print("INFO: Anmeldedaten erfolgreich validiert.")
                    if cfg['storage_method'] != 'none':
                        if input("Sollen diese Daten für alle fehlenden Ziele gespeichert werden? (j/n): ").lower() == 'j':
                            for ip in targets_without_creds:
                                save_credential(ip, user, password, cfg)
                    for ip in targets_without_creds:
                        credentials_store[ip] = {'user': user, 'pass': password}
                    break
                else:
                    if input("Erneut versuchen? (j/n): ").lower() != 'j':
                        sys.exit("Aktion abgebrochen.")
        else:
            for ip in targets_without_creds:
                print(f"\nBitte geben Sie die Anmeldedaten für {ip} ein.")
                while True:
                    user, password = get_credentials_interactively()
                    if validate_credentials(ip, user, password, cfg['timeout']):
                        print("INFO: Anmeldedaten erfolgreich validiert.")
                        if cfg['storage_method'] != 'none':
                             if input(f"Sollen diese Daten für {ip} gespeichert werden? (j/n): ").lower() == 'j':
                                save_credential(ip, user, password, cfg)
                        credentials_store[ip] = {'user': user, 'pass': password}
                        break
                    else:
                        if input("Erneut versuchen? (j/n): ").lower() != 'j':
                            sys.exit("Aktion abgebrochen.")
    else:
        if targets:
            print("INFO: Für alle Ziele wurden gespeicherte Anmeldedaten gefunden.")
    
    # Header-Definition (Logik aus v1.0.2)
    fieldnames_list = ['Conductor-Name', 'AP-IP-Adresse', 'AP-MAC-Adresse', 'Seriennummer', 'AP-Typ (Roh)', 'AP-Teilenummer']
    
    if args.greenlake:
        # GreenLake-Format (basierend auf sample_file-newcentral.csv)
        list_csv_file = os.path.join(output_dir, "greenlake_import_v2.csv")
        fieldnames_list = ['Serial_No', 'MAC_Address', 'Part_Number', 'tag:name1', 'tag:name2']
    else:
        # Standard-Format
        list_csv_file = os.path.join(output_dir, "ap_list.csv")
        if args.apname:
            fieldnames_list.insert(1, 'AP-Name')

    
    total_conductors_checked = 0
    total_aps_listed = 0
    failed_auth_ips = {}
    
    # Datensammlung (Logik aus v1.0.2)
    all_online_ap_details_list = []
    all_offline_ap_details_list = []

    for i, conductor_ip in enumerate(targets):
        creds = credentials_store.get(conductor_ip)
        if not creds:
            with print_lock: print(f"WARNUNG: Keine validen Anmeldedaten für {conductor_ip} vorhanden. Überspringe...")
            continue
        
        user, password = creds['user'], creds['pass']

        # 1. Daten vom Conductor holen (Ruft LOKALE Funktion auf)
        aps_to_check, provisioned_macs, conductor_name, _, reason = _local_get_conductor_data(conductor_ip, user, password, cfg['timeout'], cfg['lang'])
        
        if reason != "success":
            if reason == "auth_error":
                failed_auth_ips[conductor_ip] = user
            continue 
        
        total_conductors_checked += 1
        if not aps_to_check:
            with print_lock: print(f"INFO: Conductor {conductor_name} ({conductor_ip}) meldet keine online APs.")
            for mac in provisioned_macs:
                all_offline_ap_details_list.append({'conductor_name': conductor_name, 'mac': mac})
            continue

        # 2. Worker starten, um MAC-Adressen von Member-APs zu holen
        task_queue, all_results_queue = Queue(), Queue()
        threads = []
        for _ in range(cfg['num_threads']):
            thread = threading.Thread(target=worker, args=(task_queue, all_results_queue, user, password, cfg['timeout'], cfg['lang']))
            thread.start()
            threads.append(thread)
        
        sorted_ips = sorted(aps_to_check.keys(), key=lambda ip: [int(octet) for octet in ip.split('.') if octet.isdigit()])
        
        for ip in sorted_ips:
            info = aps_to_check[ip]
            task_queue.put((ip, info)) 

        task_queue.join()
        for _ in range(cfg['num_threads']): task_queue.put(None)
        for thread in threads: thread.join()

        all_online_ap_details_from_worker = [all_results_queue.get() for _ in range(all_results_queue.qsize())]
        
        # 3. Ergebnisse sammeln (Logik aus v1.0.2)
        found_online_macs = set()
        for ap_details in all_online_ap_details_from_worker:
            ap_details['conductor_name'] = conductor_name
            all_online_ap_details_list.append(ap_details)
            
            # --- ANPASSUNG V1.0.4 (Logik-Präzisierung) ---
            # Wir zählen nur valide MACs. Timeouts/Fehler werden ignoriert.
            if ap_details.get('eth0_mac') and ap_details.get('eth0_mac') not in ['N/A', 'TIMEOUT_ODER_FEHLER']:
                found_online_macs.add(ap_details['eth0_mac'].lower())

        offline_macs_set = provisioned_macs - found_online_macs
        for mac in offline_macs_set:
            all_offline_ap_details_list.append({'conductor_name': conductor_name, 'mac': mac})

        with print_lock:
            print(f"\n--- Zusammenfassung für Conductor: {conductor_name} ({conductor_ip}) ---")
            print(f"INFO: {len(all_online_ap_details_from_worker)} Online-APs erfasst.")
            if offline_macs_set:
                # --- ANPASSUNG V1.0.4 (Wording) ---
                print(f"WARNUNG: {len(offline_macs_set)} APs sind OFFLINE (in config, aber nicht in 'show aps' gefunden).")
            # Wir prüfen, ob Timeouts aufgetreten sind (separat von 'offline')
            failed_queries = [ap for ap in all_online_ap_details_from_worker if ap.get('eth0_mac') == "TIMEOUT_ODER_FEHLER"]
            if failed_queries:
                print(f"WARNUNG: {len(failed_queries)} APs KONNTEN NICHT ABGEFRAGT WERDEN (Timeout/Fehler bei 'show interface').")

            print(f"--- Ende Abfrage für Conductor: {conductor_ip} ---")

    # CSV-Schreiben (Logik aus v1.0.2)
    try:
        with open(list_csv_file, 'w', newline='', encoding='utf-8-sig') as f_list:
            writer_list = csv.DictWriter(f_list, fieldnames=fieldnames_list, extrasaction='ignore')
            writer_list.writeheader()
            
            # --- ANPASSUNG V1.0.4 (Wording) ---
            # Prüft, ob es *echte* Offline-APs gibt ODER ob MAC-Abfragen fehlschlugen.
            failed_mac_queries_total = [ap for ap in all_online_ap_details_list if ap.get('eth0_mac') == "TIMEOUT_ODER_FEHLER"]
            total_problems = len(all_offline_ap_details_list) + len(failed_mac_queries_total)

            if total_problems > 0:
                warning_text = f"*** HINWEIS: {len(all_offline_ap_details_list)} APs SIND OFFLINE UND {len(failed_mac_queries_total)} APs KONNTEN NICHT ERREICHT WERDEN (SIEHE CSV-ENDE) ***"
                warning_row = {fieldnames_list[0]: warning_text}
                writer_list.writerow(warning_row)

            # Online-APs verarbeiten
            sorted_online_list = sorted(all_online_ap_details_list, key=lambda x: [int(octet) for octet in x['ip'].split('.') if octet.isdigit()], reverse=False)

            for ap_details in sorted_online_list:
                raw_type = ap_details.get('ap_type', 'N/A')
                part_number = translate_ap_type(raw_type, part_number_map)
                
                # GreenLake-Format V2 (Logik aus v1.0.2)
                if args.greenlake:
                    row_data = {
                        'Serial_No': ap_details.get('serial'),
                        'MAC_Address': ap_details.get('eth0_mac', 'N/A'),
                        'Part_Number': part_number,
                        'tag:name1': 'dummytag1', 
                        'tag:name2': 'dummytag2'
                    }
                else:
                    # Standard Format (Logik aus v1.0.2)
                    row_data = {
                        'Conductor-Name': ap_details.get('conductor_name'),
                        'AP-IP-Adresse': ap_details.get('ip'),
                        'AP-MAC-Adresse': ap_details.get('eth0_mac', 'N/A'),
                        'Seriennummer': ap_details.get('serial'),
                        'AP-Typ (Roh)': raw_type,
                        'AP-Teilenummer': part_number
                    }
                    if args.apname:
                        row_data['AP-Name'] = ap_details.get('name', 'N/A')
                
                writer_list.writerow(row_data)
                total_aps_listed += 1
            
            # --- ANPASSUNG V1.0.4 (Wording und getrennter Footer) ---
            if total_problems > 0:
                separator_row = {fieldnames_list[0]: "--- LISTE DER OFFLINE ODER NICHT ERREICHBAREN APs ---"}
                writer_list.writerow(separator_row)

                if all_offline_ap_details_list:
                    sub_header_offline = {fieldnames_list[0]: "--- OFFLINE APs (Gefunden in 'show running-config', aber nicht in 'show aps') ---"}
                    writer_list.writerow(sub_header_offline)
                    
                    if args.greenlake:
                        footer_header = {'Serial_No': "Conductor-Name", 'MAC_Address': "Offline-MAC-Adresse"}
                    else:
                        footer_header = {'Conductor-Name': "Conductor-Name", 'AP-IP-Adresse': "Offline-MAC-Adresse"}
                    writer_list.writerow(footer_header)
                    
                    for ap in sorted(all_offline_ap_details_list, key=lambda x: x['conductor_name']):
                        if args.greenlake:
                            offline_row = {'Serial_No': ap['conductor_name'], 'MAC_Address': ap['mac']}
                        else:
                            offline_row = {'Conductor-Name': ap['conductor_name'], 'AP-IP-Adresse': ap['mac']}
                        writer_list.writerow(offline_row)

                if failed_mac_queries_total:
                    sub_header_failed = {fieldnames_list[0]: "--- NICHT ERREICHBARE APs (Gefunden in 'show aps', aber 'show interface' Abfrage fehlgeschlagen) ---"}
                    writer_list.writerow(sub_header_failed)

                    if args.greenlake:
                        footer_header = {'Serial_No': "Conductor-Name", 'MAC_Address': "AP-IP-Adresse", 'Part_Number': "Seriennummer"}
                    else:
                        footer_header = {'Conductor-Name': "Conductor-Name", 'AP-IP-Adresse': "AP-IP-Adresse", 'Seriennummer': "Seriennummer"}
                    writer_list.writerow(footer_header)

                    for ap in sorted(failed_mac_queries_total, key=lambda x: x['conductor_name']):
                        if args.greenlake:
                            failed_row = {'Serial_No': ap['conductor_name'], 'MAC_Address': ap['ip'], 'Part_Number': ap.get('serial', 'N/A')}
                        else:
                            failed_row = {'Conductor-Name': ap['conductor_name'], 'AP-IP-Adresse': ap['ip'], 'Seriennummer': ap.get('serial', 'N/A')}
                        writer_list.writerow(failed_row)


    except IOError as e:
        print(f"FEHLER: Die CSV-Datei '{list_csv_file}' konnte nicht geschrieben werden: {e}")
    except Exception as e:
        print(f"Ein unerwarteter Fehler ist aufgetreten: {e}")

    end_time = datetime.now()
    total_duration = end_time - start_time
    print(f"\n===== Skriptende: {end_time.strftime('%Y-%m-%d %H:%M:%S')} =====")
    print(f"Gesamtdauer: {str(total_duration).split('.')[0]}")
    print(f"{total_aps_listed} Online-Access Points bei {total_conductors_checked} Conductors erfasst.")
    
    # --- ANPASSUNG V1.0.4 (Wording und getrennte Zählung) ---
    if all_offline_ap_details_list or failed_mac_queries_total:
        print(f"WARNUNG: {len(all_offline_ap_details_list)} APs sind OFFLINE und {len(failed_mac_queries_total)} APs konnten NICHT ABGEFRAGT werden. (Siehe CSV-Ende)")

    if total_aps_listed > 0:
        time_per_ap = total_duration.total_seconds() / total_aps_listed
        print(f"Durchschnittliche Zeit pro Online-AP (inkl. MAC-Abfrage): {time_per_ap:.2f} Sekunden")

    # Aufräum-Logik (unverändert)
    if failed_auth_ips:
        print("\n--- Aufräumen fehlgeschlagener Logins ---")
        print("Für die folgenden Conductors ist die Authentifizierung mit gespeicherten Daten fehlgeschlagen:")
        for ip in failed_auth_ips:
            print(f"- {ip}")
        if input("Sollen diese veralteten Anmeldedaten aus dem Speicher gelöscht werden? (j/n): ").lower() == 'j':
            for ip, user in failed_auth_ips.items():
                deleted_stores = delete_credential_for_ip(ip, user)
                if deleted_stores:
                    print(f"INFO: Veraltete Anmeldedaten für {ip} (Benutzer: {user}) aus {', '.join(deleted_stores)} gelöscht.")

    if 'log_file_handler' in locals() and log_file_handler:
        sys.stdout = original_stdout
        log_file_handler.close()
        print(f"\nLog-Datei wurde gespeichert: {log_filename}")

### Hier ist das Ende ###