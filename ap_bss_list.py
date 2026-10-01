### ap_bss_list.py
### Version 1.0.2
### Bestandteil der Aruba Instant Python Tools Suite V 2.0.0
### Letzte Änderung 2026-04-17
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

AP_BSS_LIST_VERSION = "1.0.2"
TOOLSUITE_VERSION = "2.0.0"
print_lock = threading.Lock()

# --- LOKALE HELPER (Um aruba_helper.py nicht zu verändern) ---
def _local_execute_command_on_shell(client, command):
    """LOKALE KOPIE für sichere Command-Ausführung."""
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
    LOKALE KOPIE aus ap_list.py, um den AP-Namen zuverlässig auszulesen,
    ohne die globalen Funktionen zu beeinträchtigen.
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

        provisioned_macs = set(mac.lower() for mac in re.findall(r"allowed-ap ([\da-fA-F:]+)", config_output))
        if name_match := re.search(r"^name\s+(\S+)", config_output, re.MULTILINE):
            conductor_name = name_match.group(1)
        with print_lock: print(f"INFO: {len(provisioned_macs)} provisionierte APs in der Konfiguration für '{conductor_name}' gefunden.")

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

            # Liest den Namen als erstes Segment aus - FIX: Erlaubt optionales Sternchen nach dem Namen
            match = re.search(
                r"^(\S+)\s*\*?\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\*?\s+(\w+)\s+.*?\s+\d+\s+(\d+\(.*?\))\s+.*?\s+([\dA-Z]+)\s+.*?\s+(?:enable|disable)\s+([\d\w:]+)",
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

# --- NEUE FUNKTION: AP BSS & MAC AUSLESEN ---
def get_ap_bss_data(ip, user, pw, timeout, lang_terms):
    """
    Verbindet sich mit einem einzelnen AP, holt die Hardware-MAC (eth0)
    und durchsucht die 'show ap bss-table' nach ESS/BSS Einträgen, die zu dieser IP gehören.
    """
    with print_lock:
        print(f"INFO: Verbinde mit Member-AP {ip} für BSS-Abfrage...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    result = {'eth0_mac': 'TIMEOUT_ODER_FEHLER', 'bss_entries': []}
    try:
        client.connect(ip, username=user, password=pw, timeout=timeout)

        # 1. MAC-Adresse auslesen
        interface_output = _local_execute_command_on_shell(client, "show interface")
        interface_blocks = re.split(rf"\n(?=(?:eth|bond)\d is up)", '\n' + interface_output)

        found_mac = 'N/A'
        for block in interface_blocks:
            name_match = re.search(r"^((?:eth|bond)\d)", block.strip())
            if not name_match: continue
            if_name = name_match.group(1)

            if mac_match := re.search(rf"{lang_terms['interface_address']} ([\da-fA-F:]{{17}})", block):
                if if_name == "bond0":
                    found_mac = mac_match.group(1)
                    break
                elif if_name == "eth0":
                    found_mac = mac_match.group(1)

        result['eth0_mac'] = found_mac

        # 2. BSS-Tabelle auslesen
        bss_output = _local_execute_command_on_shell(client, "show ap bss-table")

        for line in bss_output.splitlines():
            # Extrahiert BSS, ESS und IP. Die Filterung per row_ip stellt sicher,
            # dass nur BSSIDs dieses konkreten APs aufgenommen werden.
            match = re.search(r"^([a-fA-F0-9:]{17})\s+(.+?)\s+(\S+)\s+(\d{1,3}(?:\.\d{1,3}){3})", line)
            if match:
                bss_mac = match.group(1).lower()
                ess_name = match.group(2).strip()
                row_ip = match.group(4)

                if row_ip == ip:
                    result['bss_entries'].append({'bss': bss_mac, 'ess': ess_name})

        return result

    except Exception as e:
        with print_lock:
            print(f"FEHLER bei AP {ip} (BSS-Abfrage): {e}")
        return result
    finally:
        if client: client.close()

def worker(task_queue, all_results_queue, user, pw, timeout, lang_terms):
    """Worker-Thread für die parallele Abfrage der Member-APs."""
    while True:
        item = task_queue.get()
        if item is None: break

        ip, ap_info = item
        bss_data = get_ap_bss_data(ip, user, pw, timeout, lang_terms)

        full_result = ap_info.copy()
        full_result['ip'] = ip
        full_result['eth0_mac'] = bss_data['eth0_mac']
        full_result['bss_entries'] = bss_data['bss_entries']

        all_results_queue.put(full_result)
        task_queue.task_done()

# === Hauptskript ===
if __name__ == "__main__":
    check_dependencies()

    original_stdout = sys.stdout
    log_file_handler = None

    epilog_text = """
Beispiele:
  # Standard-BSS-Liste für einen Conductor erstellen
  py ap_bss_list.py 10.1.1.1

  # Importieren und Log erstellen
  py ap_bss_list.py --importfile C:\\pfad\\zur\\liste.csv --log
"""

    parser = argparse.ArgumentParser(
        description="Erstellt eine detaillierte BSSID-Liste (ESS, BSS, MAC, Name) von Aruba Conductors.",
        epilog=epilog_text,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('targets', nargs='*', default=[], help="Optional: Eine oder mehrere Conductor-IPs (kommasepariert).")
    parser.add_argument('--importfile', type=str, help="Pfad zu einer CSV-Datei, aus der Conductor-IPs importiert werden sollen.")
    parser.add_argument('--log', action='store_true', help="Aktiviert das Schreiben der Konsolenausgabe in die Log-Datei im Ergebnisordner.")
    parser.add_argument('--delete-credentials', type=str, help="WERKZEUG: Löscht gespeicherte Anmeldedaten für die angegebenen IPs.")

    args = parser.parse_args()

    # Logik für --delete-credentials
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
    output_dir = os.path.join(os.getcwd(), "ap_bss_list_" + run_timestamp)
    os.makedirs(output_dir, exist_ok=True)

    if args.log:
        try:
            log_filename = os.path.join(output_dir, "ap_bss_list_log.txt")
            log_file_handler = Logger(filename=log_filename)
            sys.stdout = log_file_handler
        except Exception as e:
            sys.stdout = original_stdout
            print(f"FEHLER: Log-Datei konnte nicht erstellt werden: {e}")

    print(f"ap_bss_list.py Version {AP_BSS_LIST_VERSION} wird ausgeführt...")
    print(f"Teil der Aruba Instant Toolsammlung Version {TOOLSUITE_VERSION}")
    print(f"Nutze aruba_helper.py Version {HELPER_VERSION}")
    print(f"INFO: Ergebnisse werden im Verzeichnis '{output_dir}' gespeichert.")

    start_time = datetime.now()
    print(f"\n===== Skriptstart: {start_time.strftime('%Y-%m-%d %H:%M:%S')} =====")

    # config.json laden
    try:
        with open("config.json", 'r', encoding='utf-8') as f: config = json.load(f)
    except FileNotFoundError: print("FEHLER: config.json nicht gefunden!"); sys.exit(1)
    except json.JSONDecodeError as e: print(f"FEHLER: Die Datei config.json ist fehlerhaft: {e}"); sys.exit(1)

    # Config extrahieren
    cfg = {
        'timeout': config.get('timeout_seconds', 30),
        'num_threads': config.get('num_threads', 10),
        'lang': config.get('language_terms')
    }
    if not cfg['lang']: print("FEHLER: 'language_terms' fehlt in config.json."); sys.exit(1)

    # Ziel-Logik
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

    # Anmelde-Logik
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

    # CSV Definition - NEUE SPALTEN-SORTIERUNG
    fieldnames_list = ['Conductor-Name', 'AP Name', 'EKA', 'AP MAC', 'AP IP', 'AP ESS', 'AP BSS']
    list_csv_file = os.path.join(output_dir, "ap_bss_list.csv")

    total_conductors_checked = 0
    total_bss_listed = 0
    failed_auth_ips = {}

    all_online_ap_details_list = []
    all_offline_ap_details_list = []

    for i, conductor_ip in enumerate(targets):
        creds = credentials_store.get(conductor_ip)
        if not creds:
            with print_lock: print(f"WARNUNG: Keine validen Anmeldedaten für {conductor_ip} vorhanden. Überspringe...")
            continue

        user, password = creds['user'], creds['pass']

        # 1. Daten vom Conductor holen
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

        # 2. Worker starten, um BSS und MAC-Adressen von Member-APs zu holen
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

        # 3. Ergebnisse sammeln
        found_online_macs = set()
        for ap_details in all_online_ap_details_from_worker:
            ap_details['conductor_name'] = conductor_name
            all_online_ap_details_list.append(ap_details)

            if ap_details.get('eth0_mac') and ap_details.get('eth0_mac') not in ['N/A', 'TIMEOUT_ODER_FEHLER']:
                found_online_macs.add(ap_details['eth0_mac'].lower())

        offline_macs_set = provisioned_macs - found_online_macs
        for mac in offline_macs_set:
            all_offline_ap_details_list.append({'conductor_name': conductor_name, 'mac': mac})

        with print_lock:
            print(f"\n--- Zusammenfassung für Conductor: {conductor_name} ({conductor_ip}) ---")
            print(f"INFO: {len(all_online_ap_details_from_worker)} Online-APs erfasst.")
            if offline_macs_set:
                print(f"WARNUNG: {len(offline_macs_set)} APs sind OFFLINE (in config, aber nicht erfolgreich abgefragt).")

            failed_queries = [ap for ap in all_online_ap_details_from_worker if ap.get('eth0_mac') == "TIMEOUT_ODER_FEHLER"]
            if failed_queries:
                print(f"WARNUNG: {len(failed_queries)} APs KONNTEN NICHT ABGEFRAGT WERDEN (Timeout/Fehler bei AP-Zugriff).")

            print(f"--- Ende Abfrage für Conductor: {conductor_ip} ---")

    # CSV-Schreiben
    try:
        with open(list_csv_file, 'w', newline='', encoding='utf-8-sig') as f_list:
            writer_list = csv.DictWriter(f_list, fieldnames=fieldnames_list, extrasaction='ignore')
            writer_list.writeheader()

            failed_mac_queries_total = [ap for ap in all_online_ap_details_list if ap.get('eth0_mac') == "TIMEOUT_ODER_FEHLER"]
            total_problems = len(all_offline_ap_details_list) + len(failed_mac_queries_total)

            if total_problems > 0:
                warning_text = f"*** HINWEIS: {len(all_offline_ap_details_list)} APs SIND OFFLINE UND {len(failed_mac_queries_total)} APs KONNTEN NICHT ERREICHT WERDEN (SIEHE CSV-ENDE) ***"
                warning_row = {fieldnames_list[0]: warning_text}
                writer_list.writerow(warning_row)

            # Online-APs verarbeiten
            sorted_online_list = sorted(all_online_ap_details_list, key=lambda x: [int(octet) for octet in x['ip'].split('.') if octet.isdigit()], reverse=False)

            for ap_details in sorted_online_list:
                if ap_details.get('eth0_mac') == "TIMEOUT_ODER_FEHLER":
                    continue

                # Wenn BSS-Einträge vorhanden sind, für jeden Eintrag eine Zeile anlegen
                if ap_details.get('bss_entries'):
                    for bss_entry in ap_details['bss_entries']:
                        # Extrahiere die letzten 5 Zeichen (z.B. "b9:b0") für die EKA-Spalte
                        eka_val = bss_entry['bss'][-5:]

                        row_data = {
                            'Conductor-Name': ap_details.get('conductor_name'),
                            'AP Name': ap_details.get('name', 'N/A'),
                            'EKA': eka_val,
                            'AP MAC': ap_details.get('eth0_mac', 'N/A'),
                            'AP IP': ap_details.get('ip'),
                            'AP ESS': bss_entry['ess'],
                            'AP BSS': bss_entry['bss']
                        }
                        writer_list.writerow(row_data)
                        total_bss_listed += 1
                else:
                    # Fallback-Zeile, falls der AP keine BSS-Einträge gemeldet hat
                    row_data = {
                        'Conductor-Name': ap_details.get('conductor_name'),
                        'AP Name': ap_details.get('name', 'N/A'),
                        'EKA': 'N/A',
                        'AP MAC': ap_details.get('eth0_mac', 'N/A'),
                        'AP IP': ap_details.get('ip'),
                        'AP ESS': 'Keine gesendet',
                        'AP BSS': 'N/A'
                    }
                    writer_list.writerow(row_data)
                    total_bss_listed += 1

            # --- FOOTER FÜR PROBLEMATISCHE APs ---
            if total_problems > 0:
                separator_row = {fieldnames_list[0]: "--- LISTE DER OFFLINE ODER NICHT ERREICHBAREN APs ---"}
                writer_list.writerow(separator_row)

                if all_offline_ap_details_list:
                    sub_header_offline = {fieldnames_list[0]: "--- OFFLINE APs (Gefunden in 'show running-config', aber nicht aktiv) ---"}
                    writer_list.writerow(sub_header_offline)

                    footer_header = {'Conductor-Name': "Conductor-Name", 'AP Name': "AP Name", 'EKA': "EKA", 'AP MAC': "Offline-MAC-Adresse"}
                    writer_list.writerow(footer_header)

                    for ap in sorted(all_offline_ap_details_list, key=lambda x: x['conductor_name']):
                        offline_row = {'Conductor-Name': ap['conductor_name'], 'AP Name': "Unbekannt", 'EKA': "N/A", 'AP MAC': ap['mac']}
                        writer_list.writerow(offline_row)

                if failed_mac_queries_total:
                    sub_header_failed = {fieldnames_list[0]: "--- NICHT ERREICHBARE APs (Gefunden in 'show aps', aber AP-Zugriff fehlgeschlagen) ---"}
                    writer_list.writerow(sub_header_failed)

                    footer_header = {'Conductor-Name': "Conductor-Name", 'AP Name': "AP Name", 'EKA': "EKA", 'AP IP': "AP-IP-Adresse"}
                    writer_list.writerow(footer_header)

                    for ap in sorted(failed_mac_queries_total, key=lambda x: x['conductor_name']):
                        failed_row = {'Conductor-Name': ap['conductor_name'], 'AP Name': ap.get('name', 'N/A'), 'EKA': "N/A", 'AP IP': ap['ip']}
                        writer_list.writerow(failed_row)

    except IOError as e:
        print(f"FEHLER: Die CSV-Datei '{list_csv_file}' konnte nicht geschrieben werden: {e}")
    except Exception as e:
        print(f"Ein unerwarteter Fehler ist aufgetreten: {e}")

    end_time = datetime.now()
    total_duration = end_time - start_time
    print(f"\n===== Skriptende: {end_time.strftime('%Y-%m-%d %H:%M:%S')} =====")
    print(f"Gesamtdauer: {str(total_duration).split('.')[0]}")
    print(f"{total_bss_listed} BSS-Zuordnungen bei {total_conductors_checked} Conductors erfasst.")

    if all_offline_ap_details_list or failed_mac_queries_total:
        print(f"WARNUNG: {len(all_offline_ap_details_list)} APs sind OFFLINE und {len(failed_mac_queries_total)} APs konnten NICHT ABGEFRAGT werden. (Siehe CSV-Ende)")

    # Aufräum-Logik für Authentifizierungsfehler
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
