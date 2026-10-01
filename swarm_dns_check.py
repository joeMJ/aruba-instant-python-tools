### swarm_dns_check.py
### Version 1.0.0
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
    delete_credential_for_ip, KEYRING_AVAILABLE, CRYPTO_AVAILABLE
)

SWARM_DNS_CHECK_VERSION = "1.0.0"
TOOLSUITE_VERSION = "2.0.0"
print_lock = threading.Lock()

def check_conductor_dns(ip, user, pw, timeout, url_to_check):
    """
    Führt eine hochperformante DNS-Prüfung direkt auf dem Conductor (VC) durch.
    Liest den Conductor-Namen aus und extrahiert die aufgelöste IP via Ping.
    """
    with print_lock:
        print(f"INFO: Verbinde mit Conductor {ip} für DNS-Check...")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    result = {
        'conductor_name': 'N/A',
        'resolved_ip': 'Nicht aufgelöst',
        'status': 'Fehler'
    }

    try:
        client.connect(ip, username=user, password=pw, timeout=timeout)
        channel = client.invoke_shell()

        # Puffer leeren
        time.sleep(1)
        if channel.recv_ready():
            channel.recv(65535)

        # 1. Schnelle Abfrage des Conductor-Namens
        channel.send("show summary | include Name\n")
        time.sleep(1)
        if channel.recv_ready():
            summary_out = channel.recv(65535).decode('utf-8', errors='ignore')
            if name_match := re.search(r"Name\s+:\s*(.+)", summary_out):
                result['conductor_name'] = name_match.group(1).strip()

        # Fallback, falls 'show summary' den Namen nicht liefert
        if result['conductor_name'] == 'N/A':
            channel.send("show running-config | include \"name \"\n")
            time.sleep(1)
            if channel.recv_ready():
                cfg_out = channel.recv(65535).decode('utf-8', errors='ignore')
                if name_match := re.search(r"^name\s+(\S+)", cfg_out, re.MULTILINE):
                    result['conductor_name'] = name_match.group(1).strip()

        # 2. Interaktive Ping-Abfrage starten
        channel.send(f"ping {url_to_check}\n")

        output = ""
        start_time = time.time()

        # Überwache den Output für max. 5 Sekunden
        while time.time() - start_time < 5:
            if channel.recv_ready():
                output += channel.recv(65535).decode('utf-8', errors='ignore')

                # Regex sucht nach PING sub.domain.tld (10.1.2.3)
                if match := re.search(rf"PING\s+[^\s]+\s+\(([\d\.]+)\)", output, re.IGNORECASE):
                    result['resolved_ip'] = match.group(1)
                    result['status'] = 'OK'
                    channel.send("q\n")  # Ping abbrechen
                    return result

                if "bad address" in output.lower() or "host address failed" in output.lower():
                    result['status'] = 'DNS Fehler (Bad Address)'
                    channel.send("q\n")
                    return result

            time.sleep(0.5)

        channel.send("q\n")
        result['status'] = 'Timeout'
        return result

    except paramiko.AuthenticationException:
        result['status'] = 'Auth Fehler'
        return result
    except Exception as e:
        with print_lock:
            print(f"FEHLER bei Conductor {ip}: {e}")
        result['status'] = f'Verbindungsfehler: {e}'
        return result
    finally:
        if client: client.close()


def worker(task_queue, all_results_queue, user, pw, timeout, url_to_check, wanted_ip):
    """Worker-Thread für die parallele Abfrage der Conductors."""
    while True:
        ip = task_queue.get()
        if ip is None: break

        dns_data = check_conductor_dns(ip, user, pw, timeout, url_to_check)

        # Logik für --wantedip filtern
        if wanted_ip and dns_data['resolved_ip'] == wanted_ip:
            # Wird ignoriert, da die IP der gewünschten IP entspricht
            task_queue.task_done()
            continue

        full_result = {
            'Conductor-Name': dns_data['conductor_name'],
            'Conductor IP': ip,
            'URI': url_to_check,
            'Aufgelöste IP': dns_data['resolved_ip'],
            'Status': dns_data['status']
        }

        all_results_queue.put(full_result)
        task_queue.task_done()


# === Hauptskript ===
if __name__ == "__main__":
    check_dependencies()

    original_stdout = sys.stdout
    log_file_handler = None

    epilog_text = """
Beispiele:
  # Prüft, wie google.de auf dem Conductor aufgelöst wird
  py swarm_dns_check.py 10.1.1.1 --checkurl google.de

  # Prüft alle Conductors aus einer Liste, zeigt aber NUR die an, die NICHT 192.168.1.100 auflösen
  py swarm_dns_check.py --importfile C:\\pfad\\liste.csv --checkurl sub.domain.tld --wantedip 192.168.1.100 --log
"""

    parser = argparse.ArgumentParser(
        description="Prüft die DNS-Auflösung (via Ping) auf Aruba Conductors.",
        epilog=epilog_text,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('targets', nargs='*', default=[], help="Optional: Eine oder mehrere Conductor-IPs (kommasepariert).")
    parser.add_argument('--importfile', type=str, help="Pfad zu einer CSV-Datei, aus der Conductor-IPs importiert werden sollen.")
    parser.add_argument('--log', action='store_true', help="Aktiviert das Schreiben der Konsolenausgabe in die Log-Datei im Ergebnisordner.")
    parser.add_argument('--delete-credentials', type=str, help="WERKZEUG: Löscht gespeicherte Anmeldedaten für die angegebenen IPs.")

    # NEUE PARAMETER
    parser.add_argument('--checkurl', type=str, required=True, help="ZWINGEND: Die zu prüfende Domain/URL (z.B. sub.domain.tld).")
    parser.add_argument('--wantedip', type=str, help="OPTIONAL: Listet nur Conductors auf, die NICHT diese IP auflösen.")

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
    output_dir = os.path.join(os.getcwd(), "swarm_dns_check_" + run_timestamp)
    os.makedirs(output_dir, exist_ok=True)

    if args.log:
        try:
            log_filename = os.path.join(output_dir, "swarm_dns_check_log.txt")
            log_file_handler = Logger(filename=log_filename)
            sys.stdout = log_file_handler
        except Exception as e:
            sys.stdout = original_stdout
            print(f"FEHLER: Log-Datei konnte nicht erstellt werden: {e}")

    print(f"swarm_dns_check.py Version {SWARM_DNS_CHECK_VERSION} wird ausgeführt...")
    print(f"Teil der Aruba Instant Toolsammlung Version {TOOLSUITE_VERSION}")
    print(f"Nutze aruba_helper.py Version {HELPER_VERSION}")
    print(f"INFO: Ziel-URL für Prüfung: {args.checkurl}")
    if args.wantedip:
        print(f"INFO: Filter aktiv -> Zeige nur Conductors, die ungleich '{args.wantedip}' auflösen.")
    print(f"INFO: Ergebnisse werden im Verzeichnis '{output_dir}' gespeichert.")

    start_time = datetime.now()
    print(f"\n===== Skriptstart: {start_time.strftime('%Y-%m-%d %H:%M:%S')} =====")

    # config.json laden
    try:
        with open("config.json", 'r', encoding='utf-8') as f: config = json.load(f)
    except FileNotFoundError: print("FEHLER: config.json nicht gefunden!"); sys.exit(1)
    except json.JSONDecodeError as e: print(f"FEHLER: Die Datei config.json ist fehlerhaft: {e}"); sys.exit(1)

    cfg = {
        'timeout': config.get('timeout_seconds', 30),
        'num_threads': config.get('num_threads', 10)
    }

    # Ziel-Logik
    targets = []
    if args.importfile:
        print(f"\nINFO: Importiere Ziele aus Datei: {args.importfile}")
        try:
            offline_targets_from_csv = []
            with open(args.importfile, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                has_status_col = 'Status' in reader.fieldnames
                for row in reader:
                    ip = row.get('IP-Adresse')
                    if not ip: continue
                    if has_status_col and row.get('Status', '').lower() == 'down':
                        offline_targets_from_csv.append(ip)
                    else:
                        targets.append(ip)
            print(f"INFO: {len(targets) + len(offline_targets_from_csv)} Conductor(s) aus '{args.importfile}' importiert.")
            if offline_targets_from_csv:
                print(f"WARNUNG: {len(offline_targets_from_csv)} Conductor wurden in der CSV als 'Down' gemeldet.")
                if input("Sollen diese 'Down'-Conductor trotzdem geprüft werden? (j/n): ").lower() == 'j':
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
    targets_without_creds = list(set(targets))
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
        print(f"\nHINWEIS: Für {len(targets_without_creds)} Zielen fehlen Anmeldedaten.")
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
        print("INFO: Für alle Ziele wurden gespeicherte Anmeldedaten gefunden.")

    print(f"\n--- Phase 1: Starte DNS-Abfragen bei {len(set(targets))} Conductor(s) ---")

    task_queue, all_results_queue = Queue(), Queue()
    threads = []

    # Threads starten
    for _ in range(cfg['num_threads']):
        # Wir übergeben hier temporär None für user/pw, da die Credentials pro IP abweichen können
        thread = threading.Thread(target=worker, args=(task_queue, all_results_queue, None, None, cfg['timeout'], args.checkurl, args.wantedip))
        thread.start()
        threads.append(thread)

    # Warteschlange füllen (Wir modifizieren den Worker-Ansatz leicht, um Credentials mitzugeben)
    # Da der Worker im Moment globale user/pw Parameter hat, passe ich den Task-Input an:
    def worker_modified(task_queue, all_results_queue, timeout, url_to_check, wanted_ip):
        while True:
            item = task_queue.get()
            if item is None: break
            ip, user, pw = item
            dns_data = check_conductor_dns(ip, user, pw, timeout, url_to_check)
            if wanted_ip and dns_data['resolved_ip'] == wanted_ip:
                task_queue.task_done()
                continue
            all_results_queue.put({
                'Conductor-Name': dns_data['conductor_name'],
                'Conductor IP': ip,
                'URI': url_to_check,
                'Aufgelöste IP': dns_data['resolved_ip'],
                'Status': dns_data['status']
            })
            task_queue.task_done()

    # Wir stoppen die alten Threads sofort und nutzen die modifizierten, um individuelle Creds pro IP zu erlauben
    for _ in range(cfg['num_threads']): task_queue.put(None)
    for thread in threads: thread.join()

    task_queue = Queue()
    threads = []
    for _ in range(cfg['num_threads']):
        thread = threading.Thread(target=worker_modified, args=(task_queue, all_results_queue, cfg['timeout'], args.checkurl, args.wantedip))
        thread.start()
        threads.append(thread)

    for ip in set(targets):
        creds = credentials_store.get(ip)
        if creds:
            task_queue.put((ip, creds['user'], creds['pass']))

    task_queue.join()
    for _ in range(cfg['num_threads']): task_queue.put(None)
    for thread in threads: thread.join()

    all_results = [all_results_queue.get() for _ in range(all_results_queue.qsize())]

    # CSV Definition
    fieldnames_list = ['Conductor-Name', 'Conductor IP', 'URI', 'Aufgelöste IP', 'Status']
    list_csv_file = os.path.join(output_dir, "swarm_dns_results.csv")

    print("\n--- Phase 2: Ergebnisse schreiben ---")
    try:
        with open(list_csv_file, 'w', newline='', encoding='utf-8-sig') as f_list:
            writer_list = csv.DictWriter(f_list, fieldnames=fieldnames_list, extrasaction='ignore')
            writer_list.writeheader()

            sorted_results = sorted(all_results, key=lambda x: [int(octet) for octet in x['Conductor IP'].split('.') if octet.isdigit()], reverse=False)

            for row in sorted_results:
                writer_list.writerow(row)

        print(f"INFO: {len(all_results)} Einträge in die CSV geschrieben.")
    except IOError as e:
        print(f"FEHLER: Die CSV-Datei '{list_csv_file}' konnte nicht geschrieben werden: {e}")

    end_time = datetime.now()
    total_duration = end_time - start_time
    print(f"\n===== Skriptende: {end_time.strftime('%Y-%m-%d %H:%M:%S')} =====")
    print(f"Gesamtdauer: {str(total_duration).split('.')[0]}")

    if args.wantedip:
        print(f"-> {len(all_results)} Conductors gefunden, bei denen die Domain NICHT als '{args.wantedip}' aufgelöst wird.")
    else:
        print(f"-> DNS-Auflösung für {len(all_results)} Conductors erfolgreich protokolliert.")

    if 'log_file_handler' in locals() and log_file_handler:
        sys.stdout = original_stdout
        log_file_handler.close()
        print(f"\nLog-Datei wurde gespeichert: {log_filename}")

### Hier ist das Ende ###
