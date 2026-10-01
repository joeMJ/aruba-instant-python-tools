### Aruba Instant Python Tools
### ap_findlog.py - Durchsucht System- und Diagnoseprotokolle von Aruba Instant APs nach Textmustern
### Version 1.0.0
### Bestandteil der Aruba Instant Python Tools Suite V 2.0.0
### gemacht mit viel Liebe von John (johnlose.de)

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

# Importiere unveränderte Helper-Funktionen aus aruba_helper.py (Code-Freeze)
from aruba_helper import (
    SCRIPT_VERSION as HELPER_VERSION, check_dependencies, Logger, get_saved_credentials,
    validate_credentials, get_credentials_interactively, save_credential,
    delete_credential_for_ip, execute_command_on_shell,
    KEYRING_AVAILABLE, CRYPTO_AVAILABLE
)

TOOLSUITE_VERSION = "2.0.0"

AP_FINDLOG_VERSION = "1.0.0"
print_lock = threading.Lock()

# Offizielle Liste der durch 'show log ?' unterstützten Protokolle in Aruba Instant OS
VALID_PROTOCOLS = [
    "ams", "ap-debug", "apifmgr", "apprf-to-cloud", "convert",
    "datapath-exceptions", "ddns-client", "debug", "dhcp", "dhcpv6",
    "driver", "drt-debug", "event-to-cloud", "fw-session-to-cloud",
    "iap-bootup", "kernel", "l3-mobility", "loop-protect", "lte",
    "network", "openflow", "papi-handler", "pppd", "provision",
    "rapper", "rapper-brief", "rapper-counter", "rssi-to-cloud",
    "rtls-to-cloud", "sapd", "scd", "security", "state-to-cloud",
    "stats-to-cloud", "system", "uap", "ucm", "upgrade", "usb",
    "user", "user-debug", "vpn-brief", "vpn-tunnel", "vpn-tunnel-backup",
    "vpn-tunnel-primary", "wireless"
]


def parse_timestamp_from_log_line(line):
    """
    Extrahiert einen Zeitstempel (z. B. 'Sep 21 13:52:55') aus einer typischen Syslog-Zeile.
    """
    match = re.match(r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})", line.strip())
    if match:
        return match.group(1)
    return "N/A"


def query_ap_log(ap_ip, user, password, timeout, protocol, search_text, case_sensitive=False, is_regex=False):
    """
    Stellt eine SSH-Verbindung zu einem einzelnen AP her, führt 'show log <protocol>' aus
    und filtert die Zeilen nach dem Suchbegriff.
    Gibt (matching_lines, total_lines_count, error_str) zurück.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ap_ip, username=user, password=password, timeout=timeout)
        raw_output = execute_command_on_shell(client, f"show log {protocol}")
        
        matching_lines = []
        pattern = None
        if is_regex:
            flags = 0 if case_sensitive else re.IGNORECASE
            try:
                pattern = re.compile(search_text, flags)
            except re.error as re_err:
                return None, 0, f"Ungültiger regulärer Ausdruck: {re_err}"

        lines = raw_output.splitlines()
        total_valid_lines = 0

        for line in lines:
            line_str = line.strip()
            # Unnötige Leerzeilen, CLI-Prompts und Prompt-Echos überspringen
            if not line_str or line_str.endswith('#') or f"show log {protocol}" in line_str:
                continue
            if line_str.startswith("----") or line_str.lower().startswith("no paging"):
                continue

            total_valid_lines += 1
            is_match = False

            if is_regex and pattern:
                if pattern.search(line_str):
                    is_match = True
            else:
                if case_sensitive:
                    if search_text in line_str:
                        is_match = True
                else:
                    if search_text.lower() in line_str.lower():
                        is_match = True

            if is_match:
                matching_lines.append(line_str)

        return matching_lines, total_valid_lines, None

    except paramiko.AuthenticationException:
        return None, 0, "Authentifizierung fehlgeschlagen"
    except Exception as e:
        return None, 0, str(e)
    finally:
        try:
            client.close()
        except Exception:
            pass


def get_conductor_and_members(conductor_ip, user, password, timeout, check_member_aps):
    """
    Verbindet sich mit dem Conductor und ermittelt Conductor-Name sowie (falls check_member_aps=True)
    alle Member-APs aus 'show aps'.
    Gibt (conductor_name, ap_list, error_str) zurück.
    ap_list enthält Dicts: [{'ip': '...', 'name': '...', 'is_conductor': bool, 'role': 'Conductor'|'Member'}]
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    conductor_name = "N/A"
    ap_list = []

    try:
        client.connect(conductor_ip, username=user, password=password, timeout=timeout)

        # 1. Conductor-Name auslesen
        name_output = execute_command_on_shell(client, "show running-config | include ^name")
        if name_match := re.search(r"^name\s+(\S+)", name_output, re.MULTILINE):
            conductor_name = name_match.group(1)

        # Wenn keine Member-APs gewünscht sind, nur Conductor zurückgeben
        if not check_member_aps:
            ap_list.append({
                'ip': conductor_ip,
                'name': conductor_name,
                'is_conductor': True,
                'role': 'Conductor'
            })
            return conductor_name, ap_list, None

        # 2. Member-APs via 'show aps' ermitteln
        aps_output = execute_command_on_shell(client, "show aps")
        lines = aps_output.splitlines()

        header_found = False
        start_index = 0
        for i, line in enumerate(lines):
            if ("IP Address" in line or "IP" in line) and ("Serial #" in line or "Serial" in line):
                header_found = True
                start_index = i + 2
                break

        if not header_found:
            # Fallback: Falls Header nicht erkannt wurde, Conductor aufnehmen
            ap_list.append({
                'ip': conductor_ip,
                'name': conductor_name,
                'is_conductor': True,
                'role': 'Conductor'
            })
            return conductor_name, ap_list, "Warnung: 'show aps' Header nicht gefunden. Nur Conductor erfasst."

        ip_pattern = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})(\*?)")

        for line in lines[start_index:]:
            line_str = line.strip()
            if not line_str or line_str.startswith("----"):
                continue

            match = ip_pattern.search(line_str)
            if match:
                ap_ip = match.group(1)
                star = match.group(2) == '*'

                # AP-Name ist der Text vor der IP-Spalte
                ap_name = line_str[:match.start()].strip()
                if not ap_name:
                    ap_name = ap_ip

                rest_of_line = line_str[match.end():].lower()
                is_conductor = star or ('master' in rest_of_line) or (ap_ip == conductor_ip)
                role = "Conductor" if is_conductor else "Member"

                ap_list.append({
                    'ip': ap_ip,
                    'name': ap_name,
                    'is_conductor': is_conductor,
                    'role': role
                })

        # Sicherstellen, dass der abgefragte Conductor mindestens einmal in der Liste ist
        if not any(ap['ip'] == conductor_ip for ap in ap_list):
            ap_list.insert(0, {
                'ip': conductor_ip,
                'name': conductor_name,
                'is_conductor': True,
                'role': 'Conductor'
            })

        return conductor_name, ap_list, None

    except paramiko.AuthenticationException:
        return conductor_name, [], "Authentifizierung für Conductor fehlgeschlagen"
    except Exception as e:
        return conductor_name, [], f"Verbindung zu Conductor fehlgeschlagen: {e}"
    finally:
        try:
            client.close()
        except Exception:
            pass


def member_log_worker(task_queue, results_queue, credentials_store, timeout, protocol, search_text, case_sensitive, is_regex):
    """
    Thread-Worker zur parallelen SSH-Abfrage von Member-APs.
    """
    while True:
        item = task_queue.get()
        if item is None:
            break

        conductor_ip, conductor_name, ap_info = item
        ap_ip = ap_info['ip']

        # Anmeldedaten des Conductor-Swarms nutzen
        creds = credentials_store.get(conductor_ip, {})
        user = creds.get('user')
        password = creds.get('pass')

        matches, total_lines, err = query_ap_log(
            ap_ip, user, password, timeout,
            protocol, search_text, case_sensitive, is_regex
        )

        results_queue.put({
            'conductor_ip': conductor_ip,
            'conductor_name': conductor_name,
            'ap_ip': ap_ip,
            'ap_name': ap_info.get('name', ap_ip),
            'role': ap_info.get('role', 'Member'),
            'matches': matches,
            'total_lines': total_lines,
            'error': err
        })

        task_queue.task_done()


def is_ipv4(s):
    parts = s.strip().split('.')
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or not (0 <= int(p) <= 255):
            return False
    return True


def is_ip_or_ip_list(token):
    cleaned = token.strip()
    if not cleaned:
        return False
    items = cleaned.split(',')
    return all(is_ipv4(item) for item in items if item.strip())


# === Hauptskript ===
if __name__ == "__main__":
    check_dependencies()

    original_stdout = sys.stdout
    log_file_handler = None

    epilog_text = """
Beispiele:

  # 1. Einzelnen Conductor abfragen (Protokoll 'system' nach 'dhcp' durchsuchen):
  py ap_findlog.py 10.1.1.1 system "dhcp"

  # 2. Conductor UND alle zugehörigen Member-APs durchsuchen:
  py ap_findlog.py 10.1.1.1 system "dhcp" --memberaps

  # 3. Mehrere Conductors kommasepariert mit Member-APs prüfen und Log-Datei schreiben:
  py ap_findlog.py 10.1.1.1,10.2.2.2 system "dhcp" --memberaps --log

  # 4. Suche nach mehrteiligem Begriff mit Leerzeichen (in Anführungszeichen):
  py ap_findlog.py 10.1.1.1 system "found dhcp option" --memberaps

  # 5. Suche mit regulärem Ausdruck (Regex):
  py ap_findlog.py 10.1.1.1 system "option 6[67]" --regex --memberaps

  # 6. Exakte Groß-/Kleinschreibung (Case-Sensitive):
  py ap_findlog.py 10.1.1.1 security "Failed" --case-sensitive

  # 7. Conductors aus Bestandsdatei importieren (z. B. nur eine bestimmte Kommune):
  py ap_findlog.py --importfile knownconductors/conductors.csv system "dhcp" --filter-carrier "Beispielstadt" --memberaps --log

  # 8. Vollautomatische Ausführung mit Windows Credential Manager / PowerShell-Pipe:
  "1`nadmin" | py -X utf8 .\\ap_findlog.py 10.1.1.1 system "dhcp" --memberaps --log

  # 9. Gespeicherte Anmeldedaten für IPs löschen:
  py ap_findlog.py --delete-credentials 10.1.1.1
"""

    parser = argparse.ArgumentParser(
        description="Durchsucht System- und Diagnoseprotokolle von Aruba Instant APs gezielt nach Begriffen oder Mustern.",
        epilog=epilog_text,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    # Flexible Positionsargumente: fängt [targets...] <protocol> <search> ab
    parser.add_argument('pos_args', nargs='*', default=[], help="Positionsargumente: [Conductor-IP(s)] <Protokoll> <Suchtext>")
    parser.add_argument('--protocol', '-p', type=str, help=f"Name des Protokolls ({', '.join(VALID_PROTOCOLS[:8])}, ...)")
    parser.add_argument('--search', '-s', type=str, help="Suchbegriff oder Textmuster (z. B. \"dhcp\" oder \"found dhcp option\")")
    parser.add_argument('--targets', type=str, help="Optionale Conductor-IPs (kommasepariert)")
    parser.add_argument('--importfile', type=str, help="Pfad zu einer CSV-Datei (z. B. knownconductors/conductors.csv), aus der Conductor-IPs importiert werden.")
    parser.add_argument('--filter-carrier', type=str, help="Optionaler Filter bei Import: Nur Conductors dieser Kommune / dieses Trägers abfragen.")
    parser.add_argument('--filter-standort', type=str, help="Optionaler Filter bei Import: Nur Conductors mit diesem Standort-Präfix abfragen.")
    parser.add_argument('--memberaps', '-m', action='store_true', help="Aktiviert die Prüfung auf ALLEN Member-APs des jeweiligen Schwarms (nicht nur Conductor).")
    parser.add_argument('--threads', '-t', type=int, default=None, help="Anzahl paralleler Worker-Threads für Member-APs (Standard: 10 aus config.json, maximal 10).")
    parser.add_argument('--case-sensitive', '-c', action='store_true', help="Unterscheidet strikt zwischen Groß- und Kleinschreibung (Standard: case-insensitive).")
    parser.add_argument('--regex', action='store_true', help="Interpretiert den Suchtext als regulären Ausdruck (Python re-Syntax).")
    parser.add_argument('--max-preview', type=int, default=5, help="Maximale Anzahl an Trefferzeilen pro AP in der Konsolenvorschau (Standard: 5, 0 = alle).")
    parser.add_argument('--log', action='store_true', help="Aktiviert das Schreiben der Konsolenausgabe in eine Log-Datei im Ergebnisordner.")
    parser.add_argument('--delete-credentials', type=str, help="WERKZEUG: Löscht gespeicherte Anmeldedaten für die angegebenen IPs.")
    parser.add_argument('--delete-credentials-from-import', type=str, help="WERKZEUG: Löscht gespeicherte Anmeldedaten für alle IPs aus einer Importdatei.")

    args = parser.parse_args()

    # WERKZEUG: Gespeicherte Anmeldedaten löschen
    if args.delete_credentials or args.delete_credentials_from_import:
        ips_to_delete = []
        if args.delete_credentials:
            ips_to_delete.extend(args.delete_credentials.split(','))
        if args.delete_credentials_from_import:
            try:
                with open(args.delete_credentials_from_import, 'r', encoding='utf-8-sig') as f:
                    reader = csv.DictReader(f)
                    ip_col = 'ipadresse' if 'ipadresse' in reader.fieldnames else ('IP-Adresse' if 'IP-Adresse' in reader.fieldnames else 'ip')
                    for row in reader:
                        if ip := row.get(ip_col):
                            ips_to_delete.append(ip.strip())
            except Exception as e:
                print(f"FEHLER beim Lesen der Import-Datei: {e}")
                sys.exit(1)

        user_to_delete = None
        if KEYRING_AVAILABLE:
            user_to_delete = input("Für welchen Benutzernamen sollen die Anmeldedaten gelöscht werden?: ")

        print(f"\nLösche Anmeldedaten für {len(ips_to_delete)} IP(s)...")
        for ip in ips_to_delete:
            res = delete_credential_for_ip(ip, user_to_delete)
            if res:
                print(f"  - Daten für {ip} gelöscht aus: {', '.join(res)}")
            else:
                print(f"  - Keine gespeicherten Daten für {ip} gefunden.")
        print("Löschvorgang abgeschlossen.")
        sys.exit(0)

    # Intelligentes Parsen von Positionsparametern und Flags
    protocol = args.protocol.lower().strip() if args.protocol else None
    search_text = args.search.strip() if args.search else None
    targets = []

    if args.targets:
        targets.extend([ip.strip() for ip in args.targets.split(',') if ip.strip()])

    pos = list(args.pos_args)

    # 1. Alle IP-Adressen / IP-Listen aus den Positionsargumenten herausziehen
    remaining_pos = []
    for p in pos:
        if is_ip_or_ip_list(p):
            targets.extend([ip.strip() for ip in p.split(',') if ip.strip()])
        else:
            remaining_pos.append(p)

    # 2. Protokoll ermitteln (falls nicht bereits per Flag gesetzt)
    if not protocol:
        proto_indices = [i for i, token in enumerate(remaining_pos) if token.lower() in VALID_PROTOCOLS]
        if proto_indices:
            chosen_idx = proto_indices[0]
            protocol = remaining_pos[chosen_idx].lower()
            non_proto_tokens = [t for i, t in enumerate(remaining_pos) if i not in proto_indices]
            if non_proto_tokens:
                # Es gibt weitere Tokens, die als Suchtext dienen -> Protokoll-Duplikate verwerfen
                remaining_pos = non_proto_tokens
            else:
                remaining_pos.pop(chosen_idx)

    # 3. Suchtext ermitteln (falls nicht bereits per Flag gesetzt)
    if not search_text and remaining_pos:
        search_text = " ".join(remaining_pos)

    # Validierung: Protokoll
    if not protocol:
        print("\nFEHLER: Es wurde kein Protokollname angegeben!")
        print(f"Beispiel: py ap_findlog.py 10.1.1.1 system \"dhcp\"")
        print(f"\nGültige Protokollnamen:\n  {', '.join(VALID_PROTOCOLS)}")
        sys.exit(1)

    if protocol not in VALID_PROTOCOLS:
        print(f"\nFEHLER: '{protocol}' ist kein gültiger Aruba Instant Protokollname!")
        print(f"\nGültige Protokollnamen:\n  {', '.join(VALID_PROTOCOLS)}")
        sys.exit(1)

    # Validierung: Suchtext
    if not search_text:
        print("\nFEHLER: Es wurde kein Suchbegriff / Textmuster angegeben!")
        print(f"Beispiel: py ap_findlog.py 10.1.1.1 {protocol} \"dhcp\"")
        sys.exit(1)

    # Import aus Datei (z. B. conductors.csv)
    carrier_filter = args.filter_carrier.strip().lower() if args.filter_carrier else None
    standort_filter = args.filter_standort.strip().lower() if args.filter_standort else None

    if args.importfile:
        print(f"\nINFO: Importiere Conductor-Ziele aus Datei: {args.importfile}")
        try:
            with open(args.importfile, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                headers = reader.fieldnames or []
                ip_col = 'ipadresse' if 'ipadresse' in headers else ('IP-Adresse' if 'IP-Adresse' in headers else 'ip')
                carrier_col = 'kreisoderkommunenname' if 'kreisoderkommunenname' in headers else ('Träger' if 'Träger' in headers else None)
                standort_col = 'standort' if 'standort' in headers else ('Standort' if 'Standort' in headers else None)

                for row in reader:
                    ip = row.get(ip_col, '').strip()
                    if not ip:
                        continue

                    # Träger-Filter
                    if carrier_filter and carrier_col:
                        row_carrier = row.get(carrier_col, '').strip().lower()
                        if carrier_filter not in row_carrier:
                            continue

                    # Standort-Filter
                    if standort_filter and standort_col:
                        row_standort = row.get(standort_col, '').strip().lower()
                        if not row_standort.startswith(standort_filter):
                            continue

                    targets.append(ip)

            print(f"INFO: {len(targets)} Conductor(s) aus Datei importiert (nach Filter).")
        except FileNotFoundError:
            print(f"FEHLER: Import-Datei '{args.importfile}' nicht gefunden.")
            sys.exit(1)
        except Exception as e:
            print(f"FEHLER beim Verarbeiten der Import-Datei: {e}")
            sys.exit(1)

    # config.json laden
    try:
        with open("config.json", 'r', encoding='utf-8') as f:
            config = json.load(f)
    except FileNotFoundError:
        print("FEHLER: config.json nicht gefunden!")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"FEHLER: Die Datei config.json ist fehlerhaft: {e}")
        sys.exit(1)

    # Fallback auf config.json Conductor-IPs
    if not targets:
        targets = config.get('conductor_ips', [])

    if not targets:
        print("\nFEHLER: Keine Conductor-IPs angegeben (weder per CLI, Import noch in config.json).")
        parser.print_help()
        sys.exit(1)

    # Duplikate bei Targets eliminieren (Reihenfolge bewahren)
    unique_targets = []
    for ip in targets:
        if ip not in unique_targets:
            unique_targets.append(ip)
    targets = unique_targets

    # Thread-Limitierung
    config_threads = config.get('num_threads', 10)
    user_threads = args.threads if args.threads is not None else config_threads
    if user_threads > 10:
        print(f"WARNUNG: Angeforderte Thread-Anzahl ({user_threads}) übersteigt das Maximum von 10. Begrenze auf 10.")
        user_threads = 10
    elif user_threads < 1:
        user_threads = 1

    timeout = config.get('timeout_seconds', 30)

    # Ordner-Setup für Ergebnisse
    run_timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    output_dir = os.path.join(os.getcwd(), "ap_findlog_" + run_timestamp)
    os.makedirs(output_dir, exist_ok=True)

    summary_csv_path = os.path.join(output_dir, "ap_findlog_summary.csv")
    details_csv_path = os.path.join(output_dir, "ap_findlog_details.csv")

    if args.log:
        try:
            log_filename = os.path.join(output_dir, "ap_findlog_log.txt")
            log_file_handler = Logger(filename=log_filename)
            sys.stdout = log_file_handler
        except Exception as e:
            sys.stdout = original_stdout
            print(f"FEHLER: Log-Datei konnte nicht erstellt werden: {e}")

    print(f"ap_findlog.py Version {AP_FINDLOG_VERSION} wird ausgeführt...")
    print(f"Teil der Aruba Instant Toolsammlung Version {TOOLSUITE_VERSION}")
    print(f"Nutze aruba_helper.py Version {HELPER_VERSION}")
    print(f"INFO: Ergebnisse werden im Verzeichnis '{output_dir}' gespeichert.")

    start_time = datetime.now()
    print(f"\n===== Skriptstart: {start_time.strftime('%Y-%m-%d %H:%M:%S')} =====")
    print(f"Protokoll:        show log {protocol}")
    print(f"Suchtext:         '{search_text}'")
    print(f"Suchmodus:        {'Regex' if args.regex else 'Text'} ({'Case-Sensitive' if args.case_sensitive else 'Case-Insensitive'})")
    print(f"Member-AP-Scan:   {'AKTIVIERT' if args.memberaps else 'DEAKTIVIERT (nur Conductor)'}")
    print(f"Ziele:            {len(targets)} Conductor(s)")
    if args.memberaps:
        print(f"Worker-Threads:   {user_threads}")

    # Anmeldedaten-Konfiguration (vollständig kompatibel mit Keyring / Pipe)
    storage_choice = 'none'
    print("\n--- Konfiguration der Anmeldedaten ---")
    if KEYRING_AVAILABLE:
        prompt_text = (
            "Soll der Anmeldespeicher des Betriebssystems verwendet werden? (Empfohlen)\n"
            "[1] Ja\n"
            "[2] Nein, lokal mit PyCryptodome verschlüsselt speichern\n"
            "[3] Nein, bei jedem Start manuell eingeben\n"
            "-----------------------------------------------------------\n"
            "Dokumentation Keyring unter https://github.com/jaraco/keyring\n"
            "Dokumentation PyCryptodome unter https://www.pycryptodome.org/\n"
            "-----------------------------------------------------------\n"
            "Ihre Wahl: "
        )
        choice = input(prompt_text)
        if choice == '1':
            storage_choice = 'keyring'
        elif choice == '2':
            if CRYPTO_AVAILABLE:
                storage_choice = 'file'
            else:
                print("HINWEIS: 'pycryptodome' nicht installiert, Fallback auf manuelle Eingabe.")
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

    cfg = {'storage_method': storage_choice, 'timeout': timeout}

    credentials_store = {}
    targets_without_creds = list(targets)

    print("\n--- Pre-Flight Check: Prüfe gespeicherte Anmeldedaten ---")
    pre_check_user = None
    if cfg['storage_method'] == 'keyring':
        print("HINWEIS: Für die Prüfung mit dem Windows Credential Manager wird der Benutzername benötigt.")
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
                first_target = targets_without_creds[0]
                if validate_credentials(first_target, user, password, cfg['timeout']):
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
                        print(f"INFO: Anmeldedaten für {ip} erfolgreich validiert.")
                        if cfg['storage_method'] != 'none':
                            if input(f"Sollen diese Daten für {ip} gespeichert werden? (j/n): ").lower() == 'j':
                                save_credential(ip, user, password, cfg)
                        credentials_store[ip] = {'user': user, 'pass': password}
                        break
                    else:
                        if input("Erneut versuchen? (j/n): ").lower() != 'j':
                            sys.exit("Aktion abgebrochen.")

    # CSV-Writer initialisieren
    summary_fieldnames = [
        'Conductor-Name', 'Conductor-IP', 'AP-Name', 'AP-IP', 'Rolle',
        'Protokoll', 'Suchbegriff', 'Trefferanzahl', 'Geprüfte-Zeilen', 'Status'
    ]
    details_fieldnames = [
        'Conductor-Name', 'Conductor-IP', 'AP-Name', 'AP-IP', 'Rolle',
        'Protokoll', 'Suchbegriff', 'Timestamp', 'Logzeile'
    ]

    total_conductors_queried = 0
    total_aps_queried = 0
    total_matches_found = 0
    aps_with_matches = 0
    aps_without_matches = 0
    aps_with_errors = 0

    with open(summary_csv_path, 'w', newline='', encoding='utf-8') as f_summary, \
         open(details_csv_path, 'w', newline='', encoding='utf-8') as f_details:

        writer_summary = csv.DictWriter(f_summary, fieldnames=summary_fieldnames)
        writer_details = csv.DictWriter(f_details, fieldnames=details_fieldnames)
        writer_summary.writeheader()
        writer_details.writeheader()

        # Hauptschleife über alle Conductor-Ziele
        for idx, conductor_ip in enumerate(targets, 1):
            creds = credentials_store.get(conductor_ip)
            if not creds:
                with print_lock:
                    print(f"\n[{idx}/{len(targets)}] WARNUNG: Keine gültigen Anmeldedaten für {conductor_ip}. Überspringe...")
                continue

            user = creds['user']
            password = creds['pass']

            print(f"\n------------------------------------------------------------")
            print(f"[{idx}/{len(targets)}] Starte Analyse für Conductor: {conductor_ip}")

            # 1. Conductor & Member-APs erfassen
            conductor_name, ap_list, err = get_conductor_and_members(
                conductor_ip, user, password, timeout, args.memberaps
            )

            if err and not ap_list:
                with print_lock:
                    print(f"FEHLER bei Conductor {conductor_ip}: {err}")
                writer_summary.writerow({
                    'Conductor-Name': conductor_name,
                    'Conductor-IP': conductor_ip,
                    'AP-Name': conductor_name,
                    'AP-IP': conductor_ip,
                    'Rolle': 'Conductor',
                    'Protokoll': protocol,
                    'Suchbegriff': search_text,
                    'Trefferanzahl': 0,
                    'Geprüfte-Zeilen': 0,
                    'Status': f"Fehler: {err}"
                })
                aps_with_errors += 1
                total_conductors_queried += 1
                continue

            total_conductors_queried += 1
            print(f"INFO: Conductor-Name: '{conductor_name}', Gefundene APs im Schwarm: {len(ap_list)}")

            # Conductor selbst und Member-APs trennen
            conductor_ap = next((ap for ap in ap_list if ap['is_conductor'] or ap['ip'] == conductor_ip), None)
            member_aps = [ap for ap in ap_list if ap != conductor_ap and ap['ip'] != conductor_ip]

            # 2. Conductor direkt prüfen
            if conductor_ap:
                cond_ip = conductor_ap['ip']
                cond_name = conductor_ap.get('name', conductor_name)
                print(f"INFO: Frage Log von Conductor {cond_name} ({cond_ip}) ab...")

                matches, total_lines, log_err = query_ap_log(
                    cond_ip, user, password, timeout,
                    protocol, search_text, args.case_sensitive, args.regex
                )

                total_aps_queried += 1
                if log_err:
                    print(f"  [CONDUCTOR] {cond_name} ({cond_ip}): FEHLER ({log_err})")
                    writer_summary.writerow({
                        'Conductor-Name': conductor_name,
                        'Conductor-IP': conductor_ip,
                        'AP-Name': cond_name,
                        'AP-IP': cond_ip,
                        'Rolle': 'Conductor',
                        'Protokoll': protocol,
                        'Suchbegriff': search_text,
                        'Trefferanzahl': 0,
                        'Geprüfte-Zeilen': 0,
                        'Status': f"Fehler: {log_err}"
                    })
                    aps_with_errors += 1
                else:
                    match_count = len(matches)
                    total_matches_found += match_count
                    if match_count > 0:
                        aps_with_matches += 1
                        print(f"  [CONDUCTOR] {cond_name} ({cond_ip}): {match_count} Treffer gefunden (aus {total_lines} Logzeilen)")
                        preview_count = match_count if args.max_preview == 0 else min(match_count, args.max_preview)
                        for m_line in matches[:preview_count]:
                            print(f"    > {m_line}")
                        if match_count > preview_count:
                            print(f"    ... [{match_count - preview_count} weitere Treffer in ap_findlog_details.csv]")

                        for m_line in matches:
                            writer_details.writerow({
                                'Conductor-Name': conductor_name,
                                'Conductor-IP': conductor_ip,
                                'AP-Name': cond_name,
                                'AP-IP': cond_ip,
                                'Rolle': 'Conductor',
                                'Protokoll': protocol,
                                'Suchbegriff': search_text,
                                'Timestamp': parse_timestamp_from_log_line(m_line),
                                'Logzeile': m_line
                            })
                    else:
                        aps_without_matches += 1
                        print(f"  [CONDUCTOR] {cond_name} ({cond_ip}): Keine Treffer (aus {total_lines} Logzeilen)")

                    writer_summary.writerow({
                        'Conductor-Name': conductor_name,
                        'Conductor-IP': conductor_ip,
                        'AP-Name': cond_name,
                        'AP-IP': cond_ip,
                        'Rolle': 'Conductor',
                        'Protokoll': protocol,
                        'Suchbegriff': search_text,
                        'Trefferanzahl': match_count,
                        'Geprüfte-Zeilen': total_lines,
                        'Status': 'OK' if match_count > 0 else 'Keine Treffer'
                    })

            # 3. Member-APs parallel prüfen (falls --memberaps aktiv)
            if args.memberaps and member_aps:
                print(f"INFO: Starte parallele Prüfung von {len(member_aps)} Member-AP(s) mit {user_threads} Threads...")

                task_queue = Queue()
                results_queue = Queue()

                # Queue befüllen
                for m_ap in member_aps:
                    task_queue.put((conductor_ip, conductor_name, m_ap))

                # Threads starten
                threads = []
                actual_threads = min(len(member_aps), user_threads)
                for _ in range(actual_threads):
                    t = threading.Thread(
                        target=member_log_worker,
                        args=(task_queue, results_queue, credentials_store, timeout,
                              protocol, search_text, args.case_sensitive, args.regex),
                        daemon=True
                    )
                    t.start()
                    threads.append(t)

                # Queue abarbeiten
                task_queue.join()

                # Stop-Signale an Threads senden
                for _ in range(actual_threads):
                    task_queue.put(None)
                for t in threads:
                    t.join()

                # Ergebnisse der Member-APs auslesen und protokollieren
                while not results_queue.empty():
                    res = results_queue.get()
                    total_aps_queried += 1
                    m_ip = res['ap_ip']
                    m_name = res['ap_name']
                    m_role = res['role']
                    m_err = res['error']
                    m_matches = res['matches']
                    m_tot_lines = res['total_lines']

                    if m_err:
                        print(f"  [MEMBER-AP] {m_name} ({m_ip}): FEHLER ({m_err})")
                        writer_summary.writerow({
                            'Conductor-Name': conductor_name,
                            'Conductor-IP': conductor_ip,
                            'AP-Name': m_name,
                            'AP-IP': m_ip,
                            'Rolle': m_role,
                            'Protokoll': protocol,
                            'Suchbegriff': search_text,
                            'Trefferanzahl': 0,
                            'Geprüfte-Zeilen': 0,
                            'Status': f"Fehler: {m_err}"
                        })
                        aps_with_errors += 1
                    else:
                        match_count = len(m_matches)
                        total_matches_found += match_count
                        if match_count > 0:
                            aps_with_matches += 1
                            print(f"  [MEMBER-AP] {m_name} ({m_ip}): {match_count} Treffer gefunden (aus {m_tot_lines} Logzeilen)")
                            preview_count = match_count if args.max_preview == 0 else min(match_count, args.max_preview)
                            for m_line in m_matches[:preview_count]:
                                print(f"    > {m_line}")
                            if match_count > preview_count:
                                print(f"    ... [{match_count - preview_count} weitere Treffer in ap_findlog_details.csv]")

                            for m_line in m_matches:
                                writer_details.writerow({
                                    'Conductor-Name': conductor_name,
                                    'Conductor-IP': conductor_ip,
                                    'AP-Name': m_name,
                                    'AP-IP': m_ip,
                                    'Rolle': m_role,
                                    'Protokoll': protocol,
                                    'Suchbegriff': search_text,
                                    'Timestamp': parse_timestamp_from_log_line(m_line),
                                    'Logzeile': m_line
                                })
                        else:
                            aps_without_matches += 1
                            print(f"  [MEMBER-AP] {m_name} ({m_ip}): Keine Treffer (aus {m_tot_lines} Logzeilen)")

                        writer_summary.writerow({
                            'Conductor-Name': conductor_name,
                            'Conductor-IP': conductor_ip,
                            'AP-Name': m_name,
                            'AP-IP': m_ip,
                            'Rolle': m_role,
                            'Protokoll': protocol,
                            'Suchbegriff': search_text,
                            'Trefferanzahl': match_count,
                            'Geprüfte-Zeilen': m_tot_lines,
                            'Status': 'OK' if match_count > 0 else 'Keine Treffer'
                        })

    # Gesamtergebnis & Statistik
    end_time = datetime.now()
    duration = end_time - start_time

    print("\n" + "=" * 60)
    print(f"===== ZUSAMMENFASSUNG LOG-ANALYSE ({end_time.strftime('%Y-%m-%d %H:%M:%S')}) =====")
    print(f"Dauer:                               {duration}")
    print(f"Geprüfte Conductors / Swarms:        {total_conductors_queried}")
    print(f"Geprüfte Access Points gesamt:       {total_aps_queried}")
    print(f"APs mit Treffern:                    {aps_with_matches}")
    print(f"APs ohne Treffer:                    {aps_without_matches}")
    print(f"APs mit Verbindungs-/Prüffehler:     {aps_with_errors}")
    print(f"Gesamtzahl gefundener Log-Zeilen:    {total_matches_found}")
    print("-" * 60)
    print(f"Ergebnis-Übersicht (CSV):            {summary_csv_path}")
    print(f"Detail-Zeilen mit Timestamps (CSV):  {details_csv_path}")
    if args.log:
        print(f"Konsolen-Logdatei:                   {os.path.join(output_dir, 'ap_findlog_log.txt')}")
    print("=" * 60 + "\n")

    if log_file_handler:
        sys.stdout = original_stdout
        log_file_handler.close()
