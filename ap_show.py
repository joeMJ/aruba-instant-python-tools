### Aruba Instant Python Tools
### ap_show.py - Universelles CLI-Diagnosetool für Aruba Instant Conductors und Member-APs
### Version 1.1.0
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
    delete_credential_for_ip, get_conductor_data,
    KEYRING_AVAILABLE, CRYPTO_AVAILABLE
)

TOOLSUITE_VERSION = "2.0.0"

AP_SHOW_VERSION = "1.1.0"
print_lock = threading.Lock()

# Unzulässige, potenziell modifizierende oder gefährliche Schlüsselwörter
DISALLOWED_COMMANDS = {
    "clear", "reload", "reboot", "halt", "conf", "configure",
    "write", "commit", "process", "service", "delete", "erase",
    "factory-reset", "kill"
}


def normalize_show_command(raw_cmd):
    """
    Stellt sicher, dass ein Befehl unveränderlich ein 'show'-Befehl ist.
    Entfernt ein eventuell bereits vorangestelltes 'show', bereinigt gefährliche
    Steuerzeichen/Zeilenumbrüche, prüft gegen unzulässige Kommandos und stellt fest 'show ' voran.
    """
    cmd = raw_cmd.strip()
    # Entferne Zeilenumbrüche oder Semikolons (Schutz gegen Command-Chaining)
    if re.search(r'[\r\n;]', cmd):
        raise ValueError("Befehlsverkettungen mit Zeilenumbrüchen oder Semikolons sind aus Sicherheitsgründen nicht gestattet.")

    # Falls ein Benutzer aus Gewohnheit 'show ' eingegeben hat, schneide es ab
    cmd_sub = re.sub(r'^\s*show\s*', '', cmd, flags=re.IGNORECASE).strip()

    if not cmd_sub:
        return "show"

    first_word = cmd_sub.split()[0].lower()
    if first_word in DISALLOWED_COMMANDS:
        raise ValueError(f"Der Befehl '{first_word}' ist ein schreibender/modifizierender Befehl und in ap_show.py strengstens untersagt!")

    return f"show {cmd_sub}"


def sanitize_filename(name):
    """
    Erzeugt einen sicheren Dateinamen aus Hostnamen oder CLI-Befehlen.
    """
    clean = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', name.strip())
    clean = re.sub(r'_+', '_', clean)
    return clean[:80].strip('_')


def execute_cli_command(client, command, timeout=60):
    """
    Führt einen CLI-Befehl über eine interaktive Paramiko-Shell aus.
    Setzt 'no paging', wartet auf die vollständige Befehlsausführung bis zum Prompt (#)
    und gibt (bereinigte_ausgabe, erkannter_hostname) zurück.
    """
    # Sicherheitsprüfung: ap_show.py darf ausschließlich 'show'-Befehle ausführen
    normalized_cmd = command.strip()
    if not (normalized_cmd.startswith("show ") or normalized_cmd == "show"):
        raise ValueError(f"Sicherheitsverletzung: ap_show.py darf ausschließlich 'show'-Befehle ausführen! Befehl abgelehnt: {command}")

    channel = client.invoke_shell()
    channel.settimeout(timeout)

    detected_host = None

    # 1. Puffer bis zum initialen Hostname-Prompt leeren & Hostname erfassen
    initial_buffer = ""
    start_wait = time.time()
    while time.time() - start_wait < 10:
        time.sleep(0.2)
        if channel.recv_ready():
            initial_buffer += channel.recv(65535).decode('utf-8', errors='ignore')
            if initial_buffer.strip().endswith('#'):
                lines = initial_buffer.strip().splitlines()
                if lines:
                    last_line = lines[-1].strip()
                    if '#' in last_line:
                        detected_host = last_line.split('#')[0].strip()
                break

    # 2. 'no paging' senden, um interaktive Pausen zu verhindern
    channel.send("no paging\n")
    time.sleep(0.3)
    paging_buffer = ""
    start_paging = time.time()
    while time.time() - start_paging < 5:
        time.sleep(0.2)
        if channel.recv_ready():
            paging_buffer += channel.recv(65535).decode('utf-8', errors='ignore')
            if paging_buffer.strip().endswith('#'):
                break

    # 3. Den eigentlichen Befehl senden
    channel.send(command.strip() + "\n")

    # 4. Ausgabe einlesen, bis der CLI-Prompt (#) am Zeilenende wiederkehrt
    output = ""
    stall_count = 0
    # Bei großen Ausgaben (wie AirGroup Cache oder Tech-Support) kontinuierlich streamen
    while True:
        time.sleep(0.3)
        if channel.recv_ready():
            chunk = channel.recv(65535).decode('utf-8', errors='ignore')
            output += chunk
            stall_count = 0
            # Prüfen, ob der Prompt am Ende steht (Prompt = Zeile endet auf '#')
            lines = output.splitlines()
            if lines:
                last_line = lines[-1].strip()
                if last_line.endswith('#') and len(lines) > 1:
                    break
        else:
            stall_count += 1
            # Wenn 10 Schleifendurchläufe (~3s) keine Daten kamen und Output vorhanden ist
            if stall_count >= 10 and output:
                lines = output.splitlines()
                if lines and lines[-1].strip().endswith('#'):
                    break
            # Maximales Timeout bei anhaltendem Schweigen
            if stall_count > int(timeout / 0.3):
                break

    channel.close()

    # 5. Echos und Prompts bereinigen
    lines = output.splitlines()
    cleaned = []
    for line in lines:
        stripped = line.strip()
        # Prompt-Zeilen am Ende oder Befehlsecho am Anfang überspringen
        if stripped == command.strip() or stripped.endswith('#'):
            continue
        cleaned.append(line)

    return "\n".join(cleaned).strip(), detected_host


def query_single_target(ip, name, role, commands, user, password, timeout, output_dir, log_enabled):
    """
    Verbindet sich per SSH mit einer Ziel-IP, führt alle übergebenen Befehle aus
    und gibt die Ausgaben auf der Konsole und optional in Dateien aus.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    results = {}

    try:
        client.connect(ip, username=user, password=password, timeout=timeout)
    except Exception as e:
        err_msg = f"FEHLER: Verbindung zu {name} ({ip}) fehlgeschlagen: {e}"
        with print_lock:
            print(f"\n[{role}] {name} ({ip}) -> {err_msg}")
        return {ip: {"error": str(e)}}

    actual_name = name
    try:
        for cmd in commands:
            cmd_output, detected_host = execute_cli_command(client, cmd, timeout=timeout)
            if detected_host and (actual_name == ip or actual_name == "N/A"):
                actual_name = detected_host

            with print_lock:
                print(f"\n{'=' * 80}")
                print(f"Ziel:        {actual_name} ({ip}) [{role}]")
                print(f"Befehl:      {cmd}")
                print(f"Zeitstempel: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"{'=' * 80}")

            results[cmd] = cmd_output

            with print_lock:
                if cmd_output:
                    print(cmd_output)
                else:
                    print("(Keine Ausgabe / leerer Rückgabewert)")
                print(f"{'-' * 80}")

            # Optional: Speichern in Datei
            if output_dir:
                cmd_slug = sanitize_filename(cmd)
                target_slug = sanitize_filename(f"{actual_name}_{ip}")
                file_path = os.path.join(output_dir, f"{target_slug}_{cmd_slug}.txt")
                try:
                    with open(file_path, "w", encoding="utf-8") as f_out:
                        f_out.write(f"Ziel: {actual_name} ({ip}) [{role}]\n")
                        f_out.write(f"Befehl: {cmd}\n")
                        f_out.write(f"Zeitstempel: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                        f_out.write(cmd_output + "\n")
                except Exception as save_err:
                    with print_lock:
                        print(f"WARNUNG: Ausgabe konnte nicht in Datei '{file_path}' gespeichert werden: {save_err}")
    finally:
        client.close()

    return results


def member_worker(task_queue, results_queue, commands, credentials_store, timeout, output_dir, log_enabled):
    """
    Worker-Thread zur parallelen Ausführung von CLI-Befehlen auf Member-APs.
    """
    while True:
        item = task_queue.get()
        if item is None:
            task_queue.task_done()
            break

        cond_ip, member_info = item
        m_ip = member_info.get('ip')
        m_name = member_info.get('name', m_ip)

        creds = credentials_store.get(cond_ip)
        if not creds:
            task_queue.task_done()
            continue

        res = query_single_target(
            m_ip, m_name, "Member-AP", commands,
            creds['user'], creds['pass'], timeout,
            output_dir, log_enabled
        )
        results_queue.put((m_ip, res))
        task_queue.task_done()


def main():
    original_stdout = sys.stdout
    check_dependencies()

    parser = argparse.ArgumentParser(
        description="ap_show.py - Universelles CLI-Diagnosetool für Aruba Instant Conductors und Member-APs."
    )
    parser.add_argument("targets", nargs="*", help="Eine oder mehrere Conductor-/AP-IP-Adressen")
    parser.add_argument("-c", "--cmd", dest="commands", action="append", help="Ein auszuführender Show-Befehl (z. B. -c 'version' oder -c 'airgroup cache entries'). Das Präfix 'show' ist fest verdrahtet. Mehrfachangabe möglich.")
    parser.add_argument("--cmd-file", help="Pfad zu einer Textdatei mit Show-Befehlen (ein Befehl pro Zeile, ohne führendes 'show')")
    parser.add_argument("-m", "--memberaps", action="store_true", help="Führt den/die Befehl(e) auch auf allen aktiven Member-APs des Schwarms aus")
    parser.add_argument("-i", "--importfile", help="Pfad zu einer Bestandsdatei (CSV, z. B. conductors.csv)")
    parser.add_argument("--filter-carrier", help="Filtert nach Kreis/Kommune beim Import aus CSV")
    parser.add_argument("--filter-standort", help="Filtert nach Standort beim Import aus CSV")
    parser.add_argument("--vc", "--conductor", dest="vc_ip", help="Conductor-IP, deren Anmeldedaten aus dem Speicher für die Ziel-IP(s) übernommen werden sollen")
    parser.add_argument("-t", "--threads", type=int, help="Anzahl paralleler Threads für Member-APs (Standard: 10, Max: 10)")
    parser.add_argument("--log", action="store_true", help="Aktiviert vollständiges Logging in Textdateien")
    parser.add_argument("--output-dir", help="Benutzerdefiniertes Ausgabeverzeichnis")

    args = parser.parse_args()

    # Befehle sammeln
    raw_commands = []
    if args.commands:
        raw_commands.extend([c.strip() for c in args.commands if c.strip()])

    if args.cmd_file:
        try:
            with open(args.cmd_file, "r", encoding="utf-8") as f_cmd:
                for line in f_cmd:
                    line_clean = line.strip()
                    if line_clean and not line_clean.startswith("#"):
                        raw_commands.append(line_clean)
        except Exception as e:
            print(f"FEHLER beim Lesen der Befehlsdatei '{args.cmd_file}': {e}")
            sys.exit(1)

    # Interaktive Befehlseingabe, falls keine Befehle übergeben wurden
    if not raw_commands:
        print("\nHINWEIS: Es wurde kein Show-Befehl via -c / --cmd oder --cmd-file angegeben.")
        try:
            interactive_cmd = input("Bitte gewünschten Show-Befehl eingeben (z. B. version oder airgroup cache entries): ").strip()
        except (KeyboardInterrupt, EOFError):
            sys.exit("\nAbbruch durch Benutzer.")
        if not interactive_cmd:
            print("FEHLER: Kein Befehl eingegeben. Abbruch.")
            sys.exit(1)
        raw_commands.append(interactive_cmd)

    # Sicherheitsvalidierung und feste Voranstellung von 'show '
    commands = []
    for rc in raw_commands:
        try:
            normalized = normalize_show_command(rc)
            commands.append(normalized)
        except ValueError as ve:
            print(f"\nSICHERHEITS-ABBRUCH: {ve}")
            sys.exit(1)

    # Ziel-IPs ermitteln
    targets = list(args.targets) if args.targets else []

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

                    if carrier_filter and carrier_col:
                        row_carrier = row.get(carrier_col, '').strip().lower()
                        if carrier_filter not in row_carrier:
                            continue

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
        config = {"timeout_seconds": 30, "num_threads": 10}
    except json.JSONDecodeError as e:
        print(f"FEHLER: Die Datei config.json ist fehlerhaft: {e}")
        sys.exit(1)

    if not targets:
        targets = config.get('conductor_ips', [])

    if not targets:
        print("\nFEHLER: Keine Ziel-IPs angegeben (weder per Argument, Import noch in config.json).")
        parser.print_help()
        sys.exit(1)

    # Duplikate eliminieren
    unique_targets = []
    for ip in targets:
        if ip not in unique_targets:
            unique_targets.append(ip)
    targets = unique_targets

    # Thread-Limitierung
    config_threads = config.get('num_threads', 10)
    user_threads = args.threads if args.threads is not None else config_threads
    if user_threads > 10:
        print(f"WARNUNG: Angeforderte Thread-Anzahl ({user_threads}) übersteigt Maximum von 10. Begrenze auf 10.")
        user_threads = 10
    elif user_threads < 1:
        user_threads = 1

    timeout = config.get('timeout_seconds', 30)

    # Ausgabeverzeichnis vorbereiten
    run_timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    output_dir = args.output_dir if args.output_dir else os.path.join(os.getcwd(), "ap_show_" + run_timestamp)
    if args.log or args.output_dir:
        os.makedirs(output_dir, exist_ok=True)
    else:
        output_dir = None

    if args.log and output_dir:
        try:
            log_filename = os.path.join(output_dir, "ap_show_session.log")
            log_file_handler = Logger(filename=log_filename)
            sys.stdout = log_file_handler
        except Exception as e:
            sys.stdout = original_stdout
            print(f"FEHLER: Log-Datei konnte nicht erstellt werden: {e}")

    print(f"ap_show.py Version {AP_SHOW_VERSION} wird ausgeführt...")
    print(f"Teil der Aruba Instant Toolsammlung Version {TOOLSUITE_VERSION}")
    print(f"Nutze aruba_helper.py Version {HELPER_VERSION}")
    print(f"Befehl(e):        {', '.join([repr(c) for c in commands])}")
    print(f"Ziele:            {len(targets)} Conductor(s)")
    print(f"Member-AP-Scan:   {'AKTIVIERT' if args.memberaps else 'DEAKTIVIERT (nur Conductor)'}")
    if output_dir:
        print(f"Ausgabeverzeichnis: {output_dir}")

    # Anmeldedaten-Konfiguration (Windows Credential Manager / Keyring / Pipe-kompatibel)
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

    # Falls --vc angegeben wurde: Lade Anmeldedaten des Conductors und weise sie den Zielen zu
    if args.vc_ip:
        vc_user, vc_password = get_saved_credentials(args.vc_ip, cfg, pre_check_user)
        if vc_user and vc_password:
            print(f"INFO: Anmeldedaten von Conductor {args.vc_ip} aus dem Speicher geladen und für {len(targets_without_creds)} Ziel(e) übernommen.")
            for ip in list(targets_without_creds):
                credentials_store[ip] = {'user': vc_user, 'pass': vc_password}
                found_creds_ips.append(ip)
            targets_without_creds = [ip for ip in targets_without_creds if ip not in found_creds_ips]
        else:
            print(f"WARNUNG: Keine gespeicherten Anmeldedaten für Conductor {args.vc_ip} gefunden.")

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

    start_time = datetime.now()
    print(f"\n===== Starte CLI-Ausführung: {start_time.strftime('%Y-%m-%d %H:%M:%S')} =====")

    # Hauptschleife über alle Conductor-Ziele
    for idx, conductor_ip in enumerate(targets, 1):
        creds = credentials_store.get(conductor_ip)
        if not creds:
            print(f"\n[{idx}/{len(targets)}] WARNUNG: Keine gültigen Anmeldedaten für {conductor_ip}. Überspringe...")
            continue

        user = creds['user']
        password = creds['pass']

        print(f"\n--- [{idx}/{len(targets)}] Verbinde mit Conductor {conductor_ip} ---")

        # 1. Befehl auf Conductor ausführen
        query_single_target(
            conductor_ip, conductor_ip, "Conductor", commands,
            user, password, timeout, output_dir, args.log
        )

        # 2. Member-APs abarbeiten (falls --memberaps aktiv)
        if args.memberaps:
            ap_data, provisioned_macs, cond_name, required_vlans, cond_err = get_conductor_data(
                conductor_ip, user, password, timeout, config.get('language_terms', {})
            )
            if cond_err != "success" or not ap_data:
                print(f"WARNUNG: Member-APs konnten für {conductor_ip} nicht ermittelt werden (Status: {cond_err})")
            else:
                member_aps = [{'ip': ap_ip, 'name': ap_ip} for ap_ip in ap_data.keys() if ap_ip != conductor_ip]
                if member_aps:
                    print(f"\nINFO: Starte parallele Prüfung von {len(member_aps)} Member-AP(s) mit {user_threads} Threads...")
                    task_queue = Queue()
                    results_queue = Queue()

                    for m_ap in member_aps:
                        task_queue.put((conductor_ip, m_ap))

                    threads = []
                    actual_threads = min(len(member_aps), user_threads)
                    for _ in range(actual_threads):
                        t = threading.Thread(
                            target=member_worker,
                            args=(task_queue, results_queue, commands, credentials_store,
                                  timeout, output_dir, args.log),
                            daemon=True
                        )
                        t.start()
                        threads.append(t)

                    task_queue.join()

                    for _ in range(actual_threads):
                        task_queue.put(None)
                    for t in threads:
                        t.join()

    end_time = datetime.now()
    duration = end_time - start_time
    print(f"\n===== Ausführung beendet: {end_time.strftime('%Y-%m-%d %H:%M:%S')} (Dauer: {duration}) =====")
    if output_dir:
        print(f"Ergebnisse gespeichert in: {output_dir}")

    sys.stdout = original_stdout


if __name__ == "__main__":
    main()
