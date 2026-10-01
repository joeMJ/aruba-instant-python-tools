### ap_swarm_update.py - Tool für das Firmware-Update von Schwärmen via CLI
### Version 4.1.0 - Robuste Namensfindung für Logs
### Bestandteil der Aruba Instant Python Tools Suite V 2.0.0
### gemacht mit viel Liebe von John (johnlose.de)

# Importiere notwendige Bibliotheken
import paramiko
import sys
import time
import json
import os
import argparse
import re
import csv
import requests
import threading
from queue import Queue
from bs4 import BeautifulSoup
from urllib3.exceptions import InsecureRequestWarning
from datetime import datetime

# Importiere die Helper-Funktionen
from aruba_helper import (
    SCRIPT_VERSION, check_dependencies, Logger, get_saved_credentials,
    validate_credentials, get_credentials_interactively, save_credential,
    execute_command_on_shell, KEYRING_AVAILABLE, CRYPTO_AVAILABLE
)

TOOLSUITE_VERSION = "2.0.0"

# Deaktiviere Warnungen für selbstsignierte Zertifikate
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


def get_input_and_log(prompt, logger):
    """Wrapper für input(), um sicherzustellen, dass die Antwort des Benutzers geloggt wird."""
    print() # Sorgt für sauberen Zeilenumbruch im Log
    response = input(prompt)
    logger.write(f"Benutzereingabe auf '{prompt.strip()}': '{response}'\n")
    return response

def check_current_version(client, firmware_url, cluster_statuses, conductor_ip, logger):
    """
    Prüft die aktuell installierte Version gegen die Ziel-Version.
    """
    cluster_statuses[conductor_ip] = "Phase 1: Prüfe Version..."
    
    target_version_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", firmware_url)
    if not target_version_match: return True
    target_version = target_version_match.group(1)
    
    output = execute_command_on_shell(client, "show version")
    current_version_match = re.search(r"Version\s+([\d\.\w\s]+(LSR)?)", output) # LSR optional
    if not current_version_match: return True
    current_version = current_version_match.group(1).strip()
    
    logger.write(f"INFO: Ziel-Version: {target_version} | Installierte Version: {current_version}\n")
    if target_version in current_version:
        logger.write(f"HINWEIS: Ziel-Firmware ({target_version}) ist bereits installiert.\n")
        cluster_statuses[conductor_ip] = "Übersprungen (Version aktuell)"
        return False
    
    return True

def get_ap_classes_from_conductor(client, cluster_statuses, conductor_ip, logger):
    """
    Führt 'show upgrade info' aus und extrahiert die AP-Klassen der Member.
    """
    cluster_statuses[conductor_ip] = "Phase 1: Frage AP-Klassen ab..."
    output = execute_command_on_shell(client, "show upgrade info")
    
    if "Upgrade in process: Yes" in output:
        logger.write(f"FEHLER: Auf dem Conductor läuft bereits ein Upgrade-Prozess.\n")
        cluster_statuses[conductor_ip] = "FEHLER: Upgrade läuft bereits."
        return None, 0
        
    regex = r"^([\da-fA-F:]{17})\s+[\d\.]+\s+\w+\s+(\w+)\s+.*\s+(\S+)$"
    ap_classes, ap_count = set(), 0
    for line in output.splitlines():
        if match := re.search(regex, line):
            ap_count += 1
            ap_classes.add(match.group(2))
            if match.group(3).lower() != 'none':
                error_msg = f"FEHLER: AP {match.group(1)} meldet Vorab-Fehler: {match.group(3)}."
                logger.write(f"{error_msg}\n")
                cluster_statuses[conductor_ip] = error_msg
                return None, 0
            
    if not ap_classes:
        logger.write(f"FEHLER: Konnte keine AP-Klassen ermitteln.\n")
        cluster_statuses[conductor_ip] = "FEHLER: Konnte keine AP-Klassen ermitteln."
        return None, 0
        
    return sorted(list(ap_classes)), ap_count

def get_firmware_urls_from_web(firmware_url, needed_classes, cluster_statuses, conductor_ip, logger):
    """
    Liest eine Apache-Indexseite aus und mappt die Firmware-Dateien zu den AP-Klassen.
    """
    cluster_statuses[conductor_ip] = "Phase 2: Firmware-Analyse..."
    firmware_map = {}
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        response = requests.get(firmware_url, headers=headers, timeout=20, verify=False)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        for ap_class in needed_classes:
            if link := soup.find('a', href=True, string=re.compile(f"_{ap_class}_", re.IGNORECASE)):
                firmware_map[ap_class] = requests.compat.urljoin(firmware_url, link['href'])
            else:
                error_msg = f"FEHLER: Keine Firmware für Klasse '{ap_class}' gefunden."
                logger.write(f"{error_msg}\n")
                cluster_statuses[conductor_ip] = error_msg
                return None
                
        if len(firmware_map) != len(needed_classes):
            logger.write(f"FEHLER: Konnte nicht für alle Klassen Firmware finden.\n")
            cluster_statuses[conductor_ip] = "FEHLER: Konnte nicht für alle Klassen Firmware finden."
            return None
            
        return firmware_map
    except requests.exceptions.RequestException as e:
        error_msg = f"FEHLER: Download der Firmware-Liste ({e})."
        logger.write(f"{error_msg}\n")
        cluster_statuses[conductor_ip] = error_msg
        return None

def execute_cli_upgrade(client, firmware_map, cluster_statuses, conductor_ip, logger):
    """
    Baut den korrekten Upgrade-Befehl basierend auf der Anzahl der AP-Klassen.
    """
    cluster_statuses[conductor_ip] = "Phase 3: Starte CLI-Upgrade..."
    
    if len(firmware_map) == 1:
        single_url = list(firmware_map.values())[0]
        command = f"upgrade-image2-no-reboot {single_url}"
        logger.write(f"INFO: Homogener Schwarm erkannt. Verwende Befehl: upgrade-image2-no-reboot <URL>\n")
    else:
        upgrade_parts = [f"{ap_class}@{url}" for ap_class, url in firmware_map.items()]
        command = f"upgrade-image2-no-reboot {';'.join(upgrade_parts)}"
        logger.write(f"INFO: Heterogener Schwarm erkannt. Verwende Befehl: upgrade-image2-no-reboot <Klasse@URL;...>\n")

    logger.write(f"DEBUG: Sende folgenden Befehl an den Conductor:\n---\n{command}\n---\n")
    output = execute_command_on_shell(client, command)
    logger.write(f"DEBUG: Rohe Antwort vom Conductor erhalten:\n---\n{output}\n---\n")
    
    if "Upgrade is triggered" in output:
        logger.write(f"SUCCESS: Upgrade-Prozess erfolgreich gestartet.\n")
        return True
    else:
        clean_output = ' '.join(output.replace("\r\n", " ").split())
        logger.write(f"FEHLER: Upgrade-Befehl wurde abgewiesen. Antwort: {clean_output}\n")
        cluster_statuses[conductor_ip] = f"FEHLER: CLI-Befehl abgewiesen ({clean_output})"
        return False

def monitor_upgrade_process(client, total_ap_count, monitor_timeout, updatewait, cluster_statuses, conductor_ip, logger):
    """Überwacht den Fortschritt des Upgrades in einer Schleife mit Fehler- und Stillstand-Erkennung."""
    start_time = time.time()
    last_done_count = -1
    stalls = 0
    max_stalls = 5

    while time.time() - start_time < monitor_timeout:
        output = execute_command_on_shell(client, "show upgrade info")
        
        error_regex = r"^([\da-fA-F:]{17})\s+.*\s+(\S+)$"
        for line in output.splitlines():
            if match := re.search(error_regex, line):
                error_detail = match.group(2).strip()
                if error_detail.lower() != 'none':
                    error_msg = f"FEHLER: AP {match.group(1)} meldet Fehler: '{error_detail}'."
                    logger.write(f"{error_msg}\n")
                    cluster_statuses[conductor_ip] = error_msg
                    return False
        
        is_finished_globally = re.search(r"Upgrade in process\s*:\s*No", output, re.IGNORECASE)
        ap_lines = [line for line in output.splitlines() if re.match(r"^[\da-fA-F:]{17}", line)]
        done_count = len([line for line in ap_lines if "upgrade-done" in line])
        
        cluster_statuses[conductor_ip] = f"Phase 4: Monitoring ({done_count}/{total_ap_count} fertig)"

        if is_finished_globally and done_count >= total_ap_count:
            logger.write(f"SUCCESS: Upgrade-Prozess auf allen APs abgeschlossen.\n")
            cluster_statuses[conductor_ip] = "Phase 4: Upgrade erfolgreich beendet."
            return True

        if done_count == last_done_count:
            stalls += 1
        else:
            last_done_count = done_count
            stalls = 0
        
        if stalls >= max_stalls:
            error_msg = f"FEHLER: Upgrade-Prozess blockiert bei {done_count}/{total_ap_count} APs."
            logger.write(f"{error_msg}\n")
            cluster_statuses[conductor_ip] = error_msg
            return False
        
        time.sleep(updatewait)

    logger.write(f"FEHLER: Timeout von {monitor_timeout}s bei der Überwachung erreicht.\n")
    cluster_statuses[conductor_ip] = "FEHLER: Timeout bei der Überwachung."
    return False

def reload_swarm(client, cluster_statuses, conductor_ip, logger):
    """Führt einen 'reload all' aus."""
    cluster_statuses[conductor_ip] = "Phase 5: Sende Neustart-Befehl..."
    try:
        channel = client.invoke_shell()
        time.sleep(1); channel.recv(4096)
        channel.send("reload all\n")
        time.sleep(1)
        channel.send("y\n")
        time.sleep(1); channel.close()
        logger.write(f"SUCCESS: Neustart-Befehl gesendet.\n")
        cluster_statuses[conductor_ip] = "ERFOLG: Neustart eingeleitet."
        return True
    except Exception as e:
        logger.write(f"FEHLER: Neustart-Befehl fehlgeschlagen: {e}\n")
        cluster_statuses[conductor_ip] = "FEHLER: Neustart-Befehl fehlgeschlagen."
        return False

def upgrade_cluster_worker(q, cluster_statuses, auto_reload_all, args, cfg, output_dir):
    """Die Worker-Funktion, die pro Thread läuft und einen Cluster abarbeitet."""
    while not q.empty():
        conductor_ip, creds = q.get()
        
        log_filename = os.path.join(output_dir, f"update_log_{conductor_ip}.txt")
        worker_logger = Logger(filename=log_filename)

        worker_logger.write(f"[{datetime.now().strftime('%H:%M:%S')}] Starte Bearbeitung für Conductor {conductor_ip}.\n")
        cluster_statuses[conductor_ip] = "Phase 1: Verbinde..."
        
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            client.connect(conductor_ip, username=creds['user'], password=creds['pass'], timeout=cfg['timeout'])
            
            # ### START BUGFIX (Robuste Namensfindung) ###
            config_output = execute_command_on_shell(client, "show running-config")
            name_match = re.search(r"^name\s+(\S+)", config_output, re.MULTILINE)
            conductor_name = name_match.group(1) if name_match else conductor_ip
            # ### END BUGFIX ###
            
            final_log_filename = os.path.join(output_dir, f"update_log_{conductor_ip}_{conductor_name}.txt")
            worker_logger.logfile.close()
            os.rename(log_filename, final_log_filename)
            worker_logger.logfile = open(final_log_filename, 'a', encoding='utf-8')

            if not check_current_version(client, args.firmwareurl, cluster_statuses, conductor_ip, worker_logger):
                continue

            needed_ap_classes, total_ap_count = get_ap_classes_from_conductor(client, cluster_statuses, conductor_ip, worker_logger)
            if not needed_ap_classes:
                continue
            
            firmware_map = get_firmware_urls_from_web(args.firmwareurl, needed_ap_classes, cluster_statuses, conductor_ip, worker_logger)
            if not firmware_map:
                continue
                
            if not execute_cli_upgrade(client, firmware_map, cluster_statuses, conductor_ip, worker_logger):
                continue
            
            if not monitor_upgrade_process(client, total_ap_count, cfg['monitor_timeout'], cfg['updatewait'], cluster_statuses, conductor_ip, worker_logger):
                continue

            if auto_reload_all:
                reload_swarm(client, cluster_statuses, conductor_ip, worker_logger)
            else:
                 cluster_statuses[conductor_ip] = "ERFOLG: Upgrade beendet (manueller Neustart erforderlich)."

        except Exception as e:
            error_msg = f"FATALER FEHLER: {str(e).strip()}"
            worker_logger.write(f"{error_msg}\n")
            cluster_statuses[conductor_ip] = error_msg
        finally:
            if client: client.close()
            worker_logger.close()
            q.task_done()

def display_progress(cluster_statuses, start_time, all_threads, firmware_url):
    """Zeigt den Fortschritt aller Threads in einer Live-Tabelle an."""
    target_version_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", firmware_url)
    target_version = target_version_match.group(1) if target_version_match else "Unbekannt"

    while any(t.is_alive() for t in all_threads):
        os.system('cls' if os.name == 'nt' else 'clear')
        
        print(f"--- Echtzeit-Monitoring der Cluster-Upgrades (Version 4.1.0) ---")
        print(f"Zielversion: {target_version} | Letzte Aktualisierung: {datetime.now().strftime('%H:%M:%S')} | Laufzeit: {str(datetime.now() - start_time).split('.')[0]}")
        print(f"Updatequelle: {firmware_url}\n")

        print("{:<16} | {:<70}".format("IP-ADRESSE", "STATUS"))
        print("-" * 90)
        
        for ip, status in sorted(cluster_statuses.items()):
            print("{:<16} | {:<70}".format(ip, status))
            
        time.sleep(1)


# === Hauptskript ===
if __name__ == "__main__":
    check_dependencies()
    
    parser = argparse.ArgumentParser(description="Startet ein Firmware-Update für Aruba Swarms via CLI.", formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('targets', nargs='*', default=[], help="Optional: Eine oder mehrere Conductor-IPs (kommasepariert).")
    parser.add_argument('--importfile', type=str, help="Pfad zu einer CSV-Datei, aus der Conductor-IPs importiert werden.")
    parser.add_argument('-f', '--firmwareurl', type=str, required=True, help="URL zum Verzeichnis mit den Firmware-Dateien.")
    parser.add_argument('--log', action='store_true', help="Aktiviert Logging in eine Datei (wird jetzt pro Cluster erstellt).")
    args = parser.parse_args()

    run_timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    output_dir = os.path.join(os.getcwd(), "update_" + run_timestamp)
    os.makedirs(output_dir, exist_ok=True)
    
    main_log_filename = os.path.join(output_dir, "main_skript_log.txt")
    main_logger = Logger(filename=main_log_filename)
    main_logger.write(f"ap_swarm_update.py Version 4.1.0 wird ausgeführt...\n")
    main_logger.write(f"Teil der Aruba Instant Toolsammlung Version {TOOLSUITE_VERSION}\n")
    main_logger.write(f"Helper-Bibliothek Version {SCRIPT_VERSION}\n")
    start_time_total = datetime.now()
    main_logger.write(f"===== Skriptstart: {start_time_total.strftime('%Y-%m-%d %H:%M:%S')} =====\n")

    try:
        with open("config.json", 'r', encoding='utf-8') as f: config = json.load(f)
    except FileNotFoundError: main_logger.write("FEHLER: config.json nicht gefunden!\n"); sys.exit(1)
    except json.JSONDecodeError as e: main_logger.write(f"FEHLER: Die Datei config.json ist fehlerhaft: {e}\n"); sys.exit(1)

    cfg = {
        'timeout': config.get('timeout_seconds', 30),
        'monitor_timeout': config.get('monitor_timeout_minutes', 20) * 60,
        'updatewait': config.get('updatewait_seconds', 10),
        'num_threads': config.get('upd_threads', 20)
    }

    targets = []
    if args.importfile:
        try:
            offline_targets_from_csv = []
            with open(args.importfile, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                has_status_col = 'Status' in reader.fieldnames
                for row in reader:
                    if ip := row.get('IP-Adresse'):
                        if has_status_col and row.get('Status', '').lower() == 'down':
                            offline_targets_from_csv.append(ip)
                        else: targets.append(ip)
            main_logger.write(f"INFO: {len(targets)} Online-Conductor(s) und {len(offline_targets_from_csv)} Offline-Conductor(s) importiert.\n")
            if offline_targets_from_csv:
                response = get_input_and_log("WARNUNG: Conductor als 'Down' gemeldet. Trotzdem berücksichtigen? (j/n): ", main_logger)
                if response.lower() == 'j': targets.extend(offline_targets_from_csv)
        except FileNotFoundError: main_logger.write(f"FEHLER: Import-Datei '{args.importfile}' nicht gefunden.\n"); sys.exit(1)

    if args.targets:
        positional_targets = [item for arg in args.targets for item in arg.split(',')]
        if targets: main_logger.write(f"INFO: Füge {len(positional_targets)} zusätzliche Ziele aus der Kommandozeile hinzu.\n")
        targets.extend(positional_targets)

    if not targets: targets = config.get('conductor_ips', [])
    if not targets:
        main_logger.write("FEHLER: Keine Conductor-IPs angegeben.\n"); parser.print_help(); sys.exit(1)
        
    all_targets_unique = sorted(list(set(targets)))

    print("-" * 50)
    main_logger.write(f"INFO: Es sind {len(all_targets_unique)} Cluster für das Upgrade vorgesehen.\n")
    if get_input_and_log("Wollen Sie wirklich fortfahren? (j/n): ", main_logger).lower() != 'j':
        main_logger.write("Aktion vom Benutzer abgebrochen.\n"); sys.exit(0)
        
    auto_reload_all = get_input_and_log("Sollen alle Cluster nach erfolgreichem Upgrade automatisch neu gestartet werden? (j/n): ", main_logger).lower() == 'j'
    main_logger.write(f"INFO: Automatischer Neustart ist {'aktiviert' if auto_reload_all else 'deaktiviert'}.\n")
    print("-" * 50)
    
    storage_choice = 'none'
    main_logger.write("\n--- Konfiguration der Anmeldedaten ---\n")
    if KEYRING_AVAILABLE:
        prompt_text = ( "Soll der Anmeldespeicher des Betriebssystems verwendet werden? (Empfohlen)\n"
                        "[1] Ja\n[2] Nein, lokal ... speichern\n[3] Nein, ... manuell eingeben\nIhre Wahl: ")
        choice = get_input_and_log(prompt_text, main_logger).lower()
        if choice in ['1', 'j', 'ja']: storage_choice = 'keyring'
        elif choice == '2':
            if CRYPTO_AVAILABLE: storage_choice = 'file'
            else: print("HINWEIS: 'pycryptodome' nicht installiert...")
    elif CRYPTO_AVAILABLE:
        if get_input_and_log("WARNUNG - Zugangsdaten speichern\n  * Passwörter werden in der Datei 'credentials.bin' im aktuellen Verzeichnis abgelegt.\n  * Die Verschlüsselung ist nur ein Basisschutz (Schlüssel aus der MAC-Adresse dieses\n    Rechners, fester Salt) und KEIN sicherer Tresor: Wer die Datei und Zugriff auf diesen\n    Rechner hat, kann die Passwörter auslesen.\n  * Datei niemals weitergeben, in Git einchecken oder in Cloud-/Backup-Ordnern ablegen.\n  * Sicherer: Windows-Anmeldeinformationsverwaltung (Keyring).\nAnmeldedaten trotzdem in 'credentials.bin' speichern? (j/n): ", main_logger).lower() == 'j':
            storage_choice = 'file'
    cfg['storage_method'] = storage_choice

    credentials_store = {}
    targets_without_creds = list(all_targets_unique)
    
    main_logger.write("\n--- Pre-Flight Check: Prüfe gespeicherte Anmeldedaten ---\n")
    pre_check_user = None
    if cfg['storage_method'] == 'keyring':
        pre_check_user = get_input_and_log("Bitte den zu prüfenden SSH-Benutzernamen eingeben: ", main_logger)
    
    found_creds_ips = []
    for ip in targets_without_creds:
        user, password = get_saved_credentials(ip, cfg, pre_check_user)
        if user and password:
            credentials_store[ip] = {'user': user, 'pass': password}
            found_creds_ips.append(ip)
    targets_without_creds = [ip for ip in targets_without_creds if ip not in found_creds_ips]

    if targets_without_creds:
        main_logger.write(f"\nHINWEIS: Für {len(targets_without_creds)} von {len(all_targets_unique)} Zielen fehlen Anmeldedaten.\n")
        use_same_for_all = len(targets_without_creds) > 1 and get_input_and_log("Sind die fehlenden Anmeldedaten für alle diese Ziele identisch? (j/n): ", main_logger).lower() == 'j'
        
        if use_same_for_all:
            main_logger.write("\nBitte geben Sie die allgemeinen Anmeldedaten ein.\n")
            while True:
                user, password = get_credentials_interactively()
                if validate_credentials(targets_without_creds[0], user, password, cfg['timeout']):
                    if get_input_and_log("Sollen diese Daten gespeichert werden? (j/n): ", main_logger).lower() == 'j':
                        for ip in targets_without_creds: save_credential(ip, user, password, cfg)
                    for ip in targets_without_creds: credentials_store[ip] = {'user': user, 'pass': password}
                    break
                else:
                    if get_input_and_log("Erneut versuchen? (j/n): ", main_logger).lower() != 'j': sys.exit("Aktion abgebrochen.")
        else:
            for ip in targets_without_creds:
                main_logger.write(f"\nBitte geben Sie die Anmeldedaten für {ip} ein.\n")
                while True:
                    user, password = get_credentials_interactively()
                    if validate_credentials(ip, user, password, cfg['timeout']):
                        if get_input_and_log(f"Sollen diese Daten für {ip} gespeichert werden? (j/n): ", main_logger).lower() == 'j':
                            save_credential(ip, user, password, cfg)
                        credentials_store[ip] = {'user': user, 'pass': password}
                        break
                    else:
                        if get_input_and_log("Erneut versuchen? (j/n): ", main_logger).lower() != 'j': sys.exit("Aktion abgebrochen.")
    
    task_queue = Queue()
    cluster_statuses = {} 

    for ip in all_targets_unique:
        creds = credentials_store.get(ip)
        if not creds:
            main_logger.write(f"WARNUNG: Keine Anmeldedaten für {ip} gefunden, wird übersprungen.\n")
            cluster_statuses[ip] = "FEHLER: Keine Anmeldedaten"
            continue
        task_queue.put((ip, creds))
        cluster_statuses[ip] = "In Warteschlange..."
        
    threads = []
    for _ in range(min(len(all_targets_unique), cfg['num_threads'])):
        thread = threading.Thread(target=upgrade_cluster_worker, args=(task_queue, cluster_statuses, auto_reload_all, args, cfg, output_dir))
        thread.start()
        threads.append(thread)

    display_progress(cluster_statuses, start_time_total, threads, args.firmwareurl)
    
    for thread in threads:
        thread.join()

    final_summary = "\n\n" + "="*20 + " FINALE ZUSAMMENFASSUNG " + "="*20 + "\n"
    for ip, status in sorted(cluster_statuses.items()):
        final_summary += "{:<16} | {:<70}\n".format(ip, status)
    
    print("\n")
    main_logger.write(final_summary)
            
    end_time_total = datetime.now()
    main_logger.write(f"===== Skriptende: {end_time_total.strftime('%Y-%m-%d %H:%M:%S')} =====\n")
    main_logger.write(f"Gesamtdauer: {str(end_time_total - start_time_total).split('.')[0]}\n")
    main_logger.close()

### Hier ist das Ende ###