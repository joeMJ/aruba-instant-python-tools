### ap_swarm_reload.py - Tool für das Neustarten kompletter Schwärme
### Version 1.0.d - Korrektur der Eingabevalidierung
### Bestandteil der Aruba Instant Python Tools Suite V 2.0.0
### gemacht mit viel Liebe von John (johnlose.de)

# Importiere notwendige Bibliotheken
import paramiko
import csv
import sys
import time
import json
import os
import argparse
import platform
import subprocess
from datetime import datetime

# Importiere die Helper-Funktionen
from aruba_helper import (
    SCRIPT_VERSION, check_dependencies, Logger, get_saved_credentials,
    validate_credentials, get_credentials_interactively, save_credential,
    delete_credential_for_ip, KEYRING_AVAILABLE, CRYPTO_AVAILABLE
)

TOOLSUITE_VERSION = "2.0.0"

def ping_host(host):
    """
    Ping einen Host, um die Erreichbarkeit zu prüfen.
    Erkennt das Betriebssystem und passt den Befehl an.
    """
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', '-w', '2', host] # -w 2 für 2s Timeout
    try:
        # Führe den Befehl aus und unterdrücke die Ausgabe
        return subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    except FileNotFoundError:
        # Falls der 'ping'-Befehl nicht gefunden wird
        print(f"FEHLER: 'ping' Befehl nicht im Systempfad gefunden.")
        return False

def send_and_confirm_reload(ip, creds, timeout):
    """
    Baut eine SSH-Verbindung auf, sendet 'reload all' und bestätigt die (y/n) Abfrage.
    Gibt True bei Erfolg, False bei einem Fehler zurück.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        print(f"Verbinde mit {ip}...")
        client.connect(ip, username=creds['user'], password=creds['pass'], timeout=timeout)
        
        channel = client.invoke_shell()
        
        # Puffer leeren und auf den ersten Prompt warten
        time.sleep(1)
        channel.recv(4096) 
        
        print(f"Sende 'reload all' an {ip}...")
        channel.send("reload all\n")
        
        # Warte auf die Bestätigungsabfrage
        output = ""
        for _ in range(5): # 5 Versuche, je 1 Sekunde
            time.sleep(1)
            if channel.recv_ready():
                output += channel.recv(4096).decode('utf-8', errors='ignore')
                # Prüfe, ob die Bestätigungsabfrage im Output ist
                if "reset the system (y/n)" in output:
                    print(f"INFO: Bestätigungsabfrage für {ip} erkannt. Sende 'y'...")
                    channel.send("y\n")
                    time.sleep(1) # Gib dem Befehl einen Moment
                    return True # Erfolgreich bestätigt
        
        # Wenn wir hier ankommen, wurde die Abfrage nicht gefunden
        print(f"FEHLER: Die Bestätigungsabfrage 'reset the system (y/n)' wurde für {ip} nicht empfangen.")
        print(f"Letzte Ausgabe vom Gerät: {output}")
        return False

    except Exception as e:
        print(f"FEHLER bei der interaktiven Sitzung mit {ip}: {e}")
        return False
    finally:
        if client: client.close()


# === Hauptskript ===
if __name__ == "__main__":
    check_dependencies()

    original_stdout = sys.stdout
    log_file_handler = None
    
    epilog_text = """
Beispiele:

  # Einen einzelnen Conductor-Schwarm neu starten
  py ap_swarm_reload.py 10.1.1.1

  # Mehrere Schwärme neu starten
  py ap_swarm_reload.py 10.1.1.1,10.2.2.2

  # Conductors aus einer Datei importieren und Log erstellen
  py ap_swarm_reload.py --importfile C:\\pfad\\zur\\liste.csv --log
"""

    parser = argparse.ArgumentParser(
        description="Startet einen oder mehrere Aruba Swarms (Conductor APs) neu.",
        epilog=epilog_text,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('targets', nargs='*', default=[], help="Optional: Eine oder mehrere Conductor-IPs (kommasepariert).")
    parser.add_argument('--importfile', type=str, help="Pfad zu einer CSV-Datei, aus der Conductor-IPs importiert werden sollen.")
    parser.add_argument('--log', action='store_true', help="Aktiviert das Schreiben der Konsolenausgabe in eine Log-Datei.")
    
    args = parser.parse_args()

    # --- Normaler Ausführungsmodus ---
    run_timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    output_dir = os.path.join(os.getcwd(), "logs_" + run_timestamp)
    os.makedirs(output_dir, exist_ok=True)
    
    if args.log:
        try:
            log_filename = os.path.join(output_dir, "ap_swarm_reload_log.txt")
            log_file_handler = Logger(filename=log_filename)
            sys.stdout = log_file_handler
        except Exception as e:
            sys.stdout = original_stdout
            print(f"FEHLER: Log-Datei konnte nicht erstellt werden: {e}")
    
    print(f"ap_swarm_reload.py Version 1.0.d wird ausgeführt...")
    print(f"Teil der Aruba Instant Toolsammlung Version {TOOLSUITE_VERSION}")
    print(f"Helper-Bibliothek Version {SCRIPT_VERSION}")

    start_time = datetime.now()
    print(f"\n===== Skriptstart: {start_time.strftime('%Y-%m-%d %H:%M:%S')} =====")

    try:
        with open("config.json", 'r', encoding='utf-8') as f: config = json.load(f)
    except FileNotFoundError: print("FEHLER: config.json nicht gefunden!"); sys.exit(1)
    except json.JSONDecodeError as e: print(f"FEHLER: Die Datei config.json ist fehlerhaft: {e}"); sys.exit(1)

    cfg = {
        'timeout': config.get('timeout_seconds', 30),
        'reloadtimeout': config.get('reloadtimeout', 120),
        'lang': config.get('language_terms')
    }

    targets = []
    if args.importfile:
        print(f"\nINFO: Importiere Ziele aus Datei: {args.importfile}")
        try:
            with open(args.importfile, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if ip := row.get('IP-Adresse'): targets.append(ip)
            print(f"INFO: {len(targets)} Conductor(s) aus '{args.importfile}' importiert.")
        except FileNotFoundError: print(f"FEHLER: Import-Datei '{args.importfile}' nicht gefunden."); sys.exit(1)
        except Exception as e: print(f"FEHLER: Konnte Import-Datei nicht verarbeiten: {e}"); sys.exit(1)

    if args.targets:
        positional_targets = []
        for item in args.targets: positional_targets.extend(item.split(','))
        if targets: print(f"INFO: Füge {len(positional_targets)} zusätzliche Ziele aus der Kommandozeile hinzu.")
        targets.extend(positional_targets)

    if not targets: targets = config.get('conductor_ips', [])
    if not targets:
        print("FEHLER: Keine Conductor-IPs angegeben (weder per CLI, Import noch in config.json).")
        parser.print_help()
        sys.exit(1)

    # --- Credential Handling ---
    storage_choice = 'none'
    print("\n--- Konfiguration der Anmeldedaten ---")
    if KEYRING_AVAILABLE:
        prompt_text = (
            "Soll der Anmeldespeicher des Betriebssystems verwendet werden? (Empfohlen)\n"
            "[1] Ja\n"
            "[2] Nein, lokal mit PyCryptodome verschlüsselt speichern\n"
            "[3] Nein, bei jedem Start manuell eingeben\n"
            "-----------------------------------------------------------\n"
            "Ihre Wahl: "
        )
        choice = input(prompt_text).lower()
        if choice in ['1', 'j', 'ja']:
            storage_choice = 'keyring'
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
    all_targets_unique = sorted(list(set(targets)))
    targets_without_creds = list(all_targets_unique)
    
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
        print(f"\nHINWEIS: Für {len(targets_without_creds)} von {len(all_targets_unique)} Zielen fehlen Anmeldedaten.")
        use_same_for_all = len(targets_without_creds) > 1 and input("Sind die fehlenden Anmeldedaten für alle diese Ziele identisch? (j/n): ").lower() == 'j'
        
        if use_same_for_all:
            print("\nBitte geben Sie die allgemeinen Anmeldedaten ein.")
            while True:
                user, password = get_credentials_interactively()
                if validate_credentials(targets_without_creds[0], user, password, cfg['timeout']):
                    print("INFO: Anmeldedaten erfolgreich validiert.")
                    if cfg['storage_method'] != 'none' and input("Sollen diese Daten für alle fehlenden Ziele gespeichert werden? (j/n): ").lower() == 'j':
                        for ip in targets_without_creds: save_credential(ip, user, password, cfg)
                    for ip in targets_without_creds: credentials_store[ip] = {'user': user, 'pass': password}
                    break
                else:
                    if input("Erneut versuchen? (j/n): ").lower() != 'j': sys.exit("Aktion abgebrochen.")
        else:
            for ip in targets_without_creds:
                print(f"\nBitte geben Sie die Anmeldedaten für {ip} ein.")
                while True:
                    user, password = get_credentials_interactively()
                    if validate_credentials(ip, user, password, cfg['timeout']):
                        print("INFO: Anmeldedaten erfolgreich validiert.")
                        if cfg['storage_method'] != 'none' and input(f"Sollen diese Daten für {ip} gespeichert werden? (j/n): ").lower() == 'j':
                            save_credential(ip, user, password, cfg)
                        credentials_store[ip] = {'user': user, 'pass': password}
                        break
                    else:
                        if input("Erneut versuchen? (j/n): ").lower() != 'j': sys.exit("Aktion abgebrochen.")
    else:
        if all_targets_unique: print("INFO: Für alle Ziele wurden gespeicherte Anmeldedaten gefunden.")
    
    # --- Kernlogik: PING, Reload, Monitor ---
    print("\n--- Phase 1: Erreichbarkeit der Conductors prüfen (PING) ---")
    online_conductors = []
    offline_conductors = []
    for ip in all_targets_unique:
        print(f"Pinge {ip}...", end="")
        if ping_host(ip):
            print(" ERREICHBAR")
            online_conductors.append(ip)
        else:
            print(" NICHT ERREICHBAR")
            offline_conductors.append(ip)

    conductors_to_reload = list(online_conductors)
    if offline_conductors:
        print(f"\nWARNUNG: {len(offline_conductors)} Conductor(s) sind nicht per PING erreichbar:")
        for ip in offline_conductors: print(f"- {ip}")
        if input("Sollen diese trotzdem für den Reload-Versuch berücksichtigt werden? (j/n): ").lower() == 'j':
            conductors_to_reload.extend(offline_conductors)
    
    if not conductors_to_reload:
        print("\nKeine Ziele für den Neustart-Vorgang vorhanden. Skript wird beendet.")
        sys.exit(0)

    print(f"\n--- Phase 2: Sende und bestätige 'reload all' an {len(conductors_to_reload)} Conductor(s) ---")
    reloading_conductors = []
    failed_to_command = []
    for ip in conductors_to_reload:
        creds = credentials_store.get(ip)
        if not creds:
            print(f"FEHLER: Keine Anmeldedaten für {ip} gefunden. Überspringe.")
            failed_to_command.append(ip)
            continue
        
        if send_and_confirm_reload(ip, creds, cfg['timeout']):
            reloading_conductors.append(ip)
        else:
            failed_to_command.append(ip)
    
    if not reloading_conductors:
        print("\nKonnte an keinen Conductor einen Neustart-Befehl erfolgreich senden. Skript wird beendet.")
        sys.exit(1)

    print(f"\n--- Phase 3: Überwache Neustart der {len(reloading_conductors)} Conductor(s) ---")
    monitoring_start_time = time.time()
    
    while reloading_conductors:
        if time.time() - monitoring_start_time > cfg['reloadtimeout']:
            print(f"\nFEHLER: Timeout von {cfg['reloadtimeout']} Sekunden erreicht.")
            print("Folgende Conductor sind nicht wie erwartet offline gegangen:")
            for ip in reloading_conductors:
                print(f"- {ip}")
            sys.exit(1)

        print(f"INFO: {len(reloading_conductors)} Conductor(s) noch online. Pinge erneut in 5 Sekunden...")
        time.sleep(5)
        
        # Iteriere über eine Kopie, damit wir aus dem Original löschen können
        for ip in list(reloading_conductors):
            if not ping_host(ip):
                print(f"ERFOLG: Conductor {ip} ist offline und startet neu.")
                reloading_conductors.remove(ip)
    
    print("\nERFOLG: Alle angewiesenen Conductors wurden neu gestartet.")

    end_time = datetime.now()
    total_duration = end_time - start_time
    print(f"\n===== Skriptende: {end_time.strftime('%Y-%m-%d %H:%M:%S')} =====")
    print(f"Gesamtdauer: {str(total_duration).split('.')[0]}")

    if 'log_file_handler' in locals() and log_file_handler:
        sys.stdout = original_stdout
        log_file_handler.close()

### Hier ist das Ende ###