### ap_offline_delete.py - Löscht offline APs aus der Provisionierungsliste
### Version 1.3.0 - Finale kosmetische Anpassungen und korrekte Zählung
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
import re
from collections import defaultdict
from datetime import datetime

# Importiere die Helper-Funktionen
from aruba_helper import (
    SCRIPT_VERSION, check_dependencies, Logger, get_saved_credentials,
    validate_credentials, get_credentials_interactively, save_credential,
    execute_command_on_shell, KEYRING_AVAILABLE, CRYPTO_AVAILABLE
)

TOOLSUITE_VERSION = "2.0.0"

def execute_deletion_on_conductor(ip, mac_list_from_csv, creds, timeout):
    """
    Sendet Löschbefehle und gibt die Anzahl der erfolgreich entfernten APs zurück.
    Gibt 0 im Fehlerfall zurück.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print(f"\n--- Verbinde mit Conductor {ip} zur Überprüfung und Löschung ---")
    
    try:
        client.connect(ip, username=creds['user'], password=creds['pass'], timeout=timeout)
        
        print(f"Lese aktuelle Konfiguration von {ip}...")
        initial_config = execute_command_on_shell(client, "show running-config")
        
        macs_to_delete = []
        for mac in mac_list_from_csv:
            if mac.lower() in initial_config.lower():
                macs_to_delete.append(mac)
            else:
                print(f"INFO: MAC {mac} ist bereits nicht mehr in der allowed-ap Liste vorhanden, wird übersprungen.")

        if not macs_to_delete:
            print(f"INFO: Für Conductor {ip} sind keine der gelisteten APs mehr vorhanden. Nichts zu tun.")
            return 0 # Gibt 0 zurück, da nichts aktiv gelöscht wurde

        print(f"Starte interaktive Lösch-Session für {len(macs_to_delete)} AP(s) auf {ip}...")
        channel = client.invoke_shell()
        time.sleep(2)
        if channel.recv_ready():
            channel.recv(9999)

        channel.send("configure terminal\n")
        time.sleep(1)

        for mac in macs_to_delete:
            channel.send(f"no allowed-ap {mac}\n")
            time.sleep(0.5)
        
        channel.send("end\n")
        time.sleep(1)
        
        channel.send("commit apply\n")
        print("Commit-Befehl gesendet. Warte kurz auf die Verarbeitung...")
        time.sleep(3)

        commit_output = ""
        if channel.recv_ready():
            commit_output = channel.recv(9999).decode('utf-8', errors='ignore')

        if "Configuration denied by AirWave management" in commit_output:
            print("\nFEHLER: Löschen nicht erfolgreich. Ursache: Der Schwarm wird zentral verwaltet.")
            print("HINWEIS: Bitte den Verwaltungsmodus in AirWave auf 'Monitor Only + Firmware Upgrades' ändern und erneut versuchen!")
            channel.close()
            return 0

        commit_confirmed = False
        if "Configuration committed" in commit_output or "Configuration saved" in commit_output:
            commit_confirmed = True
        else:
            for _ in range(5):
                time.sleep(1)
                if channel.recv_ready():
                    if "Configuration committed" in channel.recv(9999).decode('utf-8', errors='ignore'):
                        commit_confirmed = True
                        break
        
        if commit_confirmed:
            print("INFO: Explizite Commit-Bestätigung vom Gerät erhalten.")
        else:
            print("WARNUNG: Keine explizite Commit-Bestätigung erhalten. Verlasse mich auf die finale Verifizierung.")
        
        channel.close()

        print("Finale Verifizierung: Lese Konfiguration erneut, um den Löschvorgang zu bestätigen...")
        final_config = execute_command_on_shell(client, "show running-config")

        all_deleted = True
        for mac in macs_to_delete:
            if mac.lower() in final_config.lower():
                print(f"FEHLER: Verifizierung fehlgeschlagen! AP {mac} wurde NICHT aus der Konfiguration entfernt.")
                all_deleted = False
        
        if all_deleted:
            print(f"ERFOLG: Alle {len(macs_to_delete)} AP(s) wurden nachweislich von {ip} entfernt.")
            return len(macs_to_delete)
        else:
            return 0

    except Exception as e:
        print(f"FEHLER beim Löschvorgang auf {ip}: {e}")
        return 0
    finally:
        if client: client.close()


# === Hauptskript ===
if __name__ == "__main__":
    check_dependencies()

    original_stdout = sys.stdout
    log_file_handler = None
    
    epilog_text = """
Beispiel:

  # Lösche alle APs, die in der 'ap_offline_bereinigt.csv' gelistet sind
  py ap_offline_delete.py --importfile C:\\pfad\\zu\\ap_offline_bereinigt.csv --log
"""

    parser = argparse.ArgumentParser(
        description="Löscht provisionierte Aruba APs basierend auf einer CSV-Importdatei.",
        epilog=epilog_text,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--importfile', type=str, required=True, help="Pfad zur CSV-Datei mit den zu löschenden APs (z.B. ap_offline.csv).")
    parser.add_argument('--log', action='store_true', help="Aktiviert das Schreiben der Konsolenausgabe in eine Log-Datei.")
    
    args = parser.parse_args()
    
    if args.log:
        run_timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        output_dir = os.path.join(os.getcwd(), "ap_delete_" + run_timestamp)
        os.makedirs(output_dir, exist_ok=True)
        try:
            log_filename = os.path.join(output_dir, "ap_offline_delete_log.txt")
            log_file_handler = Logger(filename=log_filename)
            sys.stdout = log_file_handler
            print(f"INFO: Logging ist aktiviert. Ausgabe wird in '{log_filename}' geschrieben.")
        except Exception as e:
            sys.stdout = original_stdout
            print(f"FEHLER: Log-Datei konnte nicht erstellt werden: {e}")
    
    print(f"ap_offline_delete.py Version 1.3.0 wird ausgeführt...")
    print(f"Teil der Aruba Instant Toolsammlung Version {TOOLSUITE_VERSION}")
    print(f"Helper-Bibliothek Version {SCRIPT_VERSION}")

    start_time = datetime.now()
    print(f"\n===== Skriptstart: {start_time.strftime('%Y-%m-%d %H:%M:%S')} =====")

    try:
        with open("config.json", 'r', encoding='utf-8') as f: config = json.load(f)
    except FileNotFoundError: print("FEHLER: config.json nicht gefunden!"); sys.exit(1)
    except json.JSONDecodeError as e: print(f"FEHLER: Die Datei config.json ist fehlerhaft: {e}"); sys.exit(1)

    cfg = { 'timeout': config.get('timeout_seconds', 30) }

    print(f"\n--- Phase 1: Analysiere Import-Datei: {args.importfile} ---")
    
    aps_to_delete_by_conductor = defaultdict(list)
    try:
        with open(args.importfile, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            
            if not all(col in reader.fieldnames for col in ['Conductor IP', 'Offline AP MAC']):
                print(f"FEHLER: Die Import-Datei '{args.importfile}' muss die Spalten 'Conductor IP' und 'Offline AP MAC' enthalten.")
                sys.exit(1)
            
            ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

            for row in reader:
                conductor_ip = (row.get('Conductor IP') or '').strip()
                offline_mac = (row.get('Offline AP MAC') or '').strip()

                if not ip_pattern.match(conductor_ip):
                    if conductor_ip: 
                        print("INFO: Ende der Datenzeilen erreicht (Footer gefunden). Lese weitere Zeilen nicht ein.")
                    break 

                if conductor_ip and offline_mac:
                    aps_to_delete_by_conductor[conductor_ip].append(offline_mac)

    except FileNotFoundError:
        print(f"FEHLER: Import-Datei '{args.importfile}' nicht gefunden.")
        sys.exit(1)
    except Exception as e:
        print(f"FEHLER: Konnte Import-Datei nicht verarbeiten: {e}")
        sys.exit(1)

    if not aps_to_delete_by_conductor:
        print("INFO: Keine gültigen Einträge in der Import-Datei gefunden. Es gibt nichts zu tun.")
        sys.exit(0)

    print("\n--- Phase 2: Zusammenfassung und Bestätigung ---")
    total_aps_to_delete = sum(len(macs) for macs in aps_to_delete_by_conductor.values())
    total_conductors = len(aps_to_delete_by_conductor)
    
    print(f"\nEs sollen insgesamt {total_aps_to_delete} AP(s) von {total_conductors} Conductor(s) gelöscht werden:")
    for ip, macs in aps_to_delete_by_conductor.items():
        print(f"- Conductor {ip}: {len(macs)} AP(s)")
    
    print("\nWARNUNG: Diese Aktion löscht die Access Points permanent aus der Provisionierungsliste.")
    if input("Wollen Sie wirklich fortfahren? (j/n): ").lower() != 'j':
        print("Aktion vom Benutzer abgebrochen.")
        sys.exit(0)
        
    targets = list(aps_to_delete_by_conductor.keys())
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
    
    print("\n--- Phase 3: Starte Löschvorgang ---")
    
    # KOSMETISCHE ANPASSUNG: Zählvariablen
    total_aps_successfully_deleted = 0
    successful_conductors = 0
    failed_conductors = 0
    
    for ip, macs_to_delete in aps_to_delete_by_conductor.items():
        creds = credentials_store.get(ip)
        if not creds:
            print(f"\nFEHLER: Keine Anmeldedaten für {ip} vorhanden. Überspringe diesen Conductor.")
            failed_conductors += 1
            continue
        
        # KOSMETISCHE ANPASSUNG: Rückgabewert (Anzahl) wird hier verarbeitet
        deleted_count = execute_deletion_on_conductor(ip, macs_to_delete, creds, cfg['timeout'])
        if deleted_count > 0:
            successful_conductors += 1
            total_aps_successfully_deleted += deleted_count
        elif len(macs_to_delete) > 0: # Nur als Fehler zählen, wenn auch etwas zu tun war
             failed_conductors += 1

    # KOSMETISCHE ANPASSUNG: Detaillierterer Abschlussbericht
    print("\n--- Abschlussbericht ---")
    print(f"Löschvorgang für {total_conductors} Conductor(s) beendet.")
    print(f"- Bearbeitete Conductors mit Erfolg: {successful_conductors}")
    print(f"- Bearbeitete Conductors mit Fehler: {failed_conductors}")
    print(f"-> Insgesamt erfolgreich gelöschte APs: {total_aps_successfully_deleted}")


    end_time = datetime.now()
    total_duration = end_time - start_time
    print(f"\n===== Skriptende: {end_time.strftime('%Y-%m-%d %H:%M:%S')} =====")
    print(f"Gesamtdauer: {str(total_duration).split('.')[0]}")

    if 'log_file_handler' in locals() and log_file_handler:
        sys.stdout = original_stdout
        log_file_handler.close()
### Hier ist das Ende ###