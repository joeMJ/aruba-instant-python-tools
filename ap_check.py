### Aruba Instant Python Tools
### ap_check.py - Überprüft den Status von Aruba Access Points
### Version 8.0.0 - DNS-Check für Member-APs hinzugefügt
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
import statistics
from datetime import datetime

# Importiere die neuen Helper-Funktionen
from aruba_helper import (
    SCRIPT_VERSION, check_dependencies, Logger, get_saved_credentials,
    validate_credentials, get_credentials_interactively, save_credential,
    delete_credential_for_ip, get_conductor_data, execute_command_on_shell,
    parse_speed, KEYRING_AVAILABLE, CRYPTO_AVAILABLE
)

TOOLSUITE_VERSION = "2.0.0"

print_lock = threading.Lock()

def check_ap_interfaces(ip, user, pw, timeout, lang):
    with print_lock:
        print(f"INFO: Verbinde mit Member-AP {ip} für Interface-Check...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    results = {'eth0_speed': 'N/A', 'eth0_errors': 0, 'eth0_mac': 'N/A',
               'eth1_speed': 'N/A', 'eth1_errors': 0, 'eth1_mac': 'N/A',
               'crashed': "0", 'power_status': 'N/A', 'active_vlans': set()}
    try:
        client.connect(ip, username=user, password=pw, timeout=timeout)

        interface_output = execute_command_on_shell(client, "show interface")
        interface_blocks = re.split(rf"\n(?=(?:eth|bond)\d is up)", '\n' + interface_output)
        for block in interface_blocks:
            name_match = re.search(r"^((?:eth|bond)\d)", block.strip())
            if not name_match: continue
            if_name = name_match.group(1)
            csv_if_name = "eth0" if if_name == "bond0" else if_name
            if csv_if_name not in ["eth0", "eth1"]: continue

            if sm := re.search(rf"{lang['interface_speed']} (\S+), {lang['interface_duplex']} (\w+)", block):
                results[f'{csv_if_name}_speed'] = f"{sm.group(1)}, {sm.group(2)}"
            if mac_match := re.search(rf"{lang['interface_address']} ([\da-fA-F:]{{17}})", block):
                results[f'{csv_if_name}_mac'] = mac_match.group(1)
            if crc_match := re.search(rf"{lang['errors_crc']}\s+(\d+)", block):
                results[f'{csv_if_name}_errors'] = int(crc_match.group(1))

        power_output = execute_command_on_shell(client, "show ap debug system-status")
        power_match = re.search(r"Current Operational State\s+:\s+(.*)", power_output)
        if power_match:
            results['power_status'] = power_match.group(1).strip()

        vlan_output = execute_command_on_shell(client, "show datapath vlan")
        active_vlans = set()
        vlan_pattern = re.compile(r"^\s*(\d+)\s+")
        for line in vlan_output.splitlines():
            match = vlan_pattern.match(line)
            if match:
                active_vlans.add(int(match.group(1)))
        results['active_vlans'] = active_vlans

        return results
    except Exception as e:
        with print_lock:
            print(f"FEHLER bei AP {ip} (Interfaces): {e}")
        results['crashed'] = "X"
        return results
    finally:
        if client: client.close()

def check_ap_dns(ip, user, pw, timeout, domain_to_check):
    """
    Führt einen performanten DNS-Check auf einem AP durch.
    Nutzt eine interaktive Shell, um nicht auf den kompletten Ping-Timeout zu warten.
    """
    with print_lock:
        print(f"INFO: Verbinde mit Member-AP {ip} für DNS-Check...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        client.connect(ip, username=user, password=pw, timeout=timeout)
        channel = client.invoke_shell()
        
        time.sleep(1)
        if channel.recv_ready():
            channel.recv(65535)

        channel.send(f"ping {domain_to_check}\n")

        output = ""
        start_time = time.time()
        while time.time() - start_time < 5:
            if channel.recv_ready():
                output += channel.recv(65535).decode('utf-8', errors='ignore')
                if "PING" in output and "(" in output and ")" in output:
                    channel.send("q\n")
                    return "OK"
                if "host address failed" in output:
                    return "Fehlgeschlagen"
            time.sleep(0.5)
        
        channel.send("q\n")
        return "Timeout"

    except Exception as e:
        with print_lock:
            print(f"FEHLER bei AP {ip} (DNS): {e}")
        return "Prüfungsfehler"
    finally:
        if client: client.close()

def find_ip_anomalies(conductor_ip, all_ap_details, gap_factor):
    anomalies, in_subnet_aps = [], []
    conductor_subnet = ".".join(conductor_ip.split('.')[:3])
    for ap in all_ap_details:
        if not ap['ip'].startswith(conductor_subnet + "."):
            ap['reason'] = "Incorrect Subnet"
            anomalies.append(ap)
        else:
            in_subnet_aps.append(ap)
    if len(in_subnet_aps) < 5: return anomalies
    last_octets = sorted([int(ap['ip'].split('.')[3]) for ap in in_subnet_aps])
    try:
        gaps = [j - i for i, j in zip(last_octets[:-1], last_octets[1:])]
        if not gaps: return anomalies
        avg_gap = statistics.mean(gaps) if gaps else 0
        gap_threshold = avg_gap * gap_factor if avg_gap > 1 else 10
        for i, gap in enumerate(gaps):
            if gap > gap_threshold:
                outlier_octet_start = last_octets[i+1]
                for ap in in_subnet_aps:
                    if int(ap['ip'].split('.')[3]) >= outlier_octet_start:
                        if ap not in anomalies:
                            ap['reason'] = "IP outlier (large gap)"
                            anomalies.append(ap)
                break
    except statistics.StatisticsError: pass
    return anomalies

def worker(task_queue, all_results_queue, online_mac_queue, user, pw, timeout, cfg):
    while True:
        item = task_queue.get()
        if item is None: break
        ip, ap_info = item
        
        iface_data = check_ap_interfaces(ip, user, pw, timeout, cfg['lang'])
        
        domain_to_check = cfg.get('dns_check_host', 'google.de')
        dns_status = check_ap_dns(ip, user, pw, timeout, domain_to_check)
        
        if iface_data['crashed'] == '0' and iface_data['eth0_mac'] != 'N/A':
            online_mac_queue.put(iface_data['eth0_mac'])
            
        full_result = ap_info.copy()
        full_result.update(iface_data)
        full_result['ip'] = ip
        full_result['dns_status'] = dns_status
        
        all_results_queue.put(full_result)
        task_queue.task_done()

def write_problem_ap_rows(writer, problem_aps_list):
    for ap in sorted(problem_aps_list, key=lambda x: x['ip']):
        writer.writerow({
            'Conductor-Name': ap.get('conductor_name'), 'IP Adresse': ap.get('ip'),
            'Seriennummer': ap.get('serial'), 'AP Typ': ap.get('ap_type'),
            'Laufzeit': ap.get('uptime'), 'eth0_speed': ap.get('eth0_speed'),
            'eth0_mac': ap.get('eth0_mac'), 'eth0_errors': ap.get('eth0_errors'),
            'eth1_speed': ap.get('eth1_speed'), 'eth1_mac': ap.get('eth1_mac'),
            'eth1_errors': ap.get('eth1_errors'), 'crashed': ap.get('crashed'),
            'Problem-Reason': ap.get('problem_reason', '')
        })

def write_offline_ap_rows(writer, offline_aps_list):
    for ap in offline_aps_list:
        writer.writerow({
            'Conductor-Name': ap.get('conductor_name'), 'Conductor IP': ap.get('conductor_ip'),
            'Offline AP MAC': ap.get('mac')
        })

def write_vlan_problem_rows(writer, vlan_problem_list):
    for ap in sorted(vlan_problem_list, key=lambda x: x['ip']):
        writer.writerow({
            'Conductor IP': ap.get('conductor_ip'), 'Conductor-Name': ap.get('conductor_name'),
            'AP Seriennummer': ap.get('serial'), 'AP MAC': ap.get('eth0_mac'),
            'AP IP': ap.get('ip'), 'Fehlende VLANs': ap.get('missing_vlans')
        })

def write_dns_problem_rows(writer, dns_problem_list):
    for ap in sorted(dns_problem_list, key=lambda x: x['ip']):
        writer.writerow({
            'Conductor-Name': ap.get('conductor_name'), 'AP IP-Adresse': ap.get('ip'),
            'Seriennummer': ap.get('serial'), 'DNS-Status': ap.get('dns_status')
        })


# === Hauptskript ===
if __name__ == "__main__":
    check_dependencies()

    original_stdout = sys.stdout
    log_file_handler = None
    
    epilog_text = """
Beispiele:

  # Einen einzelnen Conductor prüfen
  py ap_check.py 10.1.1.1

  # Mehrere Conductors kommasepariert prüfen
  py ap_check.py 10.1.1.1,10.2.2.2

  # Conductors aus einer CSV-Datei importieren und ein Log erstellen
  py ap_check.py --importfile C:\\pfad\\zur\\liste.csv --log

  # Gespeicherte Anmeldedaten für zwei IPs löschen
  py ap_check.py --delete-credentials 10.1.1.1,10.2.2.2
"""

    parser = argparse.ArgumentParser(
        description="Überprüft den Status von Aruba Access Points über SSH und erstellt Berichte.",
        epilog=epilog_text,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('targets', nargs='*', default=[], help="Optional: Eine oder mehrere Conductor-IPs (kommasepariert).")
    parser.add_argument('--importfile', type=str, help="Pfad zu einer CSV-Datei, aus der Conductor-IPs importiert werden sollen.")
    parser.add_argument('--log', action='store_true', help="Aktiviert das Schreiben der Konsolenausgabe in die Log-Datei im Ergebnisordner.")
    parser.add_argument('--delete-credentials', type=str, help="WERKZEUG: Löscht gespeicherte Anmeldedaten für die angegebenen IPs.")
    parser.add_argument('--delete-credentials-from-import', type=str, help="WERKZEUG: Löscht gespeicherte Anmeldedaten für alle IPs aus einer Importdatei.")
    
    args = parser.parse_args()

    if args.delete_credentials or args.delete_credentials_from_import:
        ips_to_delete = []
        if args.delete_credentials:
            ips_to_delete.extend(args.delete_credentials.split(','))
        if args.delete_credentials_from_import:
            try:
                with open(args.delete_credentials_from_import, 'r', encoding='utf-8-sig') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if ip := row.get('IP-Adresse'):
                            ips_to_delete.append(ip)
                print(f"INFO: {len(ips_to_delete)} IPs aus '{args.delete_credentials_from_import}' zum Löschen vorgemerkt.")
            except Exception as e:
                print(f"FEHLER beim Lesen der Importdatei: {e}")
                sys.exit(1)
        
        if not ips_to_delete:
            print("Keine IPs zum Löschen angegeben oder gefunden.")
            sys.exit(0)

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

    run_timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    # KOSMETISCHE ANPASSUNG: Verzeichnisname geändert
    output_dir = os.path.join(os.getcwd(), "ap_check_" + run_timestamp)
    os.makedirs(output_dir, exist_ok=True)
    
    if args.log:
        try:
            log_filename = os.path.join(output_dir, "ap_check_log.txt")
            log_file_handler = Logger(filename=log_filename)
            sys.stdout = log_file_handler
        except Exception as e:
            sys.stdout = original_stdout
            print(f"FEHLER: Log-Datei konnte nicht erstellt werden: {e}")
    
    print(f"ap_check.py Version 8.0.0 wird ausgeführt...")
    print(f"Teil der Aruba Instant Toolsammlung Version {TOOLSUITE_VERSION}")
    print(f"INFO: Ergebnisse werden im Verzeichnis '{output_dir}' gespeichert.")

    start_time = datetime.now()
    print(f"\n===== Skriptstart: {start_time.strftime('%Y-%m-%d %H:%M:%S')} =====")

    try:
        with open("config.json", 'r', encoding='utf-8') as f: config = json.load(f)
    except FileNotFoundError: print("FEHLER: config.json nicht gefunden!"); sys.exit(1)
    except json.JSONDecodeError as e: print(f"FEHLER: Die Datei config.json ist fehlerhaft: {e}"); sys.exit(1)

    cfg = {
        'timeout': config.get('timeout_seconds', 30),
        'num_threads': config.get('num_threads', 10),
        'minspeed': config.get('minspeed', 1000),
        'crccheck': config.get('crccheck', True),
        'mincrc': config.get('mincrc', 1),
        'showmac': config.get('showmac', True),
        'eth1_ignore_speed': config.get('eth1_ignore_speed', True),
        'check_ip_anomaly': config.get('check_ip_anomaly', True),
        'anomaly_gap_factor': config.get('anomaly_gap_factor', 10),
        'check_monitor_mode': config.get('check_monitor_mode', True),
        'check_power_status': config.get('check_power_status', True),
        'dns_check_host': config.get('dns_check_host', 'google.de'),
        'lang': config.get('language_terms')
    }
    if not cfg['lang']: print("FEHLER: 'language_terms' fehlt in config.json."); sys.exit(1)

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
            print("Gefundene Online-Conductors:")
            for ip in targets: print(f"- {ip}")
            if offline_targets_from_csv:
                print("\nGefundene Offline-Conductors:")
                for ip in offline_targets_from_csv: print(f"- {ip}")
                print(f"\nWARNUNG: {len(offline_targets_from_csv)} Conductor wurden in der CSV als 'Down' gemeldet.")
                print(f"Eine Überprüfung dieser Systeme wird den Lauf um bis zu {cfg['timeout']} Sekunden pro System verzögern.")
                if input("Sollen diese 'Down'-Conductor trotzdem am Ende geprüft werden? (j/n): ").lower() == 'j':
                    targets.extend(offline_targets_from_csv)
                else:
                    print("INFO: 'Down'-Conductor werden übersprungen.")
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
        
        if targets:
            print(f"INFO: Füge {len(positional_targets)} zusätzliche Ziele aus der Kommandozeile hinzu.")
        targets.extend(positional_targets)

    if not targets:
        targets = config.get('conductor_ips', [])

    if not targets:
        print("FEHLER: Keine Conductor-IPs angegeben (weder per CLI, Import noch in config.json).")
        parser.print_help()
        sys.exit(1)

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
    
    problem_csv_file = os.path.join(output_dir, "ap_errors.csv")
    offline_csv_file = os.path.join(output_dir, "ap_offline.csv")
    anomaly_csv_file = os.path.join(output_dir, "ap_ip_anomaly.csv")
    vlan_csv_file = os.path.join(output_dir, "ap_vlan_missing.csv")
    dns_csv_file = os.path.join(output_dir, "ap_dns_errors.csv")

    errors_footer = """

#### Troubleshooting Steps: ####
1. SSH to the specific AP IP address listed in the report.
2. For CRC or Speed Errors, run the following command:
   show interface
3. For Power Errors, run the following command and check the "Current Operational State":
   show ap debug system-status | include "Current Operational State"
   current possible power restrictions are:
    USB Port Disabled: The USB port is deactivated to reduce power consumption as a first step.
    Second Ethernet Port Disabled: The secondary Ethernet port (eth1) and its PoE-out capability are turned off.
    Radios in Reduced MIMO: Radio chains are reduced (e.g., from 4x4 to 2x2 MIMO) to lower WLAN power draw.
    Radio Disabled: One or more radio bands (e.g., the 2.4 GHz radio) are completely shut down.
   Please refer to manual regarding IPM for deeper investigation: https://arubanetworking.hpe.com/techdocs/Aruba-Instant-8.x-Books/810/Aruba-Instant-8.10.0.0-User-Guide.pdf
"""
    anomaly_footer = """

#### Recommended Actions for IP Anomalies: ####
- Ask the DHCP administrator to check or correct the IP reservation for the AP's MAC address.
- Ask the Firewall administrator to ensure the AP has the necessary permissions for outgoing traffic.
"""
    offline_footer = """

#### Recommended Actions for Offline APs: ####
- Physically locate and reconnect the missing Access Points to the network.
- If the APs have been permanently decommissioned, please ask the appropriate administrator (Virtual Conductor, Airwave, or Central) to remove them from the configuration. To do so, please provide them with the information from this report.
"""
    vlan_footer = """

#### Recommended Actions for Missing VLANs: ####
- Check the upstream switch port configuration for the affected AP.
- Ensure that the listed 'Missing VLANs' are configured as 'tagged' on the switch port to which the AP is connected.
- The command 'show datapath vlan' on the AP confirms which VLANs the AP is actually receiving from the switch.
"""

    with open(problem_csv_file, 'w', newline='', encoding='utf-8') as f_problem, \
         open(offline_csv_file, 'w', newline='', encoding='utf-8') as f_offline, \
         open(anomaly_csv_file, 'w', newline='', encoding='utf-8') as f_anomaly, \
         open(vlan_csv_file, 'w', newline='', encoding='utf-8') as f_vlan, \
         open(dns_csv_file, 'w', newline='', encoding='utf-8') as f_dns:

        fieldnames_problem = ['Conductor-Name', 'IP Adresse', 'Seriennummer', 'AP Typ', 'Laufzeit', 'eth0_speed', 'eth0_mac', 'eth0_errors', 'eth1_speed', 'eth1_mac', 'eth1_errors', 'crashed', 'Problem-Reason']
        fieldnames_offline = ['Conductor-Name', 'Conductor IP', 'Offline AP MAC']
        fieldnames_anomaly = ['Conductor-Name', 'AP-IP-Address', 'AP-MAC-Address', 'Anomaly-Reason']
        fieldnames_vlan = ['Conductor IP', 'Conductor-Name', 'AP Seriennummer', 'AP MAC', 'AP IP', 'Fehlende VLANs']
        fieldnames_dns = ['Conductor-Name', 'AP IP-Adresse', 'Seriennummer', 'DNS-Status']

        writer_problem = csv.DictWriter(f_problem, fieldnames=fieldnames_problem, extrasaction='ignore')
        writer_offline = csv.DictWriter(f_offline, fieldnames=fieldnames_offline, extrasaction='ignore')
        writer_anomaly = csv.DictWriter(f_anomaly, fieldnames=fieldnames_anomaly, extrasaction='ignore')
        writer_vlan = csv.DictWriter(f_vlan, fieldnames=fieldnames_vlan, extrasaction='ignore')
        writer_dns = csv.DictWriter(f_dns, fieldnames=fieldnames_dns, extrasaction='ignore')

        writer_problem.writeheader()
        writer_offline.writeheader()
        writer_anomaly.writeheader()
        writer_vlan.writeheader()
        writer_dns.writeheader()
        
        total_conductors_checked = 0
        total_aps_checked = 0
        failed_auth_ips = {}

        for i, conductor_ip in enumerate(targets):
            creds = credentials_store.get(conductor_ip)
            if not creds:
                with print_lock: print(f"WARNUNG: Keine validen Anmeldedaten für {conductor_ip} vorhanden. Überspringe...")
                continue
            
            user, password = creds['user'], creds['pass']

            aps_to_check, provisioned_macs, conductor_name, required_vlans, reason = get_conductor_data(conductor_ip, user, password, cfg['timeout'], cfg['lang'])
            
            if reason != "success":
                if reason == "auth_error":
                    failed_auth_ips[conductor_ip] = user
                continue
            
            try:
                temp_client = paramiko.SSHClient()
                temp_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                temp_client.connect(conductor_ip, username=user, password=password, timeout=cfg['timeout'])
                dns_output = execute_command_on_shell(temp_client, "show summary support | include NameServer")
                dns_match = re.search(r"NameServer\s+:\s*([\d\.]+)", dns_output)
                if dns_match:
                    with print_lock:
                        print(f"INFO: Conductor '{conductor_name}' ({conductor_ip}) verwendet DNS-Server: {dns_match.group(1).strip()}")
                temp_client.close()
            except Exception as e:
                with print_lock:
                    print(f"WARNUNG: DNS-Server für Conductor {conductor_ip} konnte nicht ermittelt werden: {e}")

            
            total_conductors_checked += 1
            if aps_to_check:
                total_aps_checked += len(aps_to_check)

            if aps_to_check:
                task_queue, all_results_queue, online_mac_queue = Queue(), Queue(), Queue()
                threads = []
                for _ in range(cfg['num_threads']):
                    thread = threading.Thread(target=worker, args=(task_queue, all_results_queue, online_mac_queue, user, password, cfg['timeout'], cfg))
                    thread.start()
                    threads.append(thread)
                
                sorted_ips = sorted(aps_to_check.keys(), key=lambda ip: [int(octet) for octet in ip.split('.')])
                
                for ip in sorted_ips:
                    info = aps_to_check[ip]
                    task_queue.put((ip, info))

                task_queue.join()
                for _ in range(cfg['num_threads']): task_queue.put(None)
                for thread in threads: thread.join()

                all_online_ap_details = [all_results_queue.get() for _ in range(all_results_queue.qsize())]
                
                anomaly_aps_conductor = find_ip_anomalies(conductor_ip, all_online_ap_details, cfg['anomaly_gap_factor']) if cfg['check_ip_anomaly'] else []
                
                problem_aps_conductor = []
                vlan_problem_aps_conductor = []
                dns_problem_aps_conductor = []
                problem_counts = {'speed': 0, 'crc': 0, 'monitor': 0, 'power': 0, 'crashed': 0, 'vlan': 0, 'dns': 0}

                for ap_details in all_online_ap_details:
                    problem_reasons = []
                    
                    if ap_details['crashed'] == "X":
                        problem_reasons.append("AP crashed")
                        problem_counts['crashed'] += 1
                    if cfg['crccheck'] and ap_details['eth0_errors'] >= cfg['mincrc']:
                        problem_reasons.append(f"eth0 CRC errors: {ap_details['eth0_errors']}")
                        problem_counts['crc'] += 1
                    if cfg['crccheck'] and ap_details['eth1_errors'] >= cfg['mincrc']:
                         problem_reasons.append(f"eth1 CRC errors: {ap_details['eth1_errors']}")
                         problem_counts['crc'] += 1
                    if parse_speed(ap_details['eth0_speed']) < cfg['minspeed']:
                        problem_reasons.append(f"eth0 speed low: {ap_details['eth0_speed']}")
                        problem_counts['speed'] += 1
                    if not cfg['eth1_ignore_speed'] and parse_speed(ap_details['eth1_speed']) < cfg['minspeed'] and ap_details['eth1_speed'] != "N/A":
                        problem_reasons.append(f"eth1 speed low: {ap_details['eth1_speed']}")
                        problem_counts['speed'] += 1
                    if cfg['check_monitor_mode'] and ap_details.get('mode') == 'monitor':
                        problem_reasons.append("Monitor mode active")
                        problem_counts['monitor'] += 1
                    
                    power_status = ap_details.get('power_status', 'N/A').strip()
                    if cfg['check_power_status'] and power_status != 'N/A' and not power_status.startswith('No restrictions'):
                        problem_reasons.append(f"Power status: {power_status}")
                        problem_counts['power'] += 1
                    
                    active_ap_vlans = ap_details.get('active_vlans', set())
                    missing_vlans = required_vlans - active_ap_vlans
                    if missing_vlans:
                        problem_counts['vlan'] += 1
                        vlan_ap_info = ap_details.copy()
                        vlan_ap_info['conductor_ip'] = conductor_ip
                        vlan_ap_info['conductor_name'] = conductor_name
                        vlan_ap_info['missing_vlans'] = ", ".join(map(str, sorted(list(missing_vlans))))
                        vlan_problem_aps_conductor.append(vlan_ap_info)
                    
                    if ap_details.get('dns_status', 'OK') != 'OK':
                        problem_counts['dns'] += 1
                        dns_ap_info = ap_details.copy()
                        dns_ap_info['conductor_name'] = conductor_name
                        dns_problem_aps_conductor.append(dns_ap_info)

                    if problem_reasons:
                        ap_details['conductor_name'] = conductor_name
                        ap_details['problem_reason'] = ", ".join(problem_reasons)
                        problem_aps_conductor.append(ap_details)
                
                found_online_macs = set()
                while not online_mac_queue.empty():
                    mac = online_mac_queue.get()
                    if mac: found_online_macs.add(mac.lower())
                
                offline_macs_set = provisioned_macs - found_online_macs
                offline_aps_conductor = [{'conductor_name': conductor_name, 'conductor_ip': conductor_ip, 'mac': mac} for mac in sorted(list(offline_macs_set))] if offline_macs_set else []

                if problem_aps_conductor: write_problem_ap_rows(writer_problem, problem_aps_conductor)
                if offline_aps_conductor: write_offline_ap_rows(writer_offline, offline_aps_conductor)
                if vlan_problem_aps_conductor: write_vlan_problem_rows(writer_vlan, vlan_problem_aps_conductor)
                if dns_problem_aps_conductor: write_dns_problem_rows(writer_dns, dns_problem_aps_conductor)
                if anomaly_aps_conductor:
                    for anom_ap in anomaly_aps_conductor:
                        writer_anomaly.writerow({'Conductor-Name': conductor_name, 'AP-IP-Address': anom_ap['ip'], 'AP-MAC-Address': anom_ap['eth0_mac'], 'Anomaly-Reason': anom_ap.get('reason', 'Unbekannt')})

                with print_lock:
                    print(f"\n--- Zusammenfassung für Conductor: {conductor_name} ({conductor_ip}) ---")
                    if problem_aps_conductor:
                        details = []
                        if problem_counts['crashed'] > 0: details.append(f"{problem_counts['crashed']}x Gecrasht")
                        if problem_counts['speed'] > 0: details.append(f"{problem_counts['speed']}x Geschw.")
                        if problem_counts['crc'] > 0: details.append(f"{problem_counts['crc']}x CRC Fehler")
                        if problem_counts['monitor'] > 0: details.append(f"{problem_counts['monitor']}x Monitor-Modus")
                        if problem_counts['power'] > 0: details.append(f"{problem_counts['power']}x Stromversorgung")
                        summary_details = ", ".join(details)
                        print(f"WARNUNG: {len(problem_aps_conductor)} AP(s) mit allgemeinen Problemen gefunden (davon: {summary_details}).")
                    else:
                        print(f"INFO: Keine allgemeinen AP-Probleme gefunden.")

                    if vlan_problem_aps_conductor: print(f"WARNUNG: {len(vlan_problem_aps_conductor)} AP(s) mit fehlenden VLANs gefunden.")
                    else: print(f"INFO: Keine VLAN-Probleme gefunden.")
                    
                    if offline_aps_conductor: print(f"WARNUNG: {len(offline_aps_conductor)} Offline-AP(s) gefunden.")
                    else: print(f"INFO: Keine Offline-APs gefunden.")
                    
                    if anomaly_aps_conductor: print(f"WARNUNG: {len(anomaly_aps_conductor)} IP-Anomalie(n) gefunden.")
                    else: print(f"INFO: Keine IP-Anomalien gefunden.")
                    
                    if dns_problem_aps_conductor: print(f"WARNUNG: {len(dns_problem_aps_conductor)} AP(s) mit DNS-Problemen gefunden.")
                    else: print(f"INFO: Keine DNS-Probleme gefunden.")
                    
                    print(f"--- Ende Abfrage für Conductor: {conductor_ip} ---")
        
        f_problem.write(errors_footer)
        f_anomaly.write(anomaly_footer)
        f_offline.write(offline_footer)
        f_vlan.write(vlan_footer)
        f_dns.write("\n\n#### Mögliche Ursachen für DNS-Fehler: ####\n- Firewall blockiert DNS-Anfragen (Port 53/udp) vom AP-Subnetz.\n- Falscher DNS-Server per DHCP zugewiesen.\n- Netzwerk-Konnektivitätsproblem zwischen AP und DNS-Server.")


    end_time = datetime.now()
    total_duration = end_time - start_time
    print(f"\n===== Skriptende: {end_time.strftime('%Y-%m-%d %H:%M:%S')} =====")
    print(f"Gesamtdauer: {str(total_duration).split('.')[0]}")
    print(f"{total_aps_checked} Access Points bei {total_conductors_checked} Conductors geprüft.")
    if total_aps_checked > 0:
        time_per_ap = total_duration.total_seconds() / total_aps_checked
        print(f"Durchschnittliche Zeit pro AP: {time_per_ap:.2f} Sekunden")

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
### Hier ist das Ende ###