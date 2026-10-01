# Aruba Instant Python Tools

> [!WARNING]
> **Privates Hobbyprojekt – nicht gepflegt / unmaintained.**
> Dieses Repository ist für meinen eigenen Gebrauch gedacht und wird nur aus Bequemlichkeit öffentlich bereitgestellt.
>
> * **Keine Unterstützung:** Issues und Pull Requests werden nicht bearbeitet, Feature-Wünsche nicht umgesetzt. Bitte keine Issues eröffnen.
> * **Keine Garantie:** Bereitstellung „wie besehen“, ohne jede Gewährleistung und Haftung. Nutzung auf eigenes Risiko; Ergebnisse müssen selbst geprüft werden.
> * **Eigene Umgebung:** Entwickelt und getestet nur in meiner eigenen Umgebung (Windows, Python 3, Aruba Instant 8.10.0.x). In anderen Umgebungen oder mit anderer Firmware kann es fehlschlagen.
> * **Produktive Eingriffe:** `ap_swarm_reload.py`, `ap_swarm_update.py` und `ap_offline_delete.py` **verändern Konfiguration bzw. starten Schwärme neu** und können produktive WLANs lahmlegen. Nur mit Bedacht und nie ungeprüft gegen fremde oder produktive Systeme einsetzen.
> * **Zugangsdaten & Netzwerk:** Die Tools melden sich per SSH an Conductors und Access Points an. Der SSH-Host-Key wird **nicht geprüft** (`AutoAddPolicy`), ein Man-in-the-Middle ist daher nicht ausgeschlossen. Zugangsdaten können im Windows-Anmeldeinformationsspeicher (Keyring) oder in der Datei `credentials.bin` gespeichert werden – siehe Abschnitt [Zugangsdaten](#zugangsdaten--credentialsbin). **Lies den Code, bevor du ihn einsetzt.**
> * **Keine Updates zugesichert:** Es kann jederzeit ohne Ankündigung Änderungen, Brüche oder die Löschung des Repos geben. Gern selbst forken und anpassen.
>
> *Private hobby project, unmaintained, provided as-is. No support, no issues, no warranty. Fork it if you like.*

> **Skript-Suite (Toolsuite 2.0.0) zur Prüfung, Auswertung und Verwaltung von Aruba Instant Virtual Conductors und Swarms**

Die Suite spricht per SSH mit Aruba Instant Virtual Conductors (VC) bzw. Access Points, führt threaded Abfragen aus und erzeugt Berichte (Konsole, Log, CSV).

**Getestet:** Aruba InstantOS 8.10.0.16 bis 8.10.0.23 auf verschiedenen AP-Modellen. **Kompatibilität:** Instant 8.10.0.0 bis 8.10.0.23.

---

## Zugangsdaten / `credentials.bin`

> [!CAUTION]
> Beim ersten Lauf fragen die Tools nach Zugangsdaten und bieten an, diese zu speichern. Du hast zwei Möglichkeiten:
>
> * **Keyring (empfohlen):** Windows-Anmeldeinformationsverwaltung über die Bibliothek `keyring`.
> * **Datei `credentials.bin`:** Passwörter werden **im aktuellen Arbeitsverzeichnis** abgelegt. Die Verschlüsselung ist **nur ein Basisschutz** – der Schlüssel wird aus der MAC-Adresse des Rechners abgeleitet, der Salt ist im Code fest hinterlegt. Das ist **kein sicherer Tresor**: Wer die Datei und Zugriff auf denselben Rechner hat, kann die Passwörter auslesen.
>
> **`credentials.bin` niemals weitergeben, in Git einchecken oder in Cloud-/Backup-Ordnern ablegen.** Die mitgelieferte `.gitignore` schließt sie aus; prüfe trotzdem vor jedem Commit mit `git status`.
> Gespeicherte Zugangsdaten lassen sich mit `--delete-credentials <IP>` (bei den Tools, die das anbieten) wieder entfernen.

---

## Bestandteile

| Datei | Version | Zweck |
| :--- | :--- | :--- |
| `aruba_helper.py` | 1.0.7 | Zentrale Bibliothek: SSH (Paramiko), Zugangsdaten (Keyring / `credentials.bin`), Logging, Threads |
| `ap_check.py` | 8.0.0 | Prüft APs: Gigabit-Anbindung, CRC-Fehler, Duplex, PoE-/Stromstatus, DNS, Monitor-Modus, IP-Auffälligkeiten; fehlerhafte APs als CSV |
| `ap_list.py` | 1.0.4 | AP-Inventar (IP, MAC, Seriennummer, Teilenummer; optional AP-Name oder GreenLake-/Central-Importformat) |
| `ap_bss_list.py` | 1.0.2 | BSSID-Liste (ESS, BSS, MAC, Name) |
| `swarm_dns_check.py` | 1.0.0 | Prüft die DNS-Auflösung einer Domain auf den Conductors (`--checkurl`) |
| `ap_findlog.py` | 1.0.0 | Durchsucht Protokolle (z. B. `system`, `security`, `kernel`, `dhcp`) auf Conductors und optional allen Member-APs nach Text oder Regex |
| `ap_show.py` | 1.1.0 | Führt beliebige **`show`-Befehle** auf Conductors und optional allen Member-APs aus (nur lesend, modifizierende Befehle werden abgewiesen) |
| `ap_swarm_reload.py` | 1.0.d | ⚠️ **Startet Swarms neu** |
| `ap_swarm_update.py` | 4.1.0 | ⚠️ **Firmware-Update** von Swarms per CLI (`-f <URL>`) |
| `ap_offline_delete.py` | 1.3.0 | ⚠️ **Löscht** offline APs aus der Provisionierungsliste (per CSV) |
| `config.json` | – | Schwellenwerte, Threads, Timeouts, optionale Standard-Conductor-IPs |
| `apparts.json` | – | Übersetzung AP-Modell → Teilenummer (SKU) |
| `requirements.txt` | – | Python-Abhängigkeiten |

Lesende Tools (`ap_check`, `ap_list`, `ap_bss_list`, `swarm_dns_check`, `ap_findlog`, `ap_show`) verändern nichts an den Geräten. Schreibende Tools sind mit ⚠️ markiert.

---

## Installation

### Windows (Schnellstart mit `setup.bat`)

Für Windows-Anwender ohne Git gibt es ein Setup-Skript. Es prüft, ob **Python 3.9 oder neuer** vorhanden ist, und installiert bei Bedarf Python 3.12 von python.org (nur für den aktuellen Benutzer, **ohne Administratorrechte**, mit PATH-Eintrag; die Signatur des Installers wird geprüft). Danach lädt es die Toolsammlung von GitHub in einen Ordner deiner Wahl (Standard: `%USERPROFILE%\ArubaInstantTools`), richtet eine virtuelle Python-Umgebung mit allen Bibliotheken ein und legt eine Desktop-Verknüpfung an.

1. `setup.bat` herunterladen – entweder auf GitHub **Code → Download ZIP** und entpacken, oder in einer Eingabeaufforderung:
   ```bat
   curl.exe -L -o setup.bat https://raw.githubusercontent.com/joeMJ/aruba-instant-python-tools/main/setup.bat
   ```
2. `setup.bat` per Doppelklick starten (Windows SmartScreen ggf. mit „Weitere Informationen → Trotzdem ausführen“ bestätigen) und den Anweisungen folgen.
3. Danach über die Desktop-Verknüpfung **„Aruba Instant Tools“** (bzw. `start-tools.bat` im Installationsordner) eine Eingabeaufforderung im Tool-Ordner öffnen, z. B. `py ap_check.py 10.1.1.1 --log`.

Der Installationsordner ist zugleich der **Arbeitsordner**: Hier liegen `config.json` und alle Logs und Ergebnisordner (er muss für den Benutzer beschreibbar sein). Ein erneuter Aufruf von `setup.bat` aktualisiert die Tools; `config.json`, Logs und gespeicherte Zugangsdaten bleiben erhalten (eine neue Vorlage liegt dann als `config.json.neu` daneben).

> [!NOTE]
> `setup.bat` lädt Dateien aus dem Internet (Python-Installer von python.org, Toolsammlung von GitHub) und führt sie aus. Es ist nur wenig getestet – **lies das Skript, bevor du es startest**. Wer das nicht möchte, installiert Python manuell von [python.org](https://www.python.org/downloads/windows/) (Haken bei „Add python.exe to PATH“) und folgt der Anleitung unten.

### Manuell (alle Systeme)


**Voraussetzungen:** Python 3 (unter Windows von python.org, mit PATH-Eintrag), SSH-Zugriff auf die Conductors.

```bash
git clone https://github.com/joeMJ/aruba-instant-python-tools.git
cd aruba-instant-python-tools
pip install -r requirements.txt
```

**Genutzte Bibliotheken:** `paramiko` (SSH, auch ältere Cipher-Suites), `keyring` (Windows-Anmeldespeicher), `pycryptodome` (Verschlüsselung der `credentials.bin`), `requests` und `beautifulsoup4` (Firmware-Verzeichnis bei `ap_swarm_update.py`).

---

## Konfiguration (`config.json`)

| Schlüssel | Bedeutung | Standard |
| :--- | :--- | :--- |
| `conductor_ips` | Master-AP- bzw. VC-Adressen, falls keine IP per Kommandozeile oder Import übergeben wird (**Demo-Werte, anpassen**) | – |
| `timeout_seconds` | Wartezeit für Verbindungen | 30 |
| `num_threads` | Parallele AP-Prüfungen | 10 |
| `minspeed` | Mindestgeschwindigkeit eth0 in Mb/s | 1000 |
| `mincrc` | Maximal tolerierte CRC-Fehler | 100 |
| `eth1_ignore_speed` | Geschwindigkeit von eth1 nicht prüfen | `true` |
| `crccheck`, `check_monitor_mode`, `check_power_status`, `check_ip_anomaly` | Prüfroutinen ein-/ausschalten | `true` |
| `language_terms` | Nur ändern, wenn die APs nicht auf Englisch eingestellt sind | – |

---

## Beispiele

```bash
py ap_check.py 10.1.1.1
py ap_check.py 10.1.1.1,10.2.2.2 --log
py ap_check.py --importfile C:\pfad\zur\liste.csv --log
py ap_list.py 10.1.1.1 --apname
py ap_list.py 10.1.1.1 --greenlake
py ap_show.py 10.1.1.1 -c "version" --memberaps
py ap_findlog.py 10.1.1.1 system "dhcp" --memberaps
py swarm_dns_check.py 10.1.1.1 --checkurl example.org
py ap_check.py --help
```

**Import-CSV (`--importfile`):** Eine CSV mit Kopfzeile und einer Spalte `IP-Adresse` mit den Conductor-IPs (`ap_show.py` und `ap_findlog.py` erkennen zusätzlich `ipadresse` und `ip`). Optional werten die Tools weitere Spalten aus: `Typ` (`ap_check.py`, `ap_list.py`, `ap_bss_list.py`; nur Zeilen mit `Aruba Instant Virtual Controller` werden verwendet) und `Status` (zusätzlich `swarm_dns_check.py` und `ap_swarm_update.py`; `down` wird als offline behandelt) – das entspricht dem Export einer Netzwerkmanagement-Konsole. `ap_swarm_reload.py` liest nur `IP-Adresse`. Die von `ap_list.py` erzeugte CSV (Spalte `AP-IP-Adresse`) ist **kein** passendes Importformat.

**Ausgaben:** Mit `--log` entstehen Ergebnisordner mit Logdateien und CSVs im Arbeitsverzeichnis (z. B. `ap_check_<Zeitstempel>/`).

Details zu allen Optionen: `--help` des jeweiligen Tools und Quelltext.

---

## Hinweise

* **Nur gegen Systeme einsetzen, für die du berechtigt bist.**
* Alle Skripte wurden für Aruba **Instant 8.10.x** geschrieben; die CLI-Ausgaben werden per Textmuster ausgewertet und können bei anderer Firmware abweichen.
* Eine Versionshistorie wird hier nicht geführt.

---

## Lizenz

[Apache License 2.0](LICENSE) – Copyright 2025-2026 John Lose · [johnlose.de](https://www.johnlose.de/aruba-instant-python-tools/)
