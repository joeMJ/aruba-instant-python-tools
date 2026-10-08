### Aruba Instant Python Tools
### ap_ssid_rule.py - Ergänzt eine Firewall-Regel (Zugriffsregel) in Swarms mit passender SSID (Scan, Plan, Anwenden, Prüfen, Rollback)
### Version 1.4.1
### Bestandteil der Aruba Instant Python Tools Suite V 2.0.0
### gemacht mit viel Liebe von John (johnlose.de)

# Ablauf (jeder Schritt ist einzeln aufrufbar):
#   1. SCAN/PLAN (nur lesend, Standard): findet nicht von AirWave/Central verwaltete Swarms mit passender SSID,
#      sichert die betroffenen Regelblöcke als Textdatei und schreibt einen Plan (plan.json) inkl. Rollback-Befehlen.
#   2. --apply <plan.json>: führt den Plan aus (je VC Rückfrage), liest danach zurück und prüft; bei Abweichung
#      automatischer Rollback.
#   3. --verify <plan.json>: nur prüfen, ob die Regel (noch) wie geplant vorhanden ist.
#   4. --rollback <plan.json>: nimmt die ergänzte Regel wieder heraus und prüft den Ausgangszustand.
# Die neuen Regeln (--rule, mehrfach möglich) werden in der angegebenen Reihenfolge direkt VOR der letzten Regel
# (Abschluss 'deny any') eingefügt. Bereits vorhandene Regeln werden nicht doppelt angelegt.

import paramiko
import re
import csv
import sys
import time
import json
import os
import fnmatch
import threading
import argparse
from queue import Queue
from datetime import datetime

from aruba_helper import (
    SCRIPT_VERSION as HELPER_VERSION, check_dependencies, Logger, get_saved_credentials,
    validate_credentials, get_credentials_interactively, save_credential,
    execute_command_on_shell,
    KEYRING_AVAILABLE, CRYPTO_AVAILABLE
)

AP_SSID_RULE_VERSION = "1.4.1"
TOOLSUITE_VERSION = "2.0.0"
print_lock = threading.Lock()

# Der VC bricht lange Eingaben ab ('history buffer full' nach ca. 75 Befehlen je Sitzung)
MAX_CMDS_PER_SESSION = 40
FINAL_RULE_RE = re.compile(r"^rule any any match any any any deny( log)?$")
BAD_OUTPUT_RE = re.compile(r"(?i)\berror\b|invalid|incomplete|not found|unrecogni|cannot|could not|history buffer|%")

# Statuswerte im Scan
ST_TREFFER = "TREFFER"
ST_KEIN = "KEIN_TREFFER"
ST_AIRWAVE = "AIRWAVE"
ST_CENTRAL = "CENTRAL"
ST_NORULE = "KEINE_ZUGRIFFSREGEL"
ST_ABSCHLUSS = "ABSCHLUSS_UNERWARTET"
ST_VORHANDEN = "REGEL_VORHANDEN"
ST_FEHLER = "FEHLER"


def norm(line):
    return " ".join(line.split())


ACTION_RE = re.compile(r"^(rule .+? (?:permit|deny|src-nat|dst-nat))(?: .*)?$")


def no_form(rule):
    """Befehl zum Entfernen einer Regel: ohne Optionen hinter der Aktion (z. B. ohne 'log')."""
    m = ACTION_RE.match(norm(rule))
    return "no " + (m.group(1) if m else norm(rule))


def log(msg):
    with print_lock:
        print(msg)


# ---------------------------------------------------------------- Konfiguration auswerten
def parse_config(text):
    """Liest SSID-Profile und Zugriffsregeln aus 'show running-config'."""
    ssids, rules, order = [], {}, []
    cur_kind, cur_name, cur_essid = None, None, None
    for raw in text.splitlines():
        line = raw.rstrip()
        if line and not line[0].isspace():
            if cur_kind == "ssid" and cur_name is not None:
                ssids.append({"profile": cur_name, "essid": cur_essid})
            cur_kind, cur_name, cur_essid = None, None, None
            if line.startswith("wlan ssid-profile "):
                cur_kind, cur_name, cur_essid = "ssid", line[len("wlan ssid-profile "):].strip(), None
            elif line.startswith("wlan access-rule "):
                cur_kind, cur_name = "rule", line[len("wlan access-rule "):].strip()
                rules[cur_name] = []
                order.append(cur_name)
            continue
        s = line.strip()
        if cur_kind == "ssid" and s.startswith("essid "):
            cur_essid = s[len("essid "):].strip()
        elif cur_kind == "rule" and s.startswith("rule "):
            rules[cur_name].append(s)
    if cur_kind == "ssid" and cur_name is not None:
        ssids.append({"profile": cur_name, "essid": cur_essid})
    awx = bool(re.search(r"^ams-ip\s+\S+", text, re.MULTILINE))
    return {"ssids": ssids, "rules": rules, "airwave_marker": awx}


def summary_info(summary_out):
    """Liest die Verwaltungsangaben aus 'show summary' (Roh-Textwerte)."""
    def field(label):
        m = re.search(r"^" + label + r"\s*:\s*(.*)$", summary_out, re.MULTILINE)
        return m.group(1).strip() if m else ""
    return {"managed_via": field("Managed Via"), "central": field("Aruba Central"), "airwave": field("Airwave")}


def detect_management(summary_out, airwave_marker):
    """'Airwave', 'cop 2.0' oder 'john' (nicht von AirWave/Central verwaltet).
    Central gilt nur als verwaltet, wenn 'Aruba Central' den Status 'Connected' hat. Ein eingetragener, aber
    nicht verbundener Central-Server ('Managed Via: Aruba Central' + 'Not Connected') zählt NICHT als verwaltet."""
    info = summary_info(summary_out)
    mv, ac, aw = info["managed_via"].lower(), info["central"].lower(), info["airwave"].lower()
    if ac == 'connected' and 'central' in mv:
        return 'cop 2.0'   # Central verbunden und als Verwalter eingetragen (auch wenn noch ein alter ams-ip-Eintrag existiert)
    if airwave_marker or aw == 'connected' or ('airwave' in mv and aw not in ('', 'not set up', 'not connected')):
        return 'Airwave'
    if ac == 'connected':
        return 'cop 2.0'
    return 'john'


def ssid_matches(essid, args):
    if not essid:
        return False
    if args.ssid_regex:
        return re.fullmatch(args.ssid_regex, essid, re.IGNORECASE) is not None
    return fnmatch.fnmatchcase(essid.lower(), args.ssid.lower())


def build_items(ip, name, managed, cfg, new_rules, args):
    """Erzeugt je passender Zugriffsregel einen Planeintrag (ohne Verbindung, rein rechnerisch)."""
    si = cfg.get("summary_info", {})
    base = {"ip": ip, "conductorname": name, "managedby": managed,
            "managed_via": si.get("managed_via", ""), "central_status": si.get("central", "")}
    central_ohne = si.get("managed_via", "").lower().find("central") >= 0 and si.get("central", "").lower() != "connected"
    base["note"] = "Managed Via Aruba Central, aber Central NICHT verbunden" if central_ohne else ""
    if managed == "Airwave":
        return [dict(base, status=ST_AIRWAVE, ssid="", rule_name="", hinweis="von AirWave verwaltet")]
    if managed != "john":
        return [dict(base, status=ST_CENTRAL, ssid="", rule_name="", hinweis="von Central verwaltet")]
    hits = [s for s in cfg["ssids"] if ssid_matches(s["essid"], args)]
    if not hits:
        return [dict(base, status=ST_KEIN, ssid="", rule_name="", hinweis="")]
    items, done = [], set()
    for s in hits:
        rname = s["profile"]
        item = dict(base, ssid=s["essid"], rule_name=rname)
        if rname in done:
            continue
        done.add(rname)
        before = cfg["rules"].get(rname)
        if before is None:
            items.append(dict(item, status=ST_NORULE, hinweis="keine Zugriffsregel gleichen Namens"))
            continue
        item["before"] = before
        existing = {norm(l) for l in before}
        missing = [r for r in new_rules if norm(r) not in existing]
        if not missing:
            items.append(dict(item, status=ST_VORHANDEN, hinweis="alle Regeln schon vorhanden"))
            continue
        if not before or not FINAL_RULE_RE.match(norm(before[-1])):
            items.append(dict(item, status=ST_ABSCHLUSS, hinweis=f"letzte Regel: {before[-1] if before else '(leer)'}"))
            continue
        last = before[-1]
        # Die 'no'-Form (ohne Optionen) muss eindeutig genau diese eine Regel treffen
        if sum(1 for l in before if no_form(l) == no_form(last)) != 1:
            items.append(dict(item, status=ST_ABSCHLUSS, hinweis="Entfernen des Abschlusses wäre nicht eindeutig (gleiche Regel mehrfach, z. B. mit und ohne log)"))
            continue
        item.update(
            status=ST_TREFFER,
            hinweis=(base["note"] + "; " if base["note"] else "") + ("" if len(missing) == len(new_rules) else f"{len(new_rules) - len(missing)} Regel(n) schon vorhanden, ergänzt werden {len(missing)}"),
            new=missing,
            after=before[:-1] + missing + [last],
            commands=[f"wlan access-rule {rname}", no_form(last)] + missing + [last, "exit"],
            rollback=[f"wlan access-rule {rname}"] + [no_form(r) for r in missing] + ["exit"],
        )
        items.append(item)
    return items


# ---------------------------------------------------------------- SSH
def connect(ip, creds, timeout):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(ip, username=creds['user'], password=creds['pass'], timeout=timeout,
              look_for_keys=False, allow_agent=False)
    return c


def read_state(client):
    summary = execute_command_on_shell(client, "show summary")
    cfg_text = execute_command_on_shell(client, "show running-config")
    cfg = parse_config(cfg_text)
    name = ""
    if m := re.search(r"^Name\s+:\s*(\S+)", summary, re.MULTILINE):
        name = m.group(1).strip()
    cfg["summary_info"] = summary_info(summary)
    return name, detect_management(summary, cfg["airwave_marker"]), cfg


def run_config_session(client, lines):
    """Gibt die Befehle in EINER Konfigurationssitzung ein und wendet sie mit 'commit apply' an.
    Bei jeder Fehlermeldung des VC: 'commit revert' und Abbruch."""
    if len(lines) > MAX_CMDS_PER_SESSION:
        return False, [f"zu viele Befehle für eine Sitzung ({len(lines)} > {MAX_CMDS_PER_SESSION})"]
    ch = client.invoke_shell(width=250)
    time.sleep(1.5)
    ch.recv(65535)

    def send(cmd, wait=0.4):
        ch.send(cmd + chr(10))
        time.sleep(wait)
        out = b''
        while ch.recv_ready():
            out += ch.recv(65535)
            time.sleep(0.05)
        text = out.decode('utf-8', 'replace')
        return text.replace(cmd, '', 1)

    errs = []
    try:
        send("no paging")
        for cmd in ["configure terminal"] + lines + ["end"]:
            o = send(cmd)
            if BAD_OUTPUT_RE.search(o):
                errs.append(f"{cmd} -> {' '.join(o.split())[-160:]}")
                break
        if errs:
            send("commit revert", 3)
            return False, errs
        o = send("commit apply", 10)
        if "committed" not in o.lower():
            return False, [f"commit apply ohne Bestätigung: {' '.join(o.split())[-160:]}"]
        return True, []
    finally:
        ch.close()


# ---------------------------------------------------------------- Zugangsdaten (wie die anderen Tools)
CRED_WARNUNG = (
    "\nWARNUNG - Zugangsdaten speichern\n"
    "  * Passwörter werden in der Datei 'credentials.bin' im aktuellen Verzeichnis abgelegt.\n"
    "  * Die Verschlüsselung ist nur ein Basisschutz (Schlüssel aus der MAC-Adresse dieses\n"
    "    Rechners, fester Salt) und KEIN sicherer Tresor: Wer die Datei und Zugriff auf diesen\n"
    "    Rechner hat, kann die Passwörter auslesen.\n"
    "  * Datei niemals weitergeben, in Git einchecken oder in Cloud-/Backup-Ordnern ablegen.\n"
    "  * Sicherer: Windows-Anmeldeinformationsverwaltung (Keyring).\n")


def collect_credentials(target_ips, timeout):
    cfg = {'storage_method': 'none'}
    storage_choice = 'none'
    print("\n--- Konfiguration der Anmeldedaten ---")
    if KEYRING_AVAILABLE:
        choice = input(
            "Soll der Anmeldespeicher des Betriebssystems verwendet werden? (Empfohlen)\n"
            "[1] Ja\n"
            "[2] Nein, lokal mit PyCryptodome verschlüsselt speichern\n"
            "[3] Nein, bei jedem Start manuell eingeben\n"
            "-----------------------------------------------------------\n"
            "Dokumentation Keyring unter https://github.com/jaraco/keyring\n"
            "Dokumentation PyCryptodome unter https://www.pycryptodome.org/\n"
            "-----------------------------------------------------------\n"
            "Ihre Wahl: ")
        if choice == '1':
            storage_choice = 'keyring'
        elif choice == '2':
            if CRYPTO_AVAILABLE:
                print(CRED_WARNUNG)
                if input("Anmeldedaten trotzdem in 'credentials.bin' speichern? (j/n): ").lower() == 'j':
                    storage_choice = 'file'
            else:
                print("HINWEIS: 'pycryptodome' nicht installiert, Fallback auf manuelle Eingabe.")
    elif CRYPTO_AVAILABLE:
        print(CRED_WARNUNG)
        if input("Anmeldedaten trotzdem in 'credentials.bin' speichern? (j/n): ").lower() == 'j':
            storage_choice = 'file'
    cfg['storage_method'] = storage_choice

    store = {}
    missing = list(set(target_ips))
    print("\n--- Pre-Flight Check: Prüfe gespeicherte Anmeldedaten ---")
    pre_user = input("Bitte den zu prüfenden SSH-Benutzernamen eingeben: ") if storage_choice == 'keyring' else None
    for ip in list(missing):
        user, pw = get_saved_credentials(ip, cfg, pre_user)
        if user and pw:
            store[ip] = {'user': user, 'pass': pw}
            missing.remove(ip)
    if missing:
        print(f"\nHINWEIS: Für {len(missing)} von {len(set(target_ips))} Zielen fehlen Anmeldedaten.")
        same = len(missing) > 1 and input("Sind die fehlenden Anmeldedaten für alle diese Ziele identisch? (j/n): ").lower() == 'j'
        if same:
            while True:
                user, pw = get_credentials_interactively()
                if validate_credentials(missing[0], user, pw, timeout):
                    if storage_choice != 'none' and input("Sollen diese Daten für alle fehlenden Ziele gespeichert werden? (j/n): ").lower() == 'j':
                        for ip in missing:
                            save_credential(ip, user, pw, cfg)
                    for ip in missing:
                        store[ip] = {'user': user, 'pass': pw}
                    break
                if input("Erneut versuchen? (j/n): ").lower() != 'j':
                    sys.exit("Aktion abgebrochen.")
        else:
            for ip in missing:
                print(f"\nBitte geben Sie die Anmeldedaten für {ip} ein.")
                while True:
                    user, pw = get_credentials_interactively()
                    if validate_credentials(ip, user, pw, timeout):
                        if storage_choice != 'none' and input(f"Sollen die Daten für {ip} gespeichert werden? (j/n): ").lower() == 'j':
                            save_credential(ip, user, pw, cfg)
                        store[ip] = {'user': user, 'pass': pw}
                        break
                    if input("Erneut versuchen? (j/n): ").lower() != 'j':
                        sys.exit("Aktion abgebrochen.")
    return store


# ---------------------------------------------------------------- Scan / Plan
def scan_worker(queue, results, creds_store, timeout, new_rules, args):
    while True:
        t = queue.get()
        if t is None:
            break
        ip = t['ip']
        try:
            client = connect(ip, creds_store.get(ip, {'user': 'admin', 'pass': ''}), timeout)
            try:
                name, managed, cfg = read_state(client)
            finally:
                client.close()
            items = build_items(ip, name or t.get('conductorname', ''), managed, cfg, new_rules, args)
            for it in items:
                it.setdefault("standortnummer", t.get("standortnummer", ""))
            results.extend(items)
            hits = [i for i in items if i['status'] == ST_TREFFER]
            log(f"[{'✓' if hits else '-'}] {ip} ({name or t.get('conductorname', '')}): {managed} -> " +
                (", ".join(f"{i['ssid']}:{i['status']}" for i in items)))
        except Exception as e:
            results.append({"ip": ip, "conductorname": t.get('conductorname', ''), "managedby": "", "ssid": "",
                            "rule_name": "", "status": ST_FEHLER, "hinweis": str(e)[:120],
                            "standortnummer": t.get("standortnummer", "")})
            log(f"[✗] {ip}: {e}")
        queue.task_done()


def write_text(path, lines):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8', newline='') as f:
        f.write("\n".join(lines) + "\n")


def do_scan(args, targets, new_rules, out_dir, timeout):
    creds = collect_credentials([t['ip'] for t in targets], timeout)
    print(f"\n--- Starte Scan: {len(targets)} Ziele, Muster '{args.ssid_regex or args.ssid}' ---\n")
    q, results, threads = Queue(), [], []
    n = min(args.threads, 20)
    for _ in range(n):
        th = threading.Thread(target=scan_worker, args=(q, results, creds, timeout, new_rules, args), daemon=True)
        th.start()
        threads.append(th)
    for t in targets:
        q.put(t)
    q.join()
    for _ in range(n):
        q.put(None)
    for th in threads:
        th.join()
    results.sort(key=lambda r: [int(p) if p.isdigit() else 0 for p in r['ip'].split('.')])

    plan_items = [r for r in results if r['status'] == ST_TREFFER]
    for it in plan_items:
        key = f"{it['ip']}_{re.sub(r'[^A-Za-z0-9_.-]+', '_', it['rule_name'])}.txt"
        write_text(os.path.join(out_dir, "vorher", key), [f"wlan access-rule {it['rule_name']}"] + [" " + l for l in it['before']])
        write_text(os.path.join(out_dir, "nachher_geplant", key), [f"wlan access-rule {it['rule_name']}"] + [" " + l for l in it['after']])
        write_text(os.path.join(out_dir, "rollback", key), it['rollback'])

    cols = ['ip', 'conductorname', 'standortnummer', 'managedby', 'managed_via', 'central_status', 'note', 'ssid', 'rule_name', 'status', 'hinweis']
    with open(os.path.join(out_dir, "scan.csv"), 'w', encoding='utf-8-sig', newline='') as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction='ignore')
        w.writeheader()
        w.writerows(results)
    plan = {"erstellt": datetime.now().isoformat(timespec='seconds'), "rules": new_rules,
            "muster": args.ssid_regex or args.ssid, "items": plan_items}
    with open(os.path.join(out_dir, "plan.json"), 'w', encoding='utf-8') as f:
        json.dump(plan, f, indent=1, ensure_ascii=False)

    stat = {}
    for r in results:
        stat[r['status']] = stat.get(r['status'], 0) + 1
    print("\n=======================================================")
    print("Scan abgeschlossen (NUR GELESEN, nichts verändert)")
    for k, v in sorted(stat.items()):
        print(f"  {k:<22}{v}")
    print(f"Treffer im Plan:  {len(plan_items)}")
    print(f"Ergebnis:         {os.path.join(out_dir, 'scan.csv')}")
    print(f"Plan:             {os.path.join(out_dir, 'plan.json')}")
    print(f"Sicherung:        {os.path.join(out_dir, 'vorher')}")
    print("=======================================================")
    if plan_items:
        print(f"Anwenden mit: py ap_ssid_rule.py --apply \"{os.path.join(out_dir, 'plan.json')}\" --only <IP>")


# ---------------------------------------------------------------- Anwenden / Prüfen / Rollback
def rules_snapshot(cfg):
    return {k: list(v) for k, v in cfg["rules"].items()}


def verify_after(cfg, item, expected_rules, others_before):
    rname = item['rule_name']
    got = cfg["rules"].get(rname)
    if got != expected_rules:
        return False, f"Regelliste '{rname}' weicht ab (ist {len(got or [])}, soll {len(expected_rules)})"
    for k, v in others_before.items():
        if k != rname and cfg["rules"].get(k) != v:
            return False, f"andere Zugriffsregel '{k}' hat sich verändert"
    return True, ""


def process_item(item, creds, timeout, mode, out_dir):
    ip = item['ip']
    rname = item['rule_name']
    res = {"ip": ip, "rule_name": rname, "ssid": item.get('ssid', ''), "modus": mode, "status": "", "hinweis": ""}
    client = None
    try:
        client = connect(ip, creds, timeout)
        name, managed, cfg = read_state(client)
        if managed != "john":
            res.update(status="ABGEBROCHEN", hinweis=f"VC ist jetzt '{managed}' verwaltet")
            return res
        current = cfg["rules"].get(rname)
        if current is None:
            res.update(status="ABGEBROCHEN", hinweis="Zugriffsregel nicht mehr vorhanden")
            return res
        others = rules_snapshot(cfg)

        if mode == "verify":
            ok = current == item['after']
            res.update(status="OK" if ok else "ABWEICHUNG",
                       hinweis="Regel wie geplant vorhanden" if ok else "Regelliste entspricht nicht dem Plan")
            return res

        if mode == "apply":
            if current != item['before']:
                res.update(status="ABGEBROCHEN", hinweis="Regelliste hat sich seit dem Scan geändert (neu scannen)")
                return res
            ok, errs = run_config_session(client, item['commands'])
            if not ok:
                res.update(status="FEHLER_NICHT_ANGEWENDET", hinweis="; ".join(errs)[:300])
                return res
            time.sleep(2)
            _, _, cfg2 = read_state(client)
            ok2, why = verify_after(cfg2, item, item['after'], others)
            if ok2:
                write_text(os.path.join(out_dir, "nachher", f"{ip}_{re.sub(r'[^A-Za-z0-9_.-]+', '_', rname)}.txt"),
                           [f"wlan access-rule {rname}"] + [" " + l for l in cfg2["rules"][rname]])
                res.update(status="OK", hinweis="Regel angewendet und geprüft")
                return res
            # Prüfung fehlgeschlagen -> sofort zurückrollen
            ok_rb, errs_rb = run_config_session(client, item['rollback'])
            time.sleep(2)
            _, _, cfg3 = read_state(client)
            back = cfg3["rules"].get(rname) == item['before']
            res.update(status="VERIFY_FEHLER_ROLLBACK_OK" if (ok_rb and back) else "VERIFY_FEHLER_ROLLBACK_PRUEFEN",
                       hinweis=f"{why}; Rollback {'erfolgreich' if back else 'NICHT bestätigt: ' + '; '.join(errs_rb)}")
            return res

        if mode == "rollback":
            if current == item['before']:
                res.update(status="OK", hinweis="Ausgangszustand schon vorhanden")
                return res
            ok, errs = run_config_session(client, item['rollback'])
            if not ok:
                res.update(status="FEHLER_NICHT_ANGEWENDET", hinweis="; ".join(errs)[:300])
                return res
            time.sleep(2)
            _, _, cfg2 = read_state(client)
            back = cfg2["rules"].get(rname) == item['before']
            res.update(status="OK" if back else "ABWEICHUNG",
                       hinweis="Ausgangszustand wiederhergestellt und geprüft" if back else "Ausgangszustand NICHT erreicht")
            return res
    except Exception as e:
        res.update(status="FEHLER", hinweis=str(e)[:300])
        return res
    finally:
        if client:
            client.close()


def do_plan_run(args, mode, plan_path, out_dir, timeout):
    with open(plan_path, 'r', encoding='utf-8') as f:
        plan = json.load(f)
    items = plan.get("items", [])
    if args.only:
        wanted = {x.strip() for x in args.only.split(',') if x.strip()}
        items = [i for i in items if i['ip'] in wanted]
    if not items:
        sys.exit("FEHLER: Keine passenden Einträge im Plan (--only prüfen).")
    if mode == "apply" and len(items) > args.max_vcs:
        print(f"HINWEIS: Der Plan enthält {len(items)} VCs, erlaubt sind {args.max_vcs} je Lauf (--max-vcs). Es werden die ersten {args.max_vcs} bearbeitet.")
        items = items[:args.max_vcs]
    plan_rules = plan.get("rules") or [plan["rule"]]
    print(f"\nModus: {mode.upper()} | Regeln: {len(plan_rules)} | Einträge: {len(items)}")
    for r in plan_rules:
        print(f"  {r}")
    creds_store = collect_credentials([i['ip'] for i in items], timeout)
    results, ask_all = [], args.yes
    for it in items:
        if mode in ("apply", "rollback") and not ask_all:
            ans = input(f"\n{it['ip']} ({it.get('conductorname', '')}) SSID '{it['ssid']}', Regel '{it['rule_name']}': "
                        f"{mode} ausführen? (j/n/a=alle/q=Abbruch): ").lower()
            if ans == 'q':
                break
            if ans == 'a':
                ask_all = True
            elif ans != 'j':
                results.append({"ip": it['ip'], "rule_name": it['rule_name'], "ssid": it['ssid'], "modus": mode,
                                "status": "UEBERSPRUNGEN", "hinweis": "vom Anwender"})
                continue
        r = process_item(it, creds_store.get(it['ip'], {'user': 'admin', 'pass': ''}), timeout, mode, out_dir)
        results.append(r)
        log(f"[{r['status']}] {r['ip']} {r['rule_name']}: {r['hinweis']}")
        if mode == "apply" and r['status'] not in ("OK", "UEBERSPRUNGEN"):
            print("STOPP: Abbruch nach dem ersten Problem, weitere VCs werden nicht bearbeitet.")
            break
    with open(os.path.join(out_dir, f"ergebnis_{mode}.csv"), 'w', encoding='utf-8-sig', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['ip', 'rule_name', 'ssid', 'modus', 'status', 'hinweis'])
        w.writeheader()
        w.writerows(results)
    ok = sum(1 for r in results if r['status'] == 'OK')
    print(f"\n{mode.upper()} beendet: {ok} von {len(results)} OK. Ergebnis: {os.path.join(out_dir, f'ergebnis_{mode}.csv')}")


# ---------------------------------------------------------------- main
def load_targets(args):
    targets = []
    path = args.importfile
    if args.targets:
        ips = []
        for item in args.targets:
            ips.extend(x.strip() for x in item.split(',') if x.strip())
        return [{"ip": ip, "conductorname": ""} for ip in ips]
    if not path or not os.path.exists(path):
        sys.exit("FEHLER: Keine Ziele angegeben (IPs oder --importfile mit Spalte 'IP-Adresse' angeben).")
    print(f"INFO: Lese Ziele aus '{path}'...")
    gf = args.filter_gruppe.strip().lower() if args.filter_gruppe else None
    kf = args.filter_kurzname.strip().lower() if args.filter_kurzname else None
    with open(path, 'r', encoding='utf-8-sig') as f:
        for row in csv.DictReader(f):
            ip = (row.get('IP-Adresse') or row.get('ip') or '').strip()
            if not ip:
                continue
            if gf and gf not in (row.get('standortgruppe') or row.get('Gruppe') or '').lower():
                continue
            if kf and not (row.get('conductorkurzname') or '').lower().startswith(kf):
                continue
            targets.append({"ip": ip, "conductorname": row.get('conductorname', ''),
                            "standortnummer": row.get('standortnummer', '')})
    return targets


def main():
    check_dependencies()
    parser = argparse.ArgumentParser(
        description="""ap_ssid_rule.py - Ergänzt Zugriffsregeln (Firewall) in Aruba Instant Swarms mit passender SSID.

WOFÜR?
  Wenn in vielen Swarms dieselbe Freigabe (z. B. ein Zielhost) in der Zugriffsregel einer bestimmten SSID
  ergänzt werden muss, erledigt das Tool Suche, Sicherung, Ergänzung, Prüfung und - falls nötig -
  Rücknahme pro Swarm, ohne die Konfiguration von Hand zu bearbeiten.

WAS GENAU PASSIERT?
  Die neue(n) Regel(n) werden in die Zugriffsregel (wlan access-rule) der gefundenen SSID eingefügt, und zwar
  in der angegebenen Reihenfolge DIREKT VOR der letzten Regel (dem Abschluss 'deny any', mit oder ohne 'log').
  Das Tool entfernt dazu den Abschluss, legt die neuen Regeln an und legt den Abschluss wieder an. Alles
  zusammen wird mit EINEM 'commit apply' wirksam, es gibt also keinen Moment ohne Abschluss-Sperre.
  Es gibt keinen Neustart der APs; die Regeln werden an die Member-APs verteilt und gelten sofort.""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
ABLAUF IN VIER SCHRITTEN (jeder Schritt ist ein eigener Aufruf)
  1. SCAN / PLAN   (Standard, nur lesend, ändert nichts)
       Liest jeden Swarm, erkennt die Verwaltung, sucht die SSID, prüft die Zugriffsregel und schreibt
       Ergebnisliste (scan.csv), Plan (plan.json) und die Sicherung der betroffenen Regelblöcke.
  2. --apply PLAN  (SCHREIBT auf die Swarms)
       Wendet den Plan an: je Swarm Rückfrage, Rückleseprüfung, bei Abweichung automatischer Rollback.
  3. --verify PLAN (nur lesend)
       Prüft jederzeit, ob die Regeln im Swarm so vorhanden sind, wie es der Plan vorsieht.
  4. --rollback PLAN (SCHREIBT auf die Swarms)
       Nimmt genau die vom Plan ergänzten Regeln wieder heraus und prüft den Ausgangszustand.

WELCHE SWARMS WERDEN GEÄNDERT?
  Nur Swarms, die NICHT von AirWave und NICHT von Aruba Central verwaltet werden:
    - AirWave:  Eintrag 'ams-ip' in der Konfiguration, oder 'Airwave: Connected' in 'show summary'.
    - Central:  nur wenn 'Aruba Central: Connected' UND 'Managed Via: Aruba Central' (verbunden und als
                Verwalter eingetragen). Ist Central nur eingetragen, aber 'Not Connected', gilt der Swarm als
                unverwaltet und wird behandelt; die Konstellation wird in scan.csv ausgewiesen
                (Spalten managed_via, central_status, note).
  Ein Swarm wird übersprungen und mit Status gemeldet, wenn
    - die Zugriffsregel mit dem Namen des SSID-Profils fehlt                   (KEINE_ZUGRIFFSREGEL)
    - die letzte Regel nicht 'rule any any match any any any deny [log]' ist    (ABSCHLUSS_UNERWARTET)
    - alle neuen Regeln schon vorhanden sind                                    (REGEL_VORHANDEN)
    - der Swarm nicht erreichbar ist oder die Anmeldung scheitert               (FEHLER)

SSID-MUSTER (--ssid / --ssid-regex)
  --ssid "abc"            nur genau 'abc'
  --ssid "abc*"           alles, was mit 'abc' beginnt
  --ssid "*abc*"          alles, was 'abc' enthält
  --ssid-regex "(byod-)?abc(-[0-9]{6})?"
                          genauer: 'abc', 'byod-abc', 'abc-123456', 'byod-abc-123456' (ganzer Name muss passen)
  Groß-/Kleinschreibung wird nicht unterschieden. Verglichen wird der sichtbare SSID-Name (essid).
  Die Zugriffsregel wird über den NAMEN des SSID-Profils gefunden (gleicher Name wie die Zugriffsregel).

REGELN (--rule)
  --rule "rule 192.0.2.10 255.255.255.255 match any any any permit"        ein einzelner Host
  --rule "rule alias beispiel.example.org match any any any permit"        ein Hostname
  Mehrfach angeben für mehrere Regeln; die Reihenfolge bleibt erhalten. Das führende 'rule' darf fehlen.
  Eine schon vorhandene Regel wird nicht doppelt angelegt (Rest wird ergänzt).

SICHERHEITSMECHANISMEN
  - Standard ist immer nur Lesen. Schreiben nur mit --apply bzw. --rollback.
  - Je --apply-Lauf höchstens --max-vcs Swarms (Standard 1: Pilotbetrieb, Wert ausdrücklich erhöhen).
  - Je Swarm Rückfrage 'j/n/a/q' (a = alle Weiteren, q = Abbruch); --yes unterdrückt die Rückfrage.
  - Vor dem Schreiben wird die Regelliste neu gelesen. Hat sie sich seit dem Scan geändert, wird NICHT
    geschrieben (neu scannen).
  - Nach dem Schreiben wird zurückgelesen: die Liste muss dem Plan entsprechen und alle anderen
    Zugriffsregeln müssen unverändert sein. Sonst läuft sofort ein automatischer Rollback.
  - Bei der ersten Fehlermeldung des Swarms wird 'commit revert' ausgeführt und die Sitzung beendet.
  - Der Swarm nimmt je Sitzung nur eine begrenzte Zahl Befehle an (danach 'history buffer full');
    das Tool begrenzt die Sitzungsgröße selbst und erkennt solche Meldungen.
  - Beim ersten Problem hält --apply an; weitere Swarms werden nicht mehr bearbeitet.

ERGEBNISDATEIEN (im Ergebnisordner, Standard ./ap_ssid_rule_<Zeitstempel>)
  scan.csv            alle gescannten Swarms mit Status, Verwaltung, SSID, Zugriffsregel, Hinweis
  plan.json           die Treffer mit Vorher, Nachher, Befehlen und Rollback-Befehlen
  vorher/             Sicherung der Zugriffsregel vor der Änderung (Textdatei je Swarm)
  nachher_geplant/    so soll die Zugriffsregel danach aussehen
  rollback/           die Rollback-Befehle je Swarm
  nachher/            tatsächlicher Stand nach --apply (zurückgelesen)
  ergebnis_apply.csv / ergebnis_verify.csv / ergebnis_rollback.csv   Ergebnis des jeweiligen Modus
  Die Dateien enthalten Regelblöcke, aber keine Kennwörter oder Schlüssel.

BEISPIELE
  # 1. Scan + Plan für alle Swarms aus einer CSV-Datei (nur lesend)
  py ap_ssid_rule.py --importfile liste.csv --ssid "ssid-beispiel" --rule "rule 192.0.2.10 255.255.255.255 match any any any permit"

  # Mehrere Regeln in einem Lauf (--rule mehrfach, Reihenfolge bleibt erhalten)
  py ap_ssid_rule.py --ssid "ssid-beispiel" --rule "rule alias beispiel.example.org match any any any permit" --rule "rule 192.0.2.11 255.255.255.255 match any any any permit" 10.1.1.1

  # Nur bestimmte Swarms per IP
  py ap_ssid_rule.py --ssid "ssid-beispiel" --rule "rule 192.0.2.10 255.255.255.255 match any any any permit" 10.1.1.1,10.2.2.2

  # Nur eine Standortgruppe / nur Swarms, deren Kurzname mit 'abc' beginnt
  py ap_ssid_rule.py --ssid "ssid-beispiel" --rule "..." --importfile liste.csv --filter-gruppe "Beispielstadt"
  py ap_ssid_rule.py --ssid "ssid-beispiel" --rule "..." --importfile liste.csv --filter-kurzname abc

  # SSID mit Platzhalter oder genau per regulärem Ausdruck
  py ap_ssid_rule.py --ssid "*ssid-beispiel*" --rule "..." 10.1.1.1
  py ap_ssid_rule.py --ssid-regex "(byod-)?ssid-beispiel(-[0-9]{6})?" --rule "..." 10.1.1.1

  # 2. Plan anwenden (SCHREIBT): ein bestimmter Swarm, mit Rückfrage
  py ap_ssid_rule.py --apply ap_ssid_rule_2026-01-01-10-00-00/plan.json --only 10.1.1.1

  # Mehrere Swarms je Lauf erlauben (nur nach erfolgreichem Pilot) und ohne Rückfrage
  py ap_ssid_rule.py --apply ap_ssid_rule_2026-01-01-10-00-00/plan.json --max-vcs 10 --yes

  # 3. Prüfen (nur lesend), alle oder bestimmte Swarms
  py ap_ssid_rule.py --verify ap_ssid_rule_2026-01-01-10-00-00/plan.json
  py ap_ssid_rule.py --verify ap_ssid_rule_2026-01-01-10-00-00/plan.json --only 10.1.1.1

  # 4. Zurücknehmen (SCHREIBT)
  py ap_ssid_rule.py --rollback ap_ssid_rule_2026-01-01-10-00-00/plan.json --only 10.1.1.1

  # Anmeldedaten per Windows Credential Manager (Menüpunkt 1) und Benutzer 'admin' automatisch übergeben (PowerShell)
  "1`nadmin" | py -X utf8 ap_ssid_rule.py --apply ap_ssid_rule_2026-01-01-10-00-00/plan.json --only 10.1.1.1

EMPFOHLENES VORGEHEN
  Erst Scan und Plan prüfen (scan.csv, vorher/, nachher_geplant/). Dann EINEN Swarm anwenden und prüfen
  (--only <IP>). Erst danach Gruppen mit --max-vcs und Pausen. Nach jedem Schreiben erneut mit --verify prüfen.

ANMELDEDATEN
  Wie bei den anderen Tools: Windows Credential Manager (empfohlen), lokal verschlüsselte Datei
  'credentials.bin' (nur Basisschutz, siehe Warnhinweis bei der Auswahl) oder manuelle Eingabe.
""")
    parser.add_argument('targets', nargs='*', default=[], metavar='IP', help="Eine oder mehrere Conductor-IPs (kommasepariert). Alternativ --importfile verwenden.")
    parser.add_argument('--importfile', type=str, default=None, help="Pfad zu einer CSV mit Kopfzeile und Spalte 'IP-Adresse', aus der die Conductor-IPs gelesen werden. Optional werden die Spalten 'standortgruppe' (oder 'Gruppe') und 'conductorkurzname' fuer die Filter ausgewertet.")
    parser.add_argument('--filter-gruppe', type=str, default=None, help="Beim CSV-Import nur Conductors, deren Standortgruppe diesen Text enthält (Teilstring).")
    parser.add_argument('--filter-kurzname', type=str, default=None, help="Beim CSV-Import nur Conductors, deren Kurzname mit diesem Text beginnt (Präfix).")
    parser.add_argument('--ssid', type=str, default=None, help="SSID-Name; '*' als Platzhalter erlaubt ('abc' genau, 'abc*' beginnt mit, '*abc*' enthält). Nur im Scan.")
    parser.add_argument('--ssid-regex', type=str, default=None, help="SSID als regulärer Ausdruck, der den GANZEN Namen treffen muss (Alternative zu --ssid). Nur im Scan.")
    parser.add_argument('--rule', action='append', default=None, metavar='REGEL', help="Zu ergänzende Regel, z. B. 'rule 192.0.2.10 255.255.255.255 match any any any permit'. Mehrfach angeben für mehrere Regeln (Reihenfolge bleibt erhalten). Nur im Scan.")
    parser.add_argument('--apply', metavar='PLAN', type=str, default=None, help="SCHREIBT: Plan (plan.json aus einem Scan) auf die Swarms anwenden, je Swarm mit Rückfrage und Prüfung.")
    parser.add_argument('--verify', metavar='PLAN', type=str, default=None, help="Nur lesend: prüfen, ob die Regeln im Swarm dem Plan entsprechen.")
    parser.add_argument('--rollback', metavar='PLAN', type=str, default=None, help="SCHREIBT: die vom Plan ergänzten Regeln wieder entfernen und den Ausgangszustand prüfen.")
    parser.add_argument('--only', type=str, default=None, help="Bei --apply/--verify/--rollback nur diese Conductor-IPs aus dem Plan (kommasepariert).")
    parser.add_argument('--max-vcs', type=int, default=1, help="Höchstzahl Swarms je --apply-Lauf (Standard: 1 = Pilotbetrieb).")
    parser.add_argument('--yes', action='store_true', help="Rückfrage je Swarm bei --apply/--rollback unterdrücken.")
    parser.add_argument('--threads', '-t', type=int, default=10, help="Parallele Abfragen im Scan (Standard: 10, max. 20). Schreiben erfolgt immer nacheinander.")
    parser.add_argument('--timeout', type=int, default=25, help="SSH-Timeout in Sekunden (Standard: 25).")
    parser.add_argument('--output-dir', type=str, default=None, help="Ergebnisordner (Standard beim Scan: ./ap_ssid_rule_<Zeitstempel>, sonst der Ordner des Plans).")
    parser.add_argument('--log', action='store_true', help="Konsolenausgabe zusätzlich in eine Log-Datei im Ergebnisordner schreiben.")
    args = parser.parse_args()

    modes = [m for m in ('apply', 'verify', 'rollback') if getattr(args, m)]
    if len(modes) > 1:
        sys.exit("FEHLER: Nur einer der Modi --apply, --verify, --rollback ist je Lauf erlaubt.")
    mode = modes[0] if modes else "scan"

    ts = datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
    if mode == "scan":
        out_dir = os.path.abspath(args.output_dir or f"ap_ssid_rule_{ts}")
    else:
        plan_path = os.path.abspath(getattr(args, mode))
        out_dir = os.path.abspath(args.output_dir or os.path.dirname(plan_path))
    os.makedirs(out_dir, exist_ok=True)
    if args.log:
        try:
            sys.stdout = Logger(filename=os.path.join(out_dir, f"ap_ssid_rule_{mode}_{ts}_log.txt"))
        except Exception as e:
            print(f"WARNUNG: Log-Datei konnte nicht erstellt werden: {e}")

    print(f"ap_ssid_rule.py Version {AP_SSID_RULE_VERSION} (Suite v{TOOLSUITE_VERSION}) wird ausgeführt...")
    print(f"Teil der Aruba Instant Toolsammlung Version {TOOLSUITE_VERSION}")
    print(f"Nutze aruba_helper.py Version {HELPER_VERSION}")
    print(f"Modus: {mode.upper()} | Ergebnisordner: {out_dir}")
    print(f"\n===== Skriptstart: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} =====")

    timeout = args.timeout
    if mode == "scan":
        if not (args.ssid or args.ssid_regex):
            sys.exit("FEHLER: --ssid oder --ssid-regex ist erforderlich.")
        if not args.rule:
            sys.exit("FEHLER: --rule ist erforderlich.")
        new_rules = []
        for r in args.rule:
            r = norm(r)
            if not r.startswith("rule "):
                r = "rule " + r
            if r not in new_rules:
                new_rules.append(r)
        targets = load_targets(args)
        if not targets:
            sys.exit("FEHLER: Keine Ziele ausgewählt.")
        do_scan(args, targets, new_rules, out_dir, timeout)
    else:
        do_plan_run(args, mode, plan_path, out_dir, timeout)


if __name__ == '__main__':
    main()
