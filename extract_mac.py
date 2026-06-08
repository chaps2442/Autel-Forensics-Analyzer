# extract_mac.py (version VFS)
# Auteur : Vincent Chapeau — Teel Technologies Canada (vincent.chapeau@teeltechcanada.com)
import os
import csv
import re
import logging
import datetime
from core_scanner import iter_entries, iter_text_lines_entry, open_csv, should_skip

def load_oui_db(csvfile):
    """Charge la base de données OUI pour mapper les MAC aux constructeurs."""
    oui_db = {}
    try:
        if os.path.isfile(csvfile):
            with open(csvfile, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    prefix = row.get('Assignment', '').upper().replace('-', '')[:6]
                    vendor = row.get('Organization Name', 'Inconnu')
                    if prefix: oui_db[prefix] = vendor
    except Exception as e:
        logging.warning(f"Impossible de charger le fichier OUI DB '{csvfile}': {e}")
    return oui_db

def get_vendor(mac, oui_db):
    """Trouve le constructeur d'une adresse MAC."""
    prefix = mac.replace(':', '')[:6].upper()
    return oui_db.get(prefix, 'Inconnu')

def is_mac_randomized(mac):
    """Vérifie si une adresse MAC est probablement aléatoire (privée)."""
    try:
        first_octet = int(mac.split(':')[0], 16)
        return (first_octet & 2) != 0
    except Exception:
        return False

def extract_mac(src_dir, export_dir, skip_md5=None, **kwargs):
    """Extrait les adresses MAC et événements de connexion en utilisant l'API VFS."""
    oui_path = os.path.join(os.path.dirname(__file__), 'oui.csv')
    oui_db = load_oui_db(oui_path)
    
    mac_re = re.compile(r'(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}')
    event_re = re.compile(r'\b(connected|disconnected|connect|disconnect|association|deauth|paired|pairing)\b', re.IGNORECASE)
    time_re = re.compile(r'\b(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\b')

    all_macs_found = set()
    connection_events = []
    
    f_mac, w_mac = open_csv(export_dir, 'mac_found.csv', ['mac','vendor','randomized','path','date_modification'])
    f_evt, w_evt = open_csv(export_dir, 'mac_connections_found.csv', ['mac','event','date_evenement','vendor','randomized','path','date_modification_fichier'])
    
    try:
        for entry in iter_entries(src_dir, include_ext=['.log', '.txt']):
            if entry.is_os and should_skip(entry.path, skip_md5):
                continue
            
            try:
                mtime = datetime.datetime.fromtimestamp(entry.mtime).strftime('%Y-%m-%d %H:%M:%S') if entry.mtime else "Date Inconnue"
            except Exception:
                mtime = "Date Inconnue"

            for line in iter_text_lines_entry(entry):
                found_macs_in_line = {m.replace('-', ':').upper() for m in mac_re.findall(line)}
                if not found_macs_in_line:
                    continue
                
                for mac in found_macs_in_line:
                    if mac not in all_macs_found:
                        all_macs_found.add(mac)
                        vendor = get_vendor(mac, oui_db)
                        randomized = "Oui" if is_mac_randomized(mac) else "Non"
                        w_mac.writerow([mac, vendor, randomized, entry.rel_path, mtime])

                if evt_match := event_re.search(line):
                    date_str = (m.group(1) if (m := time_re.search(line)) else '')
                    for mac in found_macs_in_line:
                        vendor = get_vendor(mac, oui_db)
                        randomized = "Oui" if is_mac_randomized(mac) else "Non"
                        row = [mac, evt_match.group(1).lower(), date_str, vendor, randomized, entry.rel_path, mtime]
                        connection_events.append(row)
                        w_evt.writerow(row)
    finally:
        f_mac.close()
        f_evt.close()

    return list(all_macs_found) + connection_events
