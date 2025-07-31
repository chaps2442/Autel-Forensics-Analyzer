# extract_mac.py

import os
import csv
import re
import logging

def load_oui_db(csvfile):
    oui_db = {}
    try:
        if os.path.isfile(csvfile):
            with open(csvfile, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                next(reader) 
                for row in reader:
                    if len(row) >= 3:
                        prefix = row[1].upper()
                        vendor = row[2]
                        oui_db[prefix] = vendor
    except Exception as e:
        logging.warning(f"Impossible de charger le fichier OUI DB: {e}")
    return oui_db

def get_vendor(mac, oui_db):
    prefix = mac.replace(':', '')[:6]
    return oui_db.get(prefix, "Inconnu")

def is_mac_randomized(mac):
    try:
        first_octet = int(mac.split(':')[0], 16)
        return (first_octet & 2) == 2
    except:
        return False

def extract_mac(src_dir, export_dir, skip_md5=None, progress_callback=None, **kwargs):
    oui_db = load_oui_db(os.path.join(os.path.dirname(__file__), 'oui.csv'))
    mac_re = re.compile(r'(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}')
    event_re = re.compile(r'(connected|disconnected)', re.IGNORECASE)
    time_re = re.compile(r'\b(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\b')
    
    out_mac_path = os.path.join(export_dir, 'mac_found.csv')
    out_evt_path = os.path.join(export_dir, 'mac_connections_found.csv')
    
    all_macs_found = set()
    connection_events = []
    
    files_to_scan = [os.path.join(root, fname) for root, _, fnames in os.walk(src_dir) for fname in fnames if fname.lower().endswith(('.log', '.txt'))]
    total_files = len(files_to_scan)
    if progress_callback: progress_callback(0, total_files)

    with open(out_mac_path, 'w', newline='', encoding='utf-8-sig') as fmac, \
         open(out_evt_path, 'w', newline='', encoding='utf-8-sig') as fevt:
        
        wmac = csv.writer(fmac)
        wmac.writerow(['mac','vendor','randomized','path'])
        wevt = csv.writer(fevt)
        wevt.writerow(['mac','event','date','vendor','randomized','path'])

        for i, full_path in enumerate(files_to_scan, 1):
            if progress_callback: progress_callback(i, total_files)
            rel_path = os.path.relpath(full_path, src_dir)
            try:
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as rf:
                    for line in rf:
                        found_macs_in_line = mac_re.findall(line)
                        if not found_macs_in_line: continue
                        
                        mac_std_list_in_line = {m.replace('-', ':').upper() for m in found_macs_in_line}
                        
                        for mac_std in mac_std_list_in_line:
                            if mac_std not in all_macs_found:
                                all_macs_found.add(mac_std)
                                vendor = get_vendor(mac_std, oui_db)
                                randomized = "Oui" if is_mac_randomized(mac_std) else "Non"
                                wmac.writerow([mac_std, vendor, randomized, rel_path])

                        if evt := event_re.search(line):
                            date_match = time_re.search(line)
                            date_str = date_match.group(0) if date_match else ''
                            for mac_std in mac_std_list_in_line:
                                vendor = get_vendor(mac_std, oui_db)
                                randomized = "Oui" if is_mac_randomized(mac_std) else "Non"
                                row = [mac_std, evt.group(1).lower(), date_str, vendor, randomized, rel_path]
                                connection_events.append(row)
                                wevt.writerow(row)
            except Exception as e:
                logging.warning(f"Erreur lors de la lecture du fichier {rel_path}: {e}")

    return list(all_macs_found) + connection_events