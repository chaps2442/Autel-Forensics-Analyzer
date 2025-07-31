# extract_log_events.py

import os
import re
import csv
import json
import zipfile
import io
import logging

def extract_all_log_events(src_dir, export_dir, skip_md5=None, progress_callback=None, **kwargs):
    """
    Extrait une grande variété d'événements pertinents des fichiers logs, 
    y compris les JSON d'activité, les appareils Bluetooth, les SSID Wi-Fi, etc.
    """
    event_rows = []
    
    # --- NOUVEAU : Regex enrichies sur base de vos extractions manuelles ---
    PATTERNS = {
        # Activités utilisateur (avec JSON)
        "USER_ACTIVITY_JSON": re.compile(r'jsonStr\s*-->\s*({.*?})$', re.IGNORECASE),
        "KEYTOOL_USE_JSON": re.compile(r'"eventType":"IM_KEYTOOL_USE".*?({.*?})', re.IGNORECASE),
        "VIN_HISTORY_JSON": re.compile(r'"vtHis":\[(.*?)\]'),
        
        # Informations système et réseau
        "BLUETOOTH_STORED": re.compile(r'Stored bluetooth Name=(.*?),Address=(.*?)$'),
        "BLUETOOTH_DEVICE_FOUND": re.compile(r'search_result_file_init: addr:\[(.*?)\] name:\[(.*?)\]'),
        "WIFI_SSID_FOUND": re.compile(r'Skip scan ssid for single scan:\s*(.*)'),
        
        # Informations techniques
        "SERIAL_PASSWORD_QUERY": re.compile(r'queryAppInfo encrypt strJson = (.*?)$'),
        "SET_VEHICLE": re.compile(r'SetVehicleMake:\s*(.*?)$'),
        "ENCRYPTION": re.compile(r'AesRsaEcrypt begin n=(.*?) inLen=(.*?)$'),
        "EXCEPTION": re.compile(r'(Exception:.*)'),
    }

    files_to_scan = [os.path.join(root, fname) for root, _, fnames in os.walk(src_dir) for fname in fnames if fname.lower().endswith(('.log', '.txt', '.zip'))]
    total_files = len(files_to_scan)
    if progress_callback: progress_callback(0, total_files)

    for i, full_path in enumerate(files_to_scan, 1):
        if progress_callback: progress_callback(i, total_files)
        rel_path = os.path.relpath(full_path, src_dir)
        
        def parse_lines(line_iterator, file_path_display):
            for line_num, line in enumerate(line_iterator, 1):
                for event_type, pattern in PATTERNS.items():
                    for match in pattern.finditer(line):
                        details = [d.strip() for d in match.groups()]
                        event_rows.append([file_path_display, line_num, event_type] + details)
        
        if full_path.lower().endswith('.zip'):
            try:
                with zipfile.ZipFile(full_path, 'r') as zf:
                    for zinfo in zf.infolist():
                        if not zinfo.is_dir() and zinfo.filename.lower().endswith(('.log', '.txt')):
                            with zf.open(zinfo, 'r') as f:
                                text_stream = io.TextIOWrapper(f, encoding='utf-8', errors='ignore')
                                parse_lines(text_stream, f"{rel_path} -> {zinfo.filename}")
            except Exception as e:
                logging.warning(f"Impossible de traiter le ZIP {rel_path}: {e}")
        else:
            try:
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    parse_lines(f, rel_path)
            except Exception as e:
                logging.warning(f"Impossible de lire le fichier log {rel_path}: {e}")

    # --- Écriture du fichier CSV ---
    output_csv_path = os.path.join(export_dir, 'log_events_found.csv')
    with open(output_csv_path, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f)
        max_details = max(len(row) for row in event_rows) if event_rows else 3
        header = ['chemin_fichier', 'numero_ligne', 'type_evenement'] + [f'detail_{i}' for i in range(1, max_details - 2)]
        writer.writerow(header)
        writer.writerows(event_rows)

    return event_rows