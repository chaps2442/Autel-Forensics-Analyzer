# extract_vins.py

import os
import re
import csv
import hashlib
import logging
import datetime
from wmi_list import WMI_SET

VIN_REGEX = re.compile(r'(?=([A-HJ-NPR-Z0-9]{17}))', re.IGNORECASE)
VIN_SCAN_EXCLUDED_EXTENSIONS = {'.apk', '.jpg', '.jpeg', '.png', '.gif', '.mp4', '.mov', '.avi', '.zip'}

def file_md5(path: str):
    h = hashlib.md5()
    try:
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                h.update(chunk)
        return h.hexdigest().lower()
    except (IOError, OSError): return None

def vin_check_digit(vin: str) -> bool:
    vin = vin.upper()
    if len(vin) != 17: return False
    translit_map = {'A': 1, 'B': 2, 'C': 3, 'D': 4, 'E': 5, 'F': 6, 'G': 7, 'H': 8, 'J': 1, 'K': 2, 'L': 3, 'M': 4, 'N': 5, 'P': 7, 'R': 9, 'S': 2, 'T': 3, 'U': 4, 'V': 5, 'W': 6, 'X': 7, 'Y': 8, 'Z': 9}
    for i in range(10): translit_map[str(i)] = i
    weights = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2]
    try:
        total = sum(translit_map[vin[i]] * weights[i] for i in range(17))
        check = total % 11
        return vin[8] == ('X' if check == 10 else str(check))
    except KeyError: return False

def is_valid_wmi(vin: str) -> bool:
    return vin[:3].upper() in WMI_SET

def extract_all_vins(src_dir, export_dir, skip_md5=None, progress_callback=None, **kwargs):
    skip_md5 = skip_md5 or set()
    vin_rows = []
    all_files = [os.path.join(root, fname) for root, _, fnames in os.walk(src_dir) for fname in fnames]
    total_files = len(all_files)
    if progress_callback: progress_callback(0, total_files)

    for i, full_path in enumerate(all_files, 1):
        if progress_callback: progress_callback(i, total_files)
        file_ext = os.path.splitext(full_path)[1].lower()
        if file_ext in VIN_SCAN_EXCLUDED_EXTENSIONS: continue
        if file_md5(full_path) in skip_md5: continue
        
        found_vins_in_file = set()
        try:
            with open(full_path, 'rb') as f: content = f.read()
            text_content = content.decode('ascii', errors='ignore')
            for candidate_match in VIN_REGEX.finditer(text_content):
                vin_candidate = candidate_match.group(1).upper()
                if is_valid_wmi(vin_candidate):
                    found_vins_in_file.add(vin_candidate)
        except Exception: continue

        if found_vins_in_file:
            rel_path = os.path.relpath(full_path, src_dir)
            mod_date = datetime.datetime.fromtimestamp(os.path.getmtime(full_path)).strftime('%Y-%m-%d %H:%M:%S')
            for vin in sorted(list(found_vins_in_file)):
                check_digit_status = "Valide" if vin_check_digit(vin) else "Check Digit Invalide"
                vin_rows.append([rel_path, vin, mod_date, check_digit_status])

    output_csv_path = os.path.join(export_dir, 'vins_extraits.csv')
    with open(output_csv_path, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f)
        writer.writerow(['chemin_fichier', 'vin', 'date_modification', 'statut_validation'])
        writer.writerows(vin_rows)
    
    return vin_rows