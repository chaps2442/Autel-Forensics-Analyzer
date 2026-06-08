# extract_vins.py
# Auteur : Vincent Chapeau — Teel Technologies Canada (vincent.chapeau@teeltechcanada.com)
import csv, datetime, logging, re
from wmi_list import WMI_SET
from core_scanner import iter_entries, iter_binary_chunks_entry, open_csv, should_skip

VIN_REGEX = re.compile(rb'(?=([A-HJ-NPR-Z0-9]{17}))')
EXCLUDE_EXT = {'.apk', '.jpg', '.jpeg', '.png', '.gif', '.mp4', '.mov', '.avi', '.zip', '.7z', '.db'}
TRANSLIT = {ord(c): i for i, c in enumerate('0123456789')}
TRANSLIT.update({ord(c): v for c, v in zip('ABCDEFGH', range(1, 9))})
TRANSLIT.update({ord(c): v for c, v in zip('JKLMNPR', [1, 2, 3, 4, 5, 7, 9])})
TRANSLIT.update({ord(c): v for c, v in zip('STUVWXYZ', [2, 3, 4, 5, 6, 7, 8, 9])})
WEIGHTS = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2]

def _check_digit(vin: str) -> bool:
    try:
        total = sum(TRANSLIT[ord(char)] * WEIGHTS[i] for i, char in enumerate(vin))
        check = total % 11
        return vin[8] == ('X' if check == 10 else str(check))
    except (KeyError, IndexError): return False

def _valid_wmi(vin: str) -> bool: return vin[:3] in WMI_SET

def extract_all_vins(src_dir, export_dir, skip_md5=None, **kwargs):
    rows = []
    f_csv, writer = open_csv(export_dir, 'vins_extraits.csv', ['chemin_fichier','vin','date_modification','statut_validation'])
    try:
        for entry in iter_entries(src_dir, exclude_ext=EXCLUDE_EXT):
            if entry.is_os and should_skip(entry.path, skip_md5): continue
            
            found_in_file = set()
            try:
                for blob in iter_binary_chunks_entry(entry):
                    for m in VIN_REGEX.finditer(blob):
                        vin = m.group(1).decode('ascii', 'ignore').upper()
                        if _valid_wmi(vin): found_in_file.add(vin)
            except Exception as e:
                logging.warning(f"Erreur de scan VIN sur {entry.rel_path}: {e}")
                continue

            if found_in_file:
                try: mtime = datetime.datetime.fromtimestamp(entry.mtime).strftime('%Y-%m-%d %H:%M:%S') if entry.mtime else "Date Inconnue"
                except Exception: mtime = "Date Inconnue"
                
                for vin in sorted(found_in_file):
                    statut = 'Valide' if _check_digit(vin) else 'Check Digit Invalide'
                    row = [entry.rel_path, vin, mtime, statut]
                    rows.append(row); writer.writerow(row)
    finally:
        f_csv.close()
    return rows
