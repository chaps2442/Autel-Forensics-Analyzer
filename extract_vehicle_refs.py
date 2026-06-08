# extract_vehicle_refs.py (version VFS)
# Auteur : Vincent Chapeau — Teel Technologies Canada (vincent.chapeau@teeltechcanada.com)
import csv
import re
import logging
import datetime
from core_scanner import iter_entries, iter_text_lines_entry, should_skip, open_csv

RE_MAIN_ITEM = re.compile(r'"mainItem"\s*:\s*"(?P<brand>\w+)\s+(?P<model>.*?)\s+(?P<y1>\d{4})-(?P<y2>\d{4})"')
RE_REF = re.compile(r'Reference\s+(OEM|FCCID)\s*[:=]\s*([^\s"]+)', re.IGNORECASE)
JUNK = {'system','menu','path','read','code','all','obd','selection'}

def extract_vehicle_refs(src_dir, export_dir, skip_md5=None, **kwargs):
    header = ['source_path', 'type', 'marque', 'modele', 'annees', 'reference', 'date_modification']
    f_csv, w = open_csv(export_dir, 'vehicule_refs_found.csv', header)
    rows = []
    
    try:
        for entry in iter_entries(src_dir, include_ext=('.json', '.txt', '.log')):
            if entry.is_os and should_skip(entry.path, skip_md5):
                continue
            
            try:
                mtime = datetime.datetime.fromtimestamp(entry.mtime).strftime('%Y-%m-%d %H:%M:%S') if entry.mtime else "Date Inconnue"
            except Exception:
                mtime = "Date Inconnue"

            try:
                for line in iter_text_lines_entry(entry):
                    if m := RE_MAIN_ITEM.search(line):
                        brand, model = m.group('brand').strip(), m.group('model').strip()
                        if len(brand) > 2 and brand.lower() not in JUNK:
                            row = [entry.rel_path, 'Vehicule', brand, model, f"{m.group('y1')}-{m.group('y2')}", '', mtime]
                            rows.append(row); w.writerow(row)
                    if m2 := RE_REF.search(line):
                        rtype, rval = m2.group(1).upper(), m2.group(2).strip()
                        if len(rval) > 4:
                            row = [entry.rel_path, rtype, '', '', '', rval, mtime]
                            rows.append(row); w.writerow(row)
            except Exception as e:
                logging.warning(f"Erreur lecture {entry.rel_path}: {e}")
    finally:
        f_csv.close()
    return rows
