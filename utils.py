# utils.py

import os
import logging
import re
import csv
import sqlite3
from datetime import datetime

DATE_CONFIG_REGEX = re.compile(
    r"^#\s*(?P<jour_sem>\w{3})\s+(?P<mois>\w{3})\s+(?P<jour>\d{1,2})\s+"
    r"(?P<heure>[\d:]{8})\s+(?P<fuseau>\S+)\s+(?P<annee>\d{4})"
)

def setup_logging(log_dir):
    log_path = os.path.join(log_dir, 'autel_debug.log')
    root = logging.getLogger()
    if root.handlers:
        for handler in root.handlers[:]:
            root.removeHandler(handler)
    handler = logging.FileHandler(log_path, mode='w', encoding='utf-8')
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
    handler.setFormatter(formatter)
    root.addHandler(handler)
    root.setLevel(logging.INFO)

def get_tablet_info(root_dir):
    info = {
        "serial": "inconnu", "model": "inconnu",
        "fuseau_horaire": "inconnu", "langue": "inconnue",
        "date_extraite_config": "inconnue",
        "date_extraction_script": datetime.now().isoformat(),
    }
    config_found = False
    try:
        for dp, _, files in os.walk(root_dir):
            if not config_found and '.config.txt' in files:
                config_path = os.path.join(dp, '.config.txt')
                with open(config_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        match = DATE_CONFIG_REGEX.match(line)
                        if match:
                            data = match.groupdict()
                            info['date_extraite_config'] = f"{data['annee']}-{data['mois']}-{data['jour']} {data['heure']}"
                            info['fuseau_horaire'] = data['fuseau']
                            config_found = True
                            break
            for fname in files:
                if fname.lower().endswith('smart_update_log.txt'):
                    full_path = os.path.join(dp, fname)
                    with open(full_path, encoding='utf-8', errors='ignore') as sf:
                        content = sf.read()
                        if m := re.search(r'"deviceSn":"(\w+)"', content): info['serial'] = m.group(1)
                        if m2 := re.search(r'"deviceModel":"([^\"]+)"', content): info['model'] = m2.group(1)
            if config_found and info['serial'] != 'inconnu' and info['langue'] != 'inconnue':
                break
    except Exception as e:
        logging.error(f"Erreur lors de la recherche des infos tablette: {e}")
    
    db_path = os.path.join(root_dir, 'MaxiApScan', 'DataBase', 'masdas.db')
    if info['langue'] == 'inconnue' and os.path.isfile(db_path):
        try:
            conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
            cursor = conn.cursor()
            cursor.execute("SELECT Value FROM tb_sys_config WHERE Key = 'language'")
            result = cursor.fetchone()
            if result: info['langue'] = result[0]
            conn.close()
        except Exception as e:
            logging.error(f"Impossible de lire la langue depuis masdas.db: {e}")
    return info

def export_tablet_info_csv(dest_dir, info):
    fields = ['serial', 'model', 'fuseau_horaire', 'langue', 'date_extraite_config', 'date_extraction_script']
    out_csv = os.path.join(dest_dir, 'tablet_info.csv')
    with open(out_csv, 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerow(info)
    return out_csv