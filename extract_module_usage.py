# extract_module_usage.py — AFAP v2.0.0
# Auteur : Vincent Chapeau — Teel Technologies Canada (vincent.chapeau@teeltechcanada.com)
#
# Croisement de 3 sources pour quantifier l'USAGE PAR MARQUE / MODULE :
#
#   1. Scan/Update/.FREQUENCY     → {module_id: nb_utilisations}
#                                    (compteur d'usage maintenu par l'app)
#   2. copyData/CopyInfos.db      → table CARBASE_INFO
#                                    (car_code, car_name, version, lib_size)
#   3. Scan/Update/.AllUpdateList → catalogue cloud Autel
#                                    (id → nom, useNum, allUseNum, iconUrl)
#
# Ce module donne au forensique :
#   - la liste hiérarchisée des marques diagnostiquées
#   - leur version installée vs cloud
#   - la taille de la lib (preuve qu'elle a été téléchargée localement)
#
# Sortie : modules_usage.csv

import csv
import json
import logging
import os
import re
import sqlite3
import tempfile
import datetime
from core_scanner import iter_entries, open_csv

HEADER = [
    'module_id', 'car_name', 'version_installee', 'lib_size_MB',
    'freq_utilisation', 'app_use_num', 'app_all_use_num',
    'update_local_version', 'update_cloud_version', 'icon_url'
]

def _open_db_copy(entry):
    """Copie l'entry vers un fichier temp puis ouvre la DB en read-only."""
    tmp = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
    try:
        with entry.open_binary() as src:
            tmp.write(src.read())
        tmp.flush(); tmp.close()
        conn = sqlite3.connect(f"file:{tmp.name}?mode=ro", uri=True)
        return conn, tmp.name
    except Exception:
        try: tmp.close()
        except Exception: pass
        return None, None

def extract_module_usage(src_dir, export_dir, skip_md5=None, **kwargs):
    freq, carbase, catalog = {}, {}, {}

    # 1. FREQUENCY
    for entry in iter_entries(src_dir):
        rel = entry.rel_path.replace('\\', '/')
        if rel.endswith('Scan/Update/.FREQUENCY') or rel.endswith('/Update/.FREQUENCY'):
            try:
                with entry.open_text() as f:
                    freq = json.load(f)
            except Exception as e:
                logging.warning(f".FREQUENCY illisible : {e}")

        elif rel.endswith('Scan/Update/.AllUpdateList') or rel.endswith('Scan/Update/.UpdateList'):
            try:
                with entry.open_text() as f:
                    txt = f.read()
                data = json.loads(txt)
                for cat in data if isinstance(data, list) else []:
                    for u in cat.get('updateList', []) or []:
                        mid = u.get('id')
                        if not mid: continue
                        # Ne pas écraser une entrée déjà présente (priorité au 1er)
                        catalog.setdefault(mid, {
                            'name': u.get('name', ''),
                            'localV': u.get('localVersion', ''),
                            'cloudV': u.get('version', ''),
                            'useNum': u.get('useNum', ''),
                            'allUseNum': u.get('allUseNum', ''),
                            'iconUrl': u.get('iconUrl', ''),
                        })
            except Exception as e:
                logging.debug(f"UpdateList parse fail {rel}: {e}")

        elif rel.endswith('copyData/CopyInfos.db') or rel.endswith('/CopyInfos.db'):
            conn, tmppath = _open_db_copy(entry)
            if not conn: continue
            try:
                cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
                if any(t[0] == 'CARBASE_INFO' for t in cur.fetchall()):
                    for r in conn.execute("SELECT CAR_CODE,CAR_NAME,VERSION,CAR_LIB_SIZE FROM CARBASE_INFO"):
                        carbase[r[0]] = {'name': r[1] or '', 'version': r[2] or '', 'size': r[3] or 0}
            except Exception as e:
                logging.warning(f"CARBASE_INFO read fail : {e}")
            finally:
                try: conn.close()
                except Exception: pass
                try: os.unlink(tmppath)
                except Exception: pass

    if not freq and not carbase:
        return []

    # Set complet de toutes les clés vues (freq + catalogue + carbase)
    all_ids = set(freq) | set(carbase) | set(catalog)
    rows = []
    for mid in all_ids:
        cb = carbase.get(mid, {})
        cat = catalog.get(mid, {})
        size_mb = (cb.get('size', 0) or 0) / 1e6
        rows.append([
            mid,
            cb.get('name', '') or cat.get('name', ''),
            cb.get('version', ''),
            f"{size_mb:.2f}" if size_mb else '',
            freq.get(mid, 0),
            cat.get('useNum', ''),
            cat.get('allUseNum', ''),
            cat.get('localV', ''),
            cat.get('cloudV', ''),
            cat.get('iconUrl', ''),
        ])
    # Trier par fréquence décroissante puis par nom
    rows.sort(key=lambda r: (-(r[4] or 0), r[1] or ''))

    f, w = open_csv(export_dir, 'modules_usage.csv', HEADER)
    try:
        for r in rows:
            w.writerow(r)
    finally:
        f.close()
    logging.info(f"Modules usage : {len(rows)} modules ({sum(1 for r in rows if r[4])} utilisés)")
    return rows
