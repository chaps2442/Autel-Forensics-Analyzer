# extract_external_storage.py — AFAP v2.0.0
# Auteur : Vincent Chapeau — Teel Technologies Canada (vincent.chapeau@teeltechcanada.com)
#
# Détection des supports de stockage EXTERNES (SD/USB) montés à un moment
# donné sur la tablette, en croisant plusieurs sources :
#
#   - ES File Explorer visit_history (paths /storage/XXXX-XXXX/)
#   - chemins de stockage rencontrés dans .UpdateList ("storePath":["/storage/..."])
#   - chemins observés dans les logs (.log/.txt)
#
# Les UUID FAT/NTFS au format XXXX-XXXX (8 hex chars avec tiret au milieu)
# permettent d'identifier formellement le support physique correspondant.
#
# Sortie : external_storage_seen.csv

import csv
import logging
import os
import re
import sqlite3
import tempfile
from collections import defaultdict
from core_scanner import iter_entries, iter_text_lines_entry, open_csv

HEADER = ['volume_id', 'mount_path', 'nb_paths_seen', 'sample_paths', 'sources']

# UUID FAT32/exFAT : 4 hex - 4 hex (DE56-731B)
VOL_RE = re.compile(r'/storage/([0-9A-Fa-f]{4}-[0-9A-Fa-f]{4})(/[^"\s\\]*)?')

def _open_db_copy(entry):
    tmp = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
    try:
        with entry.open_binary() as src:
            tmp.write(src.read())
        tmp.flush(); tmp.close()
        return sqlite3.connect(f"file:{tmp.name}?mode=ro", uri=True), tmp.name
    except Exception:
        try: tmp.close()
        except Exception: pass
        return None, None

def extract_external_storage(src_dir, export_dir, skip_md5=None, **kwargs):
    volumes = defaultdict(lambda: {'paths': set(), 'sources': set()})

    # 1. visit_history ES File Explorer
    for entry in iter_entries(src_dir):
        rel = entry.rel_path.replace('\\', '/')
        if not rel.endswith('com.estrongs.android.pop/cache/visit_history'):
            continue
        conn, tmppath = _open_db_copy(entry)
        if not conn: continue
        try:
            for r in conn.execute("SELECT path FROM visit_history"):
                p = r[0] or ''
                for m in VOL_RE.finditer(p):
                    vid = m.group(1).upper()
                    volumes[vid]['paths'].add(p)
                    volumes[vid]['sources'].add('ES_visit_history')
        except Exception as e:
            logging.warning(f"visit_history scan fail : {e}")
        finally:
            try: conn.close()
            except Exception: pass
            try: os.unlink(tmppath)
            except Exception: pass

    # 2. Update lists + autres .json
    for entry in iter_entries(src_dir, include_ext=('.json', '.log', '.txt', '.ini')):
        rel = entry.rel_path.replace('\\', '/')
        try:
            for line in iter_text_lines_entry(entry):
                for m in VOL_RE.finditer(line):
                    vid = m.group(1).upper()
                    volumes[vid]['paths'].add(line.strip()[:200])
                    volumes[vid]['sources'].add(rel)
        except Exception:
            continue

    if not volumes:
        return []

    rows = []
    for vid, info in sorted(volumes.items()):
        paths = sorted(info['paths'])
        sample = ' | '.join(paths[:3])
        srcs = sorted(info['sources'])
        rows.append([vid, '/storage/' + vid + '/', len(paths), sample, ', '.join(srcs[:5])])

    f, w = open_csv(export_dir, 'external_storage_seen.csv', HEADER)
    try:
        for r in rows: w.writerow(r)
    finally:
        f.close()
    logging.info(f"Stockage externe : {len(rows)} volume(s) détecté(s)")
    return rows
