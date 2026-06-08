# extract_es_history.py — AFAP v2.0.0
# Auteur : Vincent Chapeau — Teel Technologies Canada (vincent.chapeau@teeltechcanada.com)
#
# ES File Explorer (com.estrongs.android.pop) maintient un historique des
# dossiers/fichiers consultés et la liste des apps connues.
#
# Sources :
#   - Android/data/com.estrongs.android.pop/cache/visit_history  (SQLite)
#         table visit_history(id, isdir, title, path)
#         table web_icon(domain, icon)
#   - Android/data/com.estrongs.android.pop/appinfo.db           (SQLite)
#         table installed_app_info(package, app_name)
#
# Sorties :
#   - es_visit_history.csv   (chemins visités)
#   - es_installed_apps.csv  (apps connues d'ES File Explorer)
#
# Intérêt forensique :
#   - révèle SD externes/USB montées (UUID dans le path /storage/XXXX-XXXX/)
#   - révèle fichiers/APK manipulés
#   - liste des packages installés au moment du snapshot

import csv
import logging
import os
import sqlite3
import tempfile
from core_scanner import iter_entries, open_csv

VISIT_HEADER = ['id', 'isdir', 'title', 'path', 'source_path']
APPS_HEADER  = ['package', 'app_name', 'source_path']

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

def extract_es_history(src_dir, export_dir, skip_md5=None, **kwargs):
    visit_rows, app_rows = [], []

    for entry in iter_entries(src_dir):
        rel = entry.rel_path.replace('\\', '/')

        if rel.endswith('com.estrongs.android.pop/cache/visit_history'):
            conn, tmppath = _open_db_copy(entry)
            if not conn:
                continue
            try:
                tables = {t[0] for t in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if 'visit_history' in tables:
                    for r in conn.execute("SELECT id,isdir,title,path FROM visit_history"):
                        visit_rows.append([r[0], r[1], r[2] or '', r[3] or '', rel])
            except Exception as e:
                logging.warning(f"visit_history read fail : {e}")
            finally:
                try: conn.close()
                except Exception: pass
                try: os.unlink(tmppath)
                except Exception: pass

        elif rel.endswith('com.estrongs.android.pop/appinfo.db'):
            conn, tmppath = _open_db_copy(entry)
            if not conn:
                continue
            try:
                tables = {t[0] for t in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if 'installed_app_info' in tables:
                    for r in conn.execute("SELECT package, app_name FROM installed_app_info"):
                        app_rows.append([r[0] or '', r[1] or '', rel])
            except Exception as e:
                logging.warning(f"appinfo.db read fail : {e}")
            finally:
                try: conn.close()
                except Exception: pass
                try: os.unlink(tmppath)
                except Exception: pass

    if not visit_rows and not app_rows:
        return []

    if visit_rows:
        f, w = open_csv(export_dir, 'es_visit_history.csv', VISIT_HEADER)
        try:
            for r in visit_rows: w.writerow(r)
        finally:
            f.close()
    if app_rows:
        f, w = open_csv(export_dir, 'es_installed_apps.csv', APPS_HEADER)
        try:
            for r in app_rows: w.writerow(r)
        finally:
            f.close()

    logging.info(f"ES File Explorer : {len(visit_rows)} visites, {len(app_rows)} apps")
    return visit_rows + app_rows
