# export_sqlite_tables.py (version VFS)
# Auteur : Vincent Chapeau — Teel Technologies Canada (vincent.chapeau@teeltechcanada.com)
import os
import sqlite3
import csv
import logging
import tempfile
import datetime
from core_scanner import iter_entries, open_csv

def export_sqlite_tables(src_dir, export_dir, tables=None, **kwargs):
    tables_to_export = tables or []
    if not tables_to_export:
        return []

    exported = []
    
    for entry in iter_entries(src_dir, include_ext=('.db', '.sqlite', '.db3')):
        temp_db_path = None
        conn = None
        try:
            with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
                temp_db_path = tmp.name
                with entry.open_binary() as f_in:
                    tmp.write(f_in.read())

            conn = sqlite3.connect(f'file:{temp_db_path}?mode=ro', uri=True)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
            available_tables = {r[0] for r in cur.fetchall()}

            try:
                mtime = datetime.datetime.fromtimestamp(entry.mtime).strftime('%Y-%m-%d %H:%M:%S') if entry.mtime else "Date Inconnue"
            except Exception:
                mtime = "Date Inconnue"
            
            for table_name in tables_to_export:
                if table_name in available_tables:
                    sanitized_path = entry.rel_path.replace('/', '_').replace('\\', '_').strip('_')
                    out_csv_path = os.path.join(export_dir, f"{sanitized_path}_{table_name}.csv")
                    
                    with open(out_csv_path, 'w', newline='', encoding='utf-8-sig') as cf:
                        writer = csv.writer(cf)
                        cur.execute(f"SELECT * FROM '{table_name}';")
                        header = [d[0] for d in cur.description] + ['date_modification_fichier_db']
                        writer.writerow(header)
                        for row in cur.fetchall():
                            writer.writerow(list(row) + [mtime])
                    exported.append(f"{entry.rel_path} -> {table_name}")
            
        except sqlite3.Error as e:
            logging.error(f"Erreur SQLite sur {entry.rel_path}: {e}")
        finally:
            if conn:
                conn.close()
            if temp_db_path and os.path.exists(temp_db_path):
                os.unlink(temp_db_path)
                
    return exported
