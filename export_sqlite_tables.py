# export_sqlite_tables.py

import os
import sqlite3
import csv
import logging

def export_sqlite_tables(src_dir, export_dir, tables=None, skip_md5=None, progress_callback=None, **kwargs):
    """
    Exporte le contenu des tables spécifiées depuis toutes les BDD SQLite trouvées.
    """
    tables_to_export = tables or []
    if not tables_to_export:
        if progress_callback: progress_callback(1, 1)
        return []
    
    db_files_found = [os.path.join(root, fname) for root, _, fnames in os.walk(src_dir) for fname in fnames if fname.lower().endswith(('.db', '.sqlite', '.db3'))]
    total_dbs = len(db_files_found)
    if progress_callback: progress_callback(0, total_dbs)
    
    exported_tables_info = []

    for i, db_path in enumerate(db_files_found, 1):
        if progress_callback: progress_callback(i, total_dbs)
        
        # Vérification de l'en-tête pour être sûr que c'est bien une BDD SQLite
        try:
            with open(db_path, 'rb') as f:
                if not f.read(16).startswith(b'SQLite format 3\x00'):
                    continue
        except IOError:
            continue

        try:
            conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
            available_tables = {r[0] for r in cur.fetchall()}
            
            for table_name in tables_to_export:
                if table_name in available_tables:
                    out_csv = os.path.join(export_dir, f"{os.path.basename(db_path)}_{table_name}.csv")
                    with open(out_csv, 'w', newline='', encoding='utf-8-sig') as cf:
                        writer = csv.writer(cf)
                        cur.execute(f"SELECT * FROM '{table_name}';")
                        # Écriture de l'en-tête (noms de colonnes)
                        writer.writerow([description[0] for description in cur.description])
                        # Écriture des données
                        writer.writerows(cur.fetchall())
                        exported_tables_info.append(f"{os.path.basename(db_path)} -> {table_name}")
            conn.close()
        except sqlite3.Error as e:
            logging.error(f"Erreur SQLite avec le fichier {db_path}: {e}")
            
    return exported_tables_info