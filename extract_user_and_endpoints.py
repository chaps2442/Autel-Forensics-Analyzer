# extract_user_and_endpoints.py (version VFS)
# Auteur : Vincent Chapeau — Teel Technologies Canada (vincent.chapeau@teeltechcanada.com)
import csv
import re
import logging
import datetime
from core_scanner import iter_entries, iter_text_lines_entry, should_skip, open_csv

UID_RE = re.compile(r'\buserId\s*[:=]\s*(\d+)\b', re.IGNORECASE)
URL_RE = re.compile(r'https?://[^\s\'"]+', re.IGNORECASE)

def extract_user_and_endpoints(src_dir, export_dir, skip_md5=None, **kwargs):
    fu, wu = open_csv(export_dir, 'userId_found.csv', ['source_path', 'userId', 'date_modification'])
    fe, we = open_csv(export_dir, 'endpoints_found.csv', ['source_path', 'endpoint', 'date_modification'])
    results = []

    try:
        for entry in iter_entries(src_dir, include_ext=('.log', '.txt')):
            if entry.is_os and should_skip(entry.path, skip_md5):
                continue
            
            try:
                mtime = datetime.datetime.fromtimestamp(entry.mtime).strftime('%Y-%m-%d %H:%M:%S') if entry.mtime else "Date Inconnue"
            except Exception:
                mtime = "Date Inconnue"

            try:
                for line in iter_text_lines_entry(entry):
                    for m in UID_RE.finditer(line):
                        wu.writerow([entry.rel_path, m.group(1), mtime])
                        results.append(m.group(1))
                    for m in URL_RE.finditer(line):
                        we.writerow([entry.rel_path, m.group(0), mtime])
                        results.append(m.group(0))
            except Exception as e:
                logging.warning(f"Erreur lecture {entry.rel_path}: {e}")
    finally:
        fu.close()
        fe.close()
        
    return results
