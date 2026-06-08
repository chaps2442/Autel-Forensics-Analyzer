# extract_passwords.py (version VFS)
# Auteur : Vincent Chapeau — Teel Technologies Canada (vincent.chapeau@teeltechcanada.com)
import csv
import re
import logging
import json
import datetime
from core_scanner import iter_entries, iter_text_lines_entry, should_skip, open_csv

SN_RE = re.compile(r'(?:device_serialno|deviceSn|sn)\s*[:=]\s*([\w-]+)', re.IGNORECASE)
PWD_RE = re.compile(r'(?:device_password|password|pwd)\s*[:=]\s*(\S+)', re.IGNORECASE)
JSON_INLINE = re.compile(r'queryAppInfo\s+encrypt\s+strJson\s*=\s*(\{.*\})\s*$', re.IGNORECASE)

def extract_passwords(src_dir, export_dir, skip_md5=None, **kwargs):
    f_csv, w = open_csv(export_dir, 'pwd_sn_found.csv', ['source_path', 'serial', 'password', 'format_source', 'date_modification'])
    seen, results = set(), []
    
    try:
        for entry in iter_entries(src_dir, include_ext=('.log', '.txt')):
            if entry.is_os and should_skip(entry.path, skip_md5):
                continue

            try:
                mtime = datetime.datetime.fromtimestamp(entry.mtime).strftime('%Y-%m-%d %H:%M:%S') if entry.mtime else "Date Inconnue"
            except Exception:
                mtime = "Date Inconnue"

            last_sn, json_buffer, buffering_json = None, [], False
            try:
                for line in iter_text_lines_entry(entry):
                    # La logique interne de parsing de ligne ne change pas
                    if m_json_inline := JSON_INLINE.search(line):
                        try:
                            obj = json.loads(m_json_inline.group(1))
                            sn = obj.get('sn') or obj.get('deviceSn'); pwd = obj.get('password') or obj.get('pwd')
                            if sn and pwd and (sn, pwd) not in seen:
                                seen.add((sn, pwd)); w.writerow([entry.rel_path, sn, pwd, 'JSON-inline', mtime]); results.append((sn, pwd))
                        except Exception: pass
                        continue

                    if '{' in line and not buffering_json and 'queryAppInfo' in line:
                        buffering_json = True; json_buffer = [line[line.find('{'):]]; continue
                    if buffering_json:
                        json_buffer.append(line)
                        if '}' in line:
                            buffering_json = False; joined = ''.join(json_buffer)
                            try:
                                obj = json.loads(joined[joined.find('{'):joined.rfind('}') + 1])
                                sn = obj.get('sn') or obj.get('deviceSn'); pwd = obj.get('password') or obj.get('pwd')
                                if sn and pwd and (sn, pwd) not in seen:
                                    seen.add((sn, pwd)); w.writerow([entry.rel_path, sn, pwd, 'JSON-multilignes', mtime]); results.append((sn, pwd))
                            except Exception: pass
                            json_buffer = []
                        continue

                    sn_m, pwd_m = SN_RE.search(line), PWD_RE.search(line)
                    if sn_m and pwd_m:
                        sn, pwd = sn_m.group(1).strip('",'), pwd_m.group(1).strip('",')
                        if (sn, pwd) not in seen:
                            seen.add((sn, pwd)); w.writerow([entry.rel_path, sn, pwd, 'Texte (ligne unique)', mtime]); results.append((sn, pwd)); last_sn = None
                        continue
                    
                    if sn_m: last_sn = sn_m.group(1).strip('",')
                    if pwd_m and last_sn:
                        pwd = pwd_m.group(1).strip('",')
                        if (last_sn, pwd) not in seen:
                            seen.add((last_sn, pwd)); w.writerow([entry.rel_path, last_sn, pwd, 'Texte (lignes séparées)', mtime]); results.append((last_sn, pwd))
                        last_sn = None
            except Exception as e:
                logging.warning(f"Erreur lecture {entry.rel_path}: {e}")
    finally:
        f_csv.close()
    return results
