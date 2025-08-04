# extract_passwords.py

import os
import csv
import re
import logging
import json

def extract_passwords(src_dir, export_dir, skip_md5=None, progress_callback=None, **kwargs):
    """
    Extrait les paires de numéro de série (sn) et mot de passe (pwd) trouvées dans les logs.
    Recherche deux formats : le format texte simple ("sn: ... pwd: ...") et le format JSON.
    """
    out_path = os.path.join(export_dir, 'pwd_sn_found.csv')
    passwords_found = []
    seen = set() # Pour éviter les doublons

    # --- Regex pour le format texte simple ---
    sn_re_text = re.compile(r'sn[:=]\s*(\S+)')
    pwd_re_text = re.compile(r'pwd[:=]\s*(\S+)')
    
    # --- Regex pour le format JSON ---
    json_re = re.compile(r'queryAppInfo encrypt strJson = ({.*?})$')

    files_to_scan = [os.path.join(root, fname) for root, _, fnames in os.walk(src_dir) for fname in fnames if fname.lower().endswith(('.log', '.txt'))]
    total_files = len(files_to_scan)
    if progress_callback: progress_callback(0, total_files)
    
    with open(out_path, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f)
        writer.writerow(['serial', 'password', 'format_source', 'path'])
        
        for i, full_path in enumerate(files_to_scan, 1):
            if progress_callback: progress_callback(i, total_files)
            rel_path = os.path.relpath(full_path, src_dir)
            
            try:
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as rf:
                    content = rf.read()
                    
                    # --- Méthode 1 : Recherche du format texte ---
                    sns = sn_re_text.findall(content)
                    pwds = pwd_re_text.findall(content)
                    for sn, pwd in zip(sns, pwds):
                        # Nettoyage simple des valeurs
                        sn_cleaned = sn.strip('",')
                        pwd_cleaned = pwd.strip('",')
                        key = (sn_cleaned, pwd_cleaned)
                        if key not in seen:
                            seen.add(key)
                            row = [sn_cleaned, pwd_cleaned, "Texte", rel_path]
                            passwords_found.append(row)
                            writer.writerow(row)
                            
                    # --- Méthode 2 : Recherche du format JSON ---
                    for match in json_re.finditer(content):
                        try:
                            json_data = json.loads(match.group(1))
                            sn = json_data.get("sn")
                            pwd = json_data.get("password")
                            if sn and pwd:
                                key = (sn, pwd)
                                if key not in seen:
                                    seen.add(key)
                                    row = [sn, pwd, "JSON", rel_path]
                                    passwords_found.append(row)
                                    writer.writerow(row)
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                logging.warning(f"Erreur lors de la lecture du fichier {rel_path}: {e}")
                continue
                
    return passwords_found
