# extract_vehicle_refs.py

import os
import csv
import re
import logging

# Mots-clés à ignorer pour nettoyer les résultats
JUNK_KEYWORDS = {'system', 'menu', 'path', 'read', 'code', 'all', 'obd', 'selection'}

def extract_vehicle_refs(src_dir, export_dir, skip_md5=None, progress_callback=None, **kwargs):
    """
    Extrait les références de véhicules (Marque, Modèle, Années, OEM) 
    depuis les logs en appliquant des filtres pour ne garder que les données pertinentes.
    """
    out_path = os.path.join(export_dir, 'vehicule_refs_found.csv')
    refs_found = []
    
    # Regex pour extraire Marque, Modèle et Années de lignes comme "mainItem" : "Peugeot 308 2013-2016"
    re_main_item = re.compile(r'"mainItem"\s*:\s*"(?P<brand>\w+)\s+(?P<model>.*?)\s+(?P<year_start>\d{4})-(?P<year_end>\d{4})"')
    
    # Regex pour extraire les références OEM ou FCCID
    re_ref = re.compile(r'Reference (OEM|FCCID)[:=]\s*([^\s"]+)', re.IGNORECASE)

    files_to_scan = [os.path.join(root, fname) for root, _, fnames in os.walk(src_dir) for fname in fnames if fname.lower().endswith(('.json','.txt','.log'))]
    total_files = len(files_to_scan)
    if progress_callback: progress_callback(0, total_files)

    with open(out_path, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f)
        writer.writerow(['type', 'marque', 'modele', 'annees', 'reference', 'path'])
        
        for i, full_path in enumerate(files_to_scan, 1):
            if progress_callback: progress_callback(i, total_files)
            rel_path = os.path.relpath(full_path, src_dir)
            
            try:
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as rf:
                    for line in rf:
                        # Chercher les infos Marque/Modèle/Années
                        if match := re_main_item.search(line):
                            data = match.groupdict()
                            brand = data['brand'].strip()
                            model = data['model'].strip()
                            
                            # Filtres de pertinence
                            if len(brand) > 2 and brand.lower() not in JUNK_KEYWORDS:
                                row = ['Vehicule', brand, model, f"{data['year_start']}-{data['year_end']}", '', rel_path]
                                refs_found.append(row)
                                writer.writerow(row)
                        
                        # Chercher les références OEM/FCCID
                        if match := re_ref.search(line):
                            ref_type = match.group(1).upper() # OEM ou FCCID
                            ref_value = match.group(2).strip()
                            
                            # Filtres de pertinence
                            if len(ref_value) > 4:
                                row = [ref_type, '', '', '', ref_value, rel_path]
                                refs_found.append(row)
                                writer.writerow(row)
            except Exception as e:
                logging.warning(f"Erreur lecture fichier refs {rel_path}: {e}")

    return refs_found