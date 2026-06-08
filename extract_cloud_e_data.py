# extract_cloud_e_data.py — AFAP v2.0.0
# Auteur : Vincent Chapeau — Teel Technologies Canada (vincent.chapeau@teeltechcanada.com)
#
# Parse Scan/CloudEData/*.json — chacun documente une OPÉRATION DE DIAGNOSTIC
# ou de PROGRAMMATION DE CLÉ effectuée sur un véhicule par la tablette.
#
# Le nom de fichier suit le format <epoch_ms>_<ProductSN>.json
# et le JSON contient (entre autres) :
#   ProductSN, OSVersion, AppVersion
#   VCIName / VCIFirmVersion / VCISoftVersion
#   VehicleArea, VehicleCar, VehicleBrand, VehicleModel, VehicleYear, VehicleVIN
#   MenuPath  (chemin complet de la fonction Autel utilisée)
#   FuncName  (nom de la fonction — clé info forensique)
#   FuncMode  (OBD / Manuel …)
#   FileType  (EEPROM / FLASH …)
#   PartType, PartManufacturer, PartSoftVersion …
#   ip        (IP locale du device au moment de l'op)
#
# Sortie : cloud_e_data.csv

import csv
import json
import logging
import os
import datetime
from core_scanner import iter_entries, open_csv

HEADER = [
    'date_operation', 'product_sn', 'os_version', 'app_version',
    'vci_name', 'vci_firm', 'vci_soft',
    'vehicle_area', 'vehicle_brand', 'vehicle_model', 'vehicle_year', 'vehicle_vin',
    'func_mode', 'func_name', 'menu_path',
    'file_type', 'part_type', 'part_manufacturer', 'part_soft_version',
    'ip_locale', 'index_file', 'source_path'
]

def _ts_from_name(name):
    """Le préfixe du nom est un epoch_ms — utile si le JSON ne contient pas de date."""
    try:
        base = os.path.basename(name).split('_')[0]
        ts = int(base) / 1000
        return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return ''

def _g(d, *keys):
    """Récupère la 1ère clé présente (gère les variantes avec espace en suffixe)."""
    for k in keys:
        if k in d and d[k] not in (None, ''):
            return d[k]
    return ''

def extract_cloud_e_data(src_dir, export_dir, skip_md5=None, **kwargs):
    rows = []
    for entry in iter_entries(src_dir, include_ext=('.json',)):
        rel = entry.rel_path.replace('\\', '/')
        if '/Scan/CloudEData/' not in '/' + rel:
            continue
        try:
            with entry.open_text() as f:
                data = json.load(f)
        except Exception as e:
            logging.warning(f"CloudEData parse fail {rel}: {e}")
            continue

        if not isinstance(data, dict):
            continue

        row = [
            _ts_from_name(rel),
            _g(data, 'ProductSN', 'productSN'),
            _g(data, 'OSVersion', 'osVersion '),
            _g(data, 'AppVersion', 'appVersion '),
            _g(data, 'VCIName', 'vciName '),
            _g(data, 'VCIFirmVersion', 'vciFirmVersion '),
            _g(data, 'VCISoftVersion', 'vciSoftVersion '),
            _g(data, 'VehicleArea'),
            _g(data, 'VehicleBrand', 'VehicleCar'),
            _g(data, 'VehicleModel'),
            _g(data, 'VehicleYear'),
            _g(data, 'VehicleVIN'),
            _g(data, 'FuncMode'),
            _g(data, 'FuncName'),
            _g(data, 'MenuPath'),
            _g(data, 'FileType'),
            _g(data, 'PartType'),
            _g(data, 'PartManufacturer'),
            _g(data, 'PartSoftVersion'),
            _g(data, 'ip'),
            _g(data, 'index'),
            rel,
        ]
        rows.append(row)

    if not rows:
        return []

    f, w = open_csv(export_dir, 'cloud_e_data.csv', HEADER)
    try:
        for r in rows:
            w.writerow(r)
    finally:
        f.close()
    logging.info(f"CloudEData : {len(rows)} opération(s) véhicule documentée(s)")
    return rows
