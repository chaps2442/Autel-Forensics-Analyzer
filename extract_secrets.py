# extract_secrets.py — AFAP v2.0.0
# Auteur : Vincent Chapeau — Teel Technologies Canada (vincent.chapeau@teeltechcanada.com)
#
# Ramassage des artefacts cryptographiques / d'authentification présents sur
# une tablette Autel :
#
#   - Scan/Data/pem/*.pem                         (clés publiques RSA Autel)
#   - Scan/Data/ImCertificate/*.txt               (certificats IM* compactés base64)
#   - Scan/.licence.ini                           (licence Scan chiffrée)
#   - tmp/rdp_client.ini                          (config RPC + clés statiques VCI DTxx)
#   - .auth_all_car                               (flag d'auth interne)
#   - data/.push_deviceid                         (identifiant push device)
#   - .jpush/.jdevice_id_map.bat                  (JPush internal mapping)
#   - .jpush/.jpush_uid.bat                       (JPush UID)
#
# Sortie : secrets_found.csv  +  copie brute des PEM dans <export>/secrets/

import csv
import logging
import os
import shutil
from core_scanner import iter_entries, open_csv

HEADER = ['type', 'source_path', 'size_bytes', 'preview', 'exported_to']

TARGETS = {
    # rel_path suffix → (label, type)
    '/Scan/Data/pem/':                   ('public_key_pem',   'PUBLIC_KEY'),
    '/Scan/Data/ImCertificate/':         ('im_certificate',   'CERTIFICATE'),
    '/Scan/.licence.ini':                ('scan_licence',     'LICENCE'),
    '/tmp/rdp_client.ini':               ('rdp_client_keys',  'RDP_KEYS'),
    '/.auth_all_car':                    ('auth_flag',        'AUTH_FLAG'),
    '/data/.push_deviceid':              ('push_device_id',   'DEVICE_ID'),
    '/.jpush/.jdevice_id_map.bat':       ('jpush_map',        'JPUSH_MAP'),
    '/.jpush/.jpush_uid.bat':            ('jpush_uid',        'JPUSH_UID'),
}

def _match(rel):
    """Retourne (label, type) si l'entry correspond à un target connu."""
    p = '/' + rel.replace('\\', '/')
    for suffix, (label, kind) in TARGETS.items():
        if suffix.endswith('/'):
            if suffix in p:
                return label, kind
        else:
            if p.endswith(suffix):
                return label, kind
    return None, None

def _preview(entry, maxlen=200):
    try:
        with entry.open_text(errors='replace') as f:
            txt = f.read(2000)
        # Aplatis et tronque
        return (txt.replace('\r', ' ').replace('\n', ' '))[:maxlen]
    except Exception:
        return ''

def extract_secrets(src_dir, export_dir, skip_md5=None, **kwargs):
    rows = []
    out_dir = os.path.join(export_dir, 'secrets')

    for entry in iter_entries(src_dir):
        label, kind = _match(entry.rel_path)
        if not kind:
            continue

        size = 0
        exported = ''
        try:
            with entry.open_binary() as f:
                data = f.read()
            size = len(data)
        except Exception:
            data = b''

        # Pour les artefacts "à conserver" (PEM, certs, licence, rdp), on fait
        # une copie binaire dans <export>/secrets/<rel_path>
        if kind in ('PUBLIC_KEY', 'CERTIFICATE', 'LICENCE', 'RDP_KEYS', 'JPUSH_UID', 'JPUSH_MAP'):
            try:
                rel = entry.rel_path.lstrip('/\\').replace('\\', '/')
                dest = os.path.join(out_dir, rel)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with open(dest, 'wb') as out:
                    out.write(data)
                exported = os.path.relpath(dest, export_dir)
            except Exception as e:
                logging.warning(f"Copie secret {entry.rel_path} échouée: {e}")

        rows.append([label, entry.rel_path, size, _preview(entry), exported])

    if not rows:
        return []

    f, w = open_csv(export_dir, 'secrets_found.csv', HEADER)
    try:
        for r in rows:
            w.writerow(r)
    finally:
        f.close()
    logging.info(f"Secrets : {len(rows)} artefact(s) cryptographique(s)/auth ramassé(s)")
    return rows
