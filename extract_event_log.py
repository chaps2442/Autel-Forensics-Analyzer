# extract_event_log.py — AFAP v2.0.0
# Auteur : Vincent Chapeau — Teel Technologies Canada
# Contact : vincent.chapeau@teeltechcanada.com
#
# Scan/EventLog/<epoch_ms> : journaux applicatifs internes Autel.
# Format observé empiriquement :
#   - Le contenu fichier est une chaîne HEX (lowercase) d'octets < 0x80
#     (donc bytes ASCII valides après bytes.fromhex).
#   - Une fois décodés, les 155+ premiers octets sont IDENTIQUES entre fichiers
#     d'une même tablette → en-tête structurel fixe (provisioning / signature).
#   - Le payload qui suit est obfusqué (probablement schéma de substitution
#     propriétaire : `byte & 0x0f` → nibble, `byte & 0xf0` → marqueur de type).
#     Sans rétro-engineering complet de l'APK MaxiIM, le décodage exact reste
#     ouvert.
#
# Ce module produit donc :
#   - event_log_timeline.csv : 1 ligne par event avec timestamp, taille,
#     aperçu hex + aperçu ASCII décodé (utile pour analyse manuelle ultérieure)
#   - event_log/<epoch_ms>.hex   : copie brute (hex)
#   - event_log/<epoch_ms>.bin   : version décodée bytes.fromhex (pour outils
#     tiers : CyberChef, Detect It Easy, Ghidra, etc.)

import csv
import datetime
import logging
import os
from core_scanner import iter_entries, open_csv

HEADER = ['filename', 'timestamp_ms', 'datetime_local', 'size_raw_chars',
          'size_decoded_bytes', 'preview_hex', 'preview_ascii',
          'source_path', 'exported_hex', 'exported_bin']

def _printable(b):
    """Renvoie une string où les bytes non-printables sont remplacés par '.'."""
    return ''.join((chr(x) if 32 <= x < 127 else '.') for x in b)

def extract_event_log(src_dir, export_dir, skip_md5=None, **kwargs):
    rows = []
    out_dir = os.path.join(export_dir, 'event_log')

    for entry in iter_entries(src_dir):
        rel = entry.rel_path.replace('\\', '/')
        if '/Scan/EventLog/' not in '/' + rel:
            continue
        name = os.path.basename(rel)
        if not name.isdigit():
            continue
        try:
            ts_ms = int(name)
            dt = datetime.datetime.fromtimestamp(ts_ms / 1000).isoformat()
        except Exception:
            ts_ms, dt = 0, ''

        try:
            with entry.open_binary() as f:
                raw = f.read()
        except Exception as e:
            logging.warning(f"EventLog read fail {rel}: {e}")
            continue

        raw_text = raw.decode('ascii', errors='replace').strip()
        # Décode hex si possible
        decoded = b''
        try:
            if len(raw_text) % 2 == 0:
                decoded = bytes.fromhex(raw_text)
        except Exception:
            decoded = b''

        preview_hex = raw_text[:80]
        preview_ascii = _printable(decoded[:80]) if decoded else ''

        # Copies sur disque (hex + bin)
        exported_hex, exported_bin = '', ''
        try:
            os.makedirs(out_dir, exist_ok=True)
            hex_path = os.path.join(out_dir, f"{name}.hex")
            with open(hex_path, 'w', encoding='utf-8') as out:
                out.write(raw_text)
            exported_hex = os.path.relpath(hex_path, export_dir)
            if decoded:
                bin_path = os.path.join(out_dir, f"{name}.bin")
                with open(bin_path, 'wb') as out:
                    out.write(decoded)
                exported_bin = os.path.relpath(bin_path, export_dir)
        except Exception as e:
            logging.warning(f"EventLog copy fail {rel}: {e}")

        rows.append([name, ts_ms, dt, len(raw_text), len(decoded),
                     preview_hex, preview_ascii, rel, exported_hex, exported_bin])

    if not rows:
        return []

    rows.sort(key=lambda r: r[1])
    f, w = open_csv(export_dir, 'event_log_timeline.csv', HEADER)
    try:
        for r in rows:
            w.writerow(r)
    finally:
        f.close()
    logging.info(f"EventLog : {len(rows)} event(s) chronologisé(s) + décodés (hex→bin)")
    return rows
