# extract_wal_indicators.py — AFAP v2.0.0
# Auteur : Vincent Chapeau — Teel Technologies Canada
# Contact : vincent.chapeau@teeltechcanada.com
#
# Détecte tous les WAL (.db-wal) et SHM (.db-shm) accompagnant les bases
# SQLite trouvées dans la source. Mesure la taille du WAL et estime le
# nombre de frames présentes (chaque frame = 24 octets header + page).
#
# IMPORTANT : ce module N'EFFECTUE PAS de carving / récupération de
# transactions effacées. Il signale uniquement la présence des WAL et
# fournit assez d'info au rapport pour recommander l'utilisation d'un outil
# forensique tiers spécialisé (Sanderson Forensics SQLite Recovery,
# FQLite, Oxygen Forensic SQLite Viewer, BlackBag BlackLight, …).
#
# Sortie : wal_indicators.csv

import csv
import logging
import os
import struct
from core_scanner import iter_entries, open_csv

HEADER = ['db_path', 'wal_path', 'wal_size_bytes', 'wal_magic',
          'wal_page_size', 'estimated_frames', 'shm_present', 'has_dash_journal']

# WAL magic bytes (SQLite3 WAL format, big-endian "0x377f0682" or "0x377f0683")
WAL_MAGIC = (b'\x37\x7f\x06\x82', b'\x37\x7f\x06\x83')

def _read_wal_header(entry):
    """Lit les 32 premiers octets d'un WAL et retourne (magic_hex, page_size)."""
    try:
        with entry.open_binary() as f:
            hdr = f.read(32)
        if len(hdr) < 32:
            return '', 0
        magic = hdr[:4]
        # WAL header: bytes 0-3 magic, 4-7 file format version, 8-11 page size (BE)
        page_size = struct.unpack('>I', hdr[8:12])[0]
        return magic.hex(), page_size
    except Exception:
        return '', 0

def extract_wal_indicators(src_dir, export_dir, skip_md5=None, **kwargs):
    # On parcourt une 1ère fois pour indexer tous les fichiers par chemin
    by_path = {}
    for entry in iter_entries(src_dir):
        rel = entry.rel_path.replace('\\', '/')
        by_path[rel] = entry

    rows = []
    for rel, entry in by_path.items():
        # On déclenche sur .db-wal présent
        if not rel.endswith('-wal'):
            continue
        # Le -wal indique une base SQLite (peut-être absente si dump partiel)
        if rel.endswith('.db-wal') or rel.endswith('.sqlite-wal') or rel.endswith('.db3-wal'):
            db_rel = rel[:-4]   # retire "-wal"
        else:
            # WAL d'un nom sans extension (ex: visit_history-wal)
            db_rel = rel[:-4]

        # Taille WAL
        try:
            with entry.open_binary() as f:
                f.seek(0, 2)
                size = f.tell()
        except Exception:
            size = 0
        magic_hex, page_size = _read_wal_header(entry)
        magic_bytes = bytes.fromhex(magic_hex) if magic_hex else b''
        is_wal = magic_bytes[:4] in WAL_MAGIC
        # Estimation frames : (size - 32) / (24 + page_size)
        frames = 0
        if is_wal and page_size > 0 and size > 32:
            frames = max(0, (size - 32) // (24 + page_size))

        # SHM associé ?
        shm_present = (db_rel + '-shm') in by_path

        # -journal présent ? (rollback journal, ancien mode SQLite)
        has_journal = (db_rel + '-journal') in by_path

        rows.append([db_rel, rel, size, magic_hex,
                     page_size if is_wal else 0, frames,
                     'Oui' if shm_present else 'Non',
                     'Oui' if has_journal else 'Non'])

    if not rows:
        return []

    f, w = open_csv(export_dir, 'wal_indicators.csv', HEADER)
    try:
        for r in sorted(rows, key=lambda x: -x[2]):  # plus gros WAL d'abord
            w.writerow(r)
    finally:
        f.close()
    logging.info(f"WAL : {len(rows)} fichier(s) WAL détecté(s)")
    return rows
