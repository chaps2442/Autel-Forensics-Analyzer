# cli.py — AFAP v2.1.0 — Mode ligne de commande
# Auteur : Vincent Chapeau — Teel Technologies Canada (vincent.chapeau@teeltechcanada.com)
#
# Usage :
#   python cli.py --source <path> --out <dir> [--lang fr|en] [--skiplist <file>]
#                 [--modules vins,mac,...] [--no-vins] [--quiet]
#
# Exemples :
#   python cli.py --source ./KM100_B               --out ./out
#   python cli.py --source ./extraction.7z         --out ./out --lang en
#   python cli.py --source ./KM100_B --no-vins                # skip extract_vins
#   python cli.py --source ./KM100_B --modules cloud,vci,wal  # uniquement ces 3

import argparse
import datetime
import logging
import os
import sys

# Importer tous les modules
from utils import setup_logging, get_tablet_info, export_tablet_info_csv
from extract_vins import extract_all_vins
from extract_log_events import extract_all_log_events
from extract_mac import extract_mac
from extract_user_and_endpoints import extract_user_and_endpoints
from extract_passwords import extract_passwords
from extract_vehicle_refs import extract_vehicle_refs
from extract_dcim_media import extract_dcim_media
from export_sqlite_tables import export_sqlite_tables
from create_timeline_report import create_timeline_report
from extract_cloud_e_data import extract_cloud_e_data
from extract_module_usage import extract_module_usage
from extract_vci_logs import extract_vci_logs
from extract_es_history import extract_es_history
from extract_external_storage import extract_external_storage
from extract_secrets import extract_secrets
from extract_event_log import extract_event_log
from extract_wal_indicators import extract_wal_indicators
from create_forensic_report import create_forensic_report

try:
    from i18n import set_lang
except ImportError:
    def set_lang(x): pass

# Catalogue des modules : nom court CLI → (display, fn, kwargs supplémentaires)
MODULES = {
    'vins':     ('VINs',                extract_all_vins, {}),
    'logs':     ('Log events',          extract_all_log_events, {}),
    'mac':      ('MAC + connexions',    extract_mac, {}),
    'user':     ('User/Endpoints',      extract_user_and_endpoints, {}),
    'pwd':      ('Passwords',           extract_passwords, {}),
    'vehref':   ('Vehicle refs',        extract_vehicle_refs, {}),
    'dcim':     ('DCIM media',          extract_dcim_media, {}),
    'sqlite':   ('SQLite tables',       export_sqlite_tables,
                 {'tables': ['tb_history_menu', 'tb_user_info', 'tb_vci_record']}),
    'cloud':    ('CloudEData',          extract_cloud_e_data, {}),
    'usage':    ('Module usage',        extract_module_usage, {}),
    'vci':      ('VCI logs',            extract_vci_logs, {}),
    'es':       ('ES history',          extract_es_history, {}),
    'storage':  ('External storage',    extract_external_storage, {}),
    'secrets':  ('Secrets',             extract_secrets, {}),
    'events':   ('EventLog',            extract_event_log, {}),
    'wal':      ('WAL indicators',      extract_wal_indicators, {}),
    'timeline': ('Timeline HTML',       create_timeline_report, {}),
    'report':   ('Forensic report',     create_forensic_report, {}),
}

# Ordre par défaut (rapports en dernier)
DEFAULT_ORDER = ['vins', 'logs', 'mac', 'user', 'pwd', 'vehref', 'dcim', 'sqlite',
                 'cloud', 'usage', 'vci', 'es', 'storage', 'secrets', 'events',
                 'wal', 'timeline', 'report']


def main(argv=None):
    p = argparse.ArgumentParser(
        description="AFAP v2.1.0 — Autel Forensics Analyzer (CLI mode)",
        epilog="Exemple : python cli.py --source ./KM100_B --out ./out --lang en")
    p.add_argument('--source', '-s', required=True,
                   help="Source : dossier d'extraction OU archive .zip/.7z")
    p.add_argument('--out', '-o', required=True,
                   help="Dossier d'export (créé si absent)")
    p.add_argument('--lang', '-l', choices=['fr', 'en'], default='fr',
                   help="Langue du rapport (défaut: fr)")
    p.add_argument('--skiplist', help="Fichier hash_skiplist.txt (défaut: à côté du script)")
    p.add_argument('--modules', '-m',
                   help=f"Modules à exécuter (csv), parmi : {', '.join(MODULES.keys())}. "
                        "Défaut : tous, dans l'ordre standard.")
    p.add_argument('--skip', help="Modules à SAUTER (csv)")
    p.add_argument('--quiet', '-q', action='store_true', help="Sortie minimale")
    p.add_argument('--version', action='version', version='AFAP 2.1.0')
    args = p.parse_args(argv)

    set_lang(args.lang)

    if not os.path.exists(args.source):
        print(f"ERREUR : source introuvable : {args.source}", file=sys.stderr)
        return 2

    # Skiplist
    script_dir = os.path.dirname(os.path.abspath(__file__))
    skiplist_file = args.skiplist or os.path.join(script_dir, 'hash_skiplist.txt')
    skip_md5 = set()
    if os.path.isfile(skiplist_file):
        with open(skiplist_file, 'r', encoding='utf-8') as f:
            skip_md5 = {l.strip().lower() for l in f if l.strip()}

    # Sélection des modules
    if args.modules:
        wanted = [m.strip() for m in args.modules.split(',')]
        order = [m for m in wanted if m in MODULES]
        unknown = set(wanted) - set(MODULES.keys())
        if unknown:
            print(f"WARN : modules inconnus ignorés : {unknown}", file=sys.stderr)
    else:
        order = list(DEFAULT_ORDER)
    if args.skip:
        skip = {m.strip() for m in args.skip.split(',')}
        order = [m for m in order if m not in skip]

    # Identification + dossier export
    info = get_tablet_info(args.source)
    serial = info.get('serial', 'inconnu')
    export_dir = os.path.join(args.out, f"Analyse_{serial}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}")
    os.makedirs(export_dir, exist_ok=True)
    setup_logging(export_dir)
    export_tablet_info_csv(export_dir, info)

    if not args.quiet:
        print(f"[AFAP 2.1.0] Source: {args.source}")
        print(f"             Tablette: {serial} ({info.get('product_model','?')})  Langue rapport: {args.lang}")
        print(f"             Export: {export_dir}")
        print(f"             Modules: {len(order)} → {','.join(order)}")
        print()

    # Exécution
    total = len(order)
    for i, key in enumerate(order, 1):
        display, fn, extra = MODULES[key]
        if not args.quiet:
            print(f"[{i:2d}/{total}] {display:<22}", end=' ', flush=True)
        try:
            kwargs = dict(src_dir=args.source, export_dir=export_dir, skip_md5=skip_md5)
            kwargs.update(extra)
            r = fn(**kwargs)
            n = len(r) if r else 0
            if not args.quiet:
                print(f"→ {n}")
        except Exception as e:
            logging.exception(f"Module {key} a échoué")
            if not args.quiet:
                print(f"ERR: {e}")

    if not args.quiet:
        print(f"\nTerminé. Rapport : {os.path.join(export_dir, 'rapport_forensique.md')}")
    print(export_dir)   # toujours imprimé pour piping
    return 0


if __name__ == '__main__':
    sys.exit(main())
