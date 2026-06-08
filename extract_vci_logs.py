# extract_vci_logs.py — AFAP v2.0.0
# Auteur : Vincent Chapeau — Teel Technologies Canada (vincent.chapeau@teeltechcanada.com)
#
# Scan/Data/.VciLog/*.log : logs détaillés du VCI (Vehicle Communication Interface)
# pendant les communications OBD avec un véhicule.
#
# Chaque log porte un timestamp dans son nom : VciLog-YYYYMMDDhhmmss.log
# L'entête contient l'identité matérielle (SN, model VCI, FW), puis le corps
# contient des lignes timestampées Android (MM-DD HH:MM:SS.mmm pid tid LEVEL TAG).
#
# Ce module produit DEUX CSV :
#   - vci_logs_index.csv      : index chronologique (1 ligne par fichier .log)
#   - vci_logs_events.csv     : lignes événementielles parsées (extraction)
#
# Patterns extraits :
#   - VINs en clair          (B-)F (mêmes contraintes que extract_vins)
#   - SetVehicleMake/Model   (jouée par l'app pour signaler la marque ciblée)
#   - PassThru/IoctlID       (commandes bas-niveau ISO 22900 / SAE J2534)
#   - Connexion VCI / paire BT
#
# Note : ces logs ne sont PAS attrapés par extract_log_events.py car les patterns
# y sont différents. C'est pourquoi on a un parseur dédié.

import csv
import logging
import os
import re
import datetime
from core_scanner import iter_entries, iter_text_lines_entry, open_csv

INDEX_HEADER = ['filename', 'datetime_log', 'size_bytes', 'sn_header', 'product_header',
                'os_version_header', 'vci_model_header', 'vci_fw_header', 'source_path']

EVENT_HEADER = ['date_log_fichier', 'timestamp_relatif', 'pid', 'tid', 'level',
                'tag', 'evenement', 'detail', 'source_path']

# Préfixe ligne Android : MM-DD HH:MM:SS.mmm  PID  TID  L  TAG: message
LOG_LINE_RE = re.compile(
    r'^(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+(\d+)\s+(\d+)\s+([VDIWE])\s+([\w_]+)\s*:\s*(.*)$'
)

PATTERNS = {
    'VIN_IN_LOG':          re.compile(r'\b([A-HJ-NPR-Z0-9]{17})\b'),
    'SET_VEHICLE_MAKE':    re.compile(r'SetVehicleMake[^:]*:\s*([\w\-\.]+)'),
    'SET_VEHICLE_MODEL':   re.compile(r'SetVehicleModel[^:]*:\s*([\w\-\.]+)'),
    'PASSTHRU_IOCTL':      re.compile(r'PassThruIoctl\s+ChannelID=(0x[0-9a-fA-F]+),\s*IoctlID=(0x[0-9a-fA-F]+)\s*result=(0x[0-9a-fA-F]+)'),
    'BT_PAIR':             re.compile(r'(?:bluetooth|bt).*?(connect|paired|pairing|disconnect)', re.I),
    'AUTH_RESULT':         re.compile(r'(auth|authentication)\s*[:=]\s*(success|fail|failed|ok|nok)', re.I),
    'KEY_OP_RESULT':       re.compile(r'FuncResult[":=\s]+["\']?(success|fail|failed|ok)', re.I),
}

def _parse_header(entry):
    """Lit l'en-tête (lignes en clair avant la première ligne timestampée)."""
    h = {'sn': '', 'product': '', 'os': '', 'vci_model': '', 'vci_fw': ''}
    try:
        with entry.open_text() as f:
            for i, line in enumerate(f):
                if i > 20:
                    break
                if m := re.match(r'\s*Sn:\s*(\S+)', line):
                    h['sn'] = m.group(1).strip()
                if m := re.match(r'\s*Product:\s*(\S+)', line):
                    h['product'] = m.group(1).strip()
                if m := re.match(r'\s*Os version:\s*(\S+)', line):
                    h['os'] = m.group(1).strip()
                if m := re.match(r'\s*Vci Name:\s*([^,]+).*model:\s*(\S+)', line):
                    h['vci_model'] = m.group(2).strip()
                if m := re.search(r'Fw Version:\s*(\S+)', line):
                    h['vci_fw'] = m.group(1).strip()
    except Exception:
        pass
    return h

def _date_from_name(name):
    """VciLog-YYYYMMDDhhmmss.log → ISO datetime."""
    m = re.match(r'VciLog-(\d{8})(\d{6})\.log', os.path.basename(name))
    if not m: return ''
    try:
        return datetime.datetime.strptime(m.group(1) + m.group(2), '%Y%m%d%H%M%S').isoformat()
    except Exception:
        return ''

def extract_vci_logs(src_dir, export_dir, skip_md5=None, **kwargs):
    idx_rows, evt_rows = [], []
    seen_vins = set()

    for entry in iter_entries(src_dir, include_ext=('.log',)):
        rel = entry.rel_path.replace('\\', '/')
        if '/.VciLog/' not in '/' + rel:
            continue

        date_log = _date_from_name(rel)
        header = _parse_header(entry)
        size = 0
        # Streaming line-by-line pour event extraction
        try:
            with entry.open_text() as f:
                for line in f:
                    size += len(line)
                    m = LOG_LINE_RE.match(line)
                    rel_ts = m.group(1) if m else ''
                    pid    = m.group(2) if m else ''
                    tid    = m.group(3) if m else ''
                    lvl    = m.group(4) if m else ''
                    tag    = m.group(5) if m else ''
                    body   = m.group(6) if m else line.rstrip('\n')

                    for evt, pat in PATTERNS.items():
                        for match in pat.finditer(body):
                            if evt == 'VIN_IN_LOG':
                                v = match.group(1)
                                if v in seen_vins: continue
                                # Filtre simple : pas que des chiffres
                                if v.isdigit(): continue
                                seen_vins.add(v)
                                detail = v
                            elif evt == 'PASSTHRU_IOCTL':
                                detail = f"ChannelID={match.group(1)} IoctlID={match.group(2)} result={match.group(3)}"
                            else:
                                detail = ' / '.join(match.groups()) if match.groups() else match.group(0)
                            evt_rows.append([date_log, rel_ts, pid, tid, lvl, tag, evt, detail, rel])
        except Exception as e:
            logging.warning(f"VciLog parse fail {rel}: {e}")
            continue

        idx_rows.append([os.path.basename(rel), date_log, size,
                         header['sn'], header['product'], header['os'],
                         header['vci_model'], header['vci_fw'], rel])

    if not idx_rows and not evt_rows:
        return []

    if idx_rows:
        f, w = open_csv(export_dir, 'vci_logs_index.csv', INDEX_HEADER)
        try:
            for r in sorted(idx_rows, key=lambda x: x[1] or ''):
                w.writerow(r)
        finally:
            f.close()

    if evt_rows:
        f, w = open_csv(export_dir, 'vci_logs_events.csv', EVENT_HEADER)
        try:
            for r in evt_rows:
                w.writerow(r)
        finally:
            f.close()

    logging.info(f"VciLog : {len(idx_rows)} fichier(s), {len(evt_rows)} événement(s)")
    return idx_rows + evt_rows
