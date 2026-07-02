# extract_bluetooth.py — AFAP
# Auteur : Vincent Chapeau — Teel Technologies Canada (vincent.chapeau@teeltechcanada.com)
#
# Appareils Bluetooth : appairés (bonded) et vus. Contrairement au SSID d'un
# hotspot iPhone (BSSID randomisé), une MAC Bluetooth APPAIRÉE est en général
# universelle (fixe) et donc exploitable (identification d'un téléphone,
# enceinte, TV, VCI...). Récupère aussi les NOMS d'appareils (getname/remoteName)
# et signale randomisée vs fixe + le fabricant (OUI).
#
# Produit : bluetooth_devices.csv

import os
import re
import csv
import logging
import datetime
from core_scanner import iter_entries, iter_text_lines_entry, should_skip, open_csv, read_text_cached

try:
    from extract_mac import load_oui_db, get_vendor
except Exception:
    def load_oui_db(_): return {}
    def get_vendor(_m, _db): return "Inconnu"

MAC_RE = r'([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})'
BONDED_RE = re.compile(r'(?:bonded device|Bond state changed for device|bondStateChangeCallback[^\n]*Address)[:\s]*' + MAC_RE, re.I)
A2DP_RE = re.compile(r'A2dpService[^\n]*' + MAC_RE, re.I)
NAME_MAC_RE = re.compile(MAC_RE + r'[^\n]{0,30}?\bname\b[^A-Za-z0-9]{0,4}([A-Za-z0-9 _\-\[\]]{2,30})', re.I)
GETNAME_RE = re.compile(r'getname:\s*([A-Za-z0-9 _\-\[\]]{2,30})', re.I)
TS_RE = re.compile(r'(?:^|\s)(\d{2})-(\d{2})\s+(\d{2}:\d{2}:\d{2})')  # log Android: MM-DD HH:MM:SS


def _is_random(mac):
    try:
        return (int(mac.split(':')[0], 16) & 2) != 0
    except Exception:
        return False


def extract_bluetooth(src_dir, export_dir, skip_md5=None, **kwargs):
    oui_db = load_oui_db(os.path.join(os.path.dirname(__file__), 'oui.csv'))
    bonded = set()
    a2dp = set()
    seen_date = {}  # mac -> 'YYYY-MM-DD HH:MM:SS' (première occurrence)
    names = {}          # mac -> set(noms)
    loose_names = set()  # noms sans MAC associée

    try:
        for entry in iter_entries(src_dir, include_ext=('.log', '.txt')):
            if entry.is_os and should_skip(entry.path, skip_md5):
                continue
            try:
                fyear = datetime.datetime.fromtimestamp(entry.mtime).year if entry.mtime else datetime.datetime.now().year
                fdate = datetime.datetime.fromtimestamp(entry.mtime).strftime('%Y-%m-%d %H:%M:%S') if entry.mtime else ""
            except Exception:
                fyear, fdate = datetime.datetime.now().year, ""
            # Traitement LIGNE PAR LIGNE : évite tout backtracking catastrophique
            # (regex sur gros blob) et l'horodatage Android est porté par la ligne.
            try:
                for line in read_text_cached(entry).splitlines():
                    if len(line) > 4000:
                        line = line[:4000]
                    tmm = TS_RE.search(line)
                    lts = f"{fyear:04d}-{tmm.group(1)}-{tmm.group(2)} {tmm.group(3)}" if tmm else fdate
                    for m in BONDED_RE.finditer(line):
                        mac = m.group(1).upper()
                        bonded.add(mac)
                        seen_date.setdefault(mac, lts)
                    for m in A2DP_RE.finditer(line):
                        a2dp.add(m.group(1).upper())
                    for m in NAME_MAC_RE.finditer(line):
                        names.setdefault(m.group(1).upper(), set()).add(m.group(2).strip())
                    for m in GETNAME_RE.finditer(line):
                        loose_names.add(m.group(1).strip())
            except Exception as e:
                logging.debug(f"extract_bluetooth ligne {entry.rel_path}: {e}")
    except Exception as e:
        logging.warning(f"extract_bluetooth: {e}")

    rows = []
    f, w = open_csv(export_dir, 'bluetooth_devices.csv',
                    ['mac', 'type_mac', 'fabricant_oui', 'profil', 'noms_associes', 'statut', 'date'])
    try:
        allmacs = bonded | a2dp
        for mac in sorted(allmacs):
            typ = "randomisée" if _is_random(mac) else "FIXE (universelle)"
            vendor = get_vendor(mac, oui_db)
            profil = "A2DP (audio)" if mac in a2dp else ""
            nm = "; ".join(sorted(names.get(mac, [])))
            statut = "APPAIRÉ (bonded)" if mac in bonded else "vu"
            w.writerow([mac, typ, vendor, profil, nm, statut, seen_date.get(mac, '')])
            rows.append([mac, statut])
        # noms observés sans MAC (contexte)
        for n in sorted(loose_names):
            if n and not n.isdigit():
                w.writerow(["", "", "", "", n, "nom d'appareil vu (BT/scan)", ""])
    finally:
        f.close()
    return rows
