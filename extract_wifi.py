# extract_wifi.py — AFAP
# Auteur : Vincent Chapeau — Teel Technologies Canada (vincent.chapeau@teeltechcanada.com)
#
# Réseaux WiFi / partage de connexion (tethering).
# Distingue le réseau CONNECTÉ (association effective, passerelle) des réseaux
# seulement VUS EN SCAN. Détecte le tethering iPhone (passerelle 172.20.10.x =
# signature Apple Personal Hotspot) et récupère le SSID (souvent nominatif).
#
# Produit : wifi_networks.csv
#   colonnes : statut, ssid, bssid_ou_mac, vendor, passerelle, indice, source, date_fichier

import os
import re
import csv
import logging
import datetime
from core_scanner import iter_entries, iter_text_lines_entry, should_skip, open_csv, read_text_cached

try:
    from extract_mac import load_oui_db, get_vendor, is_mac_randomized
except Exception:
    def load_oui_db(_): return {}
    def get_vendor(_m, _db): return "Inconnu"
    def is_mac_randomized(_m): return False

SSID_RE = re.compile(r'(?:SSID[:=]?\s*|"ssid"\s*:\s*\\?")[\'"]?([^\'"\\\n]{1,32})')
CONNECT_RE = re.compile(r'connectToNetwork\s*"?([^"\n]{1,32})|associate with SSID\s*[\'"]([^\'"\n]{1,32})', re.I)
BSSID_RE = re.compile(r'bssid[=: ]+([0-9A-Fa-f:]{17})')
GW_RE = re.compile(r'\b(172\.20\.10\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
RSSI_RE = re.compile(r'SignalStrength[:=]?\s*(-?\d{1,3})')
TS_RE = re.compile(r'(?:^|\s)(\d{2})-(\d{2})\s+(\d{2}:\d{2}:\d{2})')  # log Android MM-DD HH:MM:SS


def extract_wifi(src_dir, export_dir, skip_md5=None, **kwargs):
    oui_db = load_oui_db(os.path.join(os.path.dirname(__file__), 'oui.csv'))

    connected_ssids = {}   # ssid -> dict(rssi,gateway,dates)
    connected_bssids = set()
    scanned_bssids = {}    # bssid -> (vendor)
    apple_hotspot = False

    try:
        for entry in iter_entries(src_dir, include_ext=('.log', '.txt')):
            if entry.is_os and should_skip(entry.path, skip_md5):
                continue
            try:
                mtime = datetime.datetime.fromtimestamp(entry.mtime).strftime('%Y-%m-%d %H:%M:%S') if entry.mtime else ""
            except Exception:
                mtime = ""
            data = read_text_cached(entry)

            try:
                fyear = datetime.datetime.fromtimestamp(entry.mtime).year if entry.mtime else datetime.datetime.now().year
            except Exception:
                fyear = datetime.datetime.now().year
            for m in CONNECT_RE.finditer(data):
                ssid = (m.group(1) or m.group(2) or "").strip()
                if ssid:
                    # horodatage précis : ligne Android juste avant l'événement
                    ctx = data[max(0, m.start()-200):m.start()]
                    tm = None
                    for tm in TS_RE.finditer(ctx):
                        pass
                    cdate = f"{fyear:04d}-{tm.group(1)}-{tm.group(2)} {tm.group(3)}" if tm else mtime
                    d = connected_ssids.setdefault(ssid, {"rssi": "", "gateway": "", "src": entry.rel_path, "date": cdate})
                    if d.get("date") in ("", None):
                        d["date"] = cdate
            for m in SSID_RE.finditer(data):
                ssid = m.group(1).strip()
                # heuristique tethering iPhone
                if ssid.lower().startswith("iphone") or "hotspot" in ssid.lower():
                    connected_ssids.setdefault(ssid, {"rssi": "", "gateway": "", "src": entry.rel_path, "date": mtime})
            for m in GW_RE.finditer(data):
                gw = m.group(1)
                if gw.startswith("172.20.10"):
                    apple_hotspot = True
                    for s in connected_ssids.values():
                        s["gateway"] = s["gateway"] or gw
            for m in RSSI_RE.finditer(data):
                for s in connected_ssids.values():
                    if not s["rssi"]:
                        s["rssi"] = m.group(1)
            for m in BSSID_RE.finditer(data):
                b = m.group(1).lower()
                if b != "00:00:00:00:00:00":
                    connected_bssids.add(b)
    except Exception as e:
        logging.warning(f"extract_wifi: {e}")

    # scan : réseaux vus par extract_mac (mac_found.csv) mais pas connectés
    mac_found = os.path.join(export_dir, 'mac_found.csv')
    if os.path.isfile(mac_found):
        try:
            with open(mac_found, encoding='utf-8-sig') as f:
                for row in csv.DictReader(f):
                    mac = (row.get('mac') or '').lower()
                    if not mac or mac == "00:00:00:00:00:00":
                        continue
                    if row.get('randomized', '').lower() in ('oui', 'yes', 'true'):
                        continue  # MAC randomisées = souvent hotspots/clients, pas des box fixes
                    if mac not in connected_bssids:
                        scanned_bssids[mac] = (row.get('vendor', 'Inconnu'), row.get('date_modification',''))
        except Exception as e:
            logging.debug(f"lecture mac_found: {e}")

    # nettoyage + dédoublonnage des SSID connectés
    def _clean(s):
        for a, b in ((r'\xe2\x80\x99', "'"), (r'\xe2\x80\x98', "'"),
                     ('\u2019', "'"), ('\u2018', "'"), ('\\', '')):
            s = s.replace(a, b)
        return s.strip().strip('"').strip("'").strip()
    cleaned = {}
    for ssid, d in connected_ssids.items():
        cs = _clean(ssid)
        if not cs:
            continue
        # ignorer un SSID qui est un préfixe strict d'un autre déjà vu
        keep = True
        for other in list(cleaned):
            if other != cs and other.startswith(cs):
                keep = False
                break
            if cs.startswith(other) and cs != other:
                del cleaned[other]
        if keep:
            cleaned[cs] = d
    connected_ssids = cleaned

    rows = []
    f, w = open_csv(export_dir, 'wifi_networks.csv',
                    ['statut', 'ssid', 'bssid_ou_mac', 'vendor', 'passerelle', 'indice', 'date', 'source'])
    try:
        for ssid, d in connected_ssids.items():
            typ = "CONNECTÉ (tethering iPhone)" if (apple_hotspot and ssid.lower().startswith("iphone")) else "CONNECTÉ"
            indice = f"RSSI {d['rssi']} dBm" if d['rssi'] else ""
            bssid = ";".join(sorted(connected_bssids)) if connected_bssids else ""
            w.writerow([typ, ssid, bssid, "Apple (hotspot)" if ssid.lower().startswith("iphone") else "", d['gateway'], indice, d.get('date',''), d['src']])
            rows.append([typ, ssid])
        for mac, (vendor, sdate) in scanned_bssids.items():
            w.writerow(["VU EN SCAN (non connecté)", "", mac, vendor, "", "géoloc WiFi possible", sdate, "mac_found.csv"])
            rows.append(["SCAN", mac])
    finally:
        f.close()
    return rows
