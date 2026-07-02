# extract_wifi.py — AFAP
# Auteur : Vincent Chapeau — Teel Technologies Canada (vincent.chapeau@teeltechcanada.com)
#
# Réseaux WiFi / partage de connexion (tethering).
# Distingue le réseau CONNECTÉ (association effective, passerelle) des réseaux
# seulement VUS EN SCAN. Détecte le tethering iPhone (passerelle 172.20.10.x =
# signature Apple Personal Hotspot) et récupère le SSID (souvent nominatif).
#
# Produit : wifi_networks.csv
#   colonnes : statut, ssid, bssid_ou_mac, vendor, passerelle, indice, date, source
#
# Architecture : la logique par fichier vit dans WifiConsumer (feed/finalize),
# réutilisable par l'orchestrateur "passe unique" (scan_text.py). finalize() lit
# mac_found.csv (produit par extract_mac) : lancer extract_mac AVANT. La fonction
# extract_wifi reste un point d'entrée autonome au comportement identique.

import os
import re
import csv
import logging
import datetime
from core_scanner import iter_entries, iter_text_lines_entry, should_skip, open_csv, read_text_cached

SSID_RE = re.compile(r'(?:SSID[:=]?\s*|"ssid"\s*:\s*\\?")[\'"]?([^\'"\\\n]{1,32})')
CONNECT_RE = re.compile(r'connectToNetwork\s*"?([^"\n]{1,32})|associate with SSID\s*[\'"]([^\'"\n]{1,32})', re.I)
BSSID_RE = re.compile(r'bssid[=: ]+([0-9A-Fa-f:]{17})')
GW_RE = re.compile(r'\b(172\.20\.10\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
RSSI_RE = re.compile(r'SignalStrength[:=]?\s*(-?\d{1,3})')
TS_RE = re.compile(r'(?:^|\s)(\d{2})-(\d{2})\s+(\d{2}:\d{2}:\d{2})')  # log Android MM-DD HH:MM:SS


class WifiConsumer:
    """Consommateur "passe unique" pour les réseaux WiFi / tethering."""
    name = 'wifi'

    def __init__(self):
        self.connected_ssids = {}   # ssid -> dict(rssi,gateway,src,date)
        self.connected_bssids = set()
        self.scanned_bssids = {}    # bssid -> (vendor, date)
        self.apple_hotspot = False

    @staticmethod
    def build_bundle(rel_path, mtime_raw, data):
        """Extraction LOURDE (regex) d'un fichier -> bundle picklable (pur)."""
        try:
            mtime = datetime.datetime.fromtimestamp(mtime_raw).strftime('%Y-%m-%d %H:%M:%S') if mtime_raw else ""
        except Exception:
            mtime = ""
        try:
            fyear = datetime.datetime.fromtimestamp(mtime_raw).year if mtime_raw else datetime.datetime.now().year
        except Exception:
            fyear = datetime.datetime.now().year
        connect = []
        for m in CONNECT_RE.finditer(data):
            ssid = (m.group(1) or m.group(2) or "").strip()
            if ssid:
                ctx = data[max(0, m.start() - 200):m.start()]
                tm = None
                for tm in TS_RE.finditer(ctx):
                    pass
                cdate = f"{fyear:04d}-{tm.group(1)}-{tm.group(2)} {tm.group(3)}" if tm else mtime
                connect.append((ssid, cdate))
        ssid_hot = []
        for m in SSID_RE.finditer(data):
            ssid = m.group(1).strip()
            if ssid.lower().startswith("iphone") or "hotspot" in ssid.lower():
                ssid_hot.append(ssid)
        gw = []
        for m in GW_RE.finditer(data):
            g = m.group(1)
            if g.startswith("172.20.10"):
                gw.append(g)
        rssi = [m.group(1) for m in RSSI_RE.finditer(data)]
        bssid = []
        for m in BSSID_RE.finditer(data):
            b = m.group(1).lower()
            if b != "00:00:00:00:00:00":
                bssid.append(b)
        return {'connect': connect, 'ssid_hot': ssid_hot, 'gw': gw, 'rssi': rssi,
                'bssid': bssid, 'mtime': mtime, 'src': rel_path}

    def apply_bundle(self, b):
        """Application LEGERE (etat global), rejouee dans l'ordre des fichiers :
        reproduit EXACTEMENT la logique sequentielle (propagation passerelle/RSSI
        a tous les SSID vus jusque-la)."""
        src = b['src']
        mtime = b['mtime']
        for ssid, cdate in b['connect']:
            d = self.connected_ssids.setdefault(ssid, {"rssi": "", "gateway": "", "src": src, "date": cdate})
            if d.get("date") in ("", None):
                d["date"] = cdate
        for ssid in b['ssid_hot']:
            self.connected_ssids.setdefault(ssid, {"rssi": "", "gateway": "", "src": src, "date": mtime})
        for g in b['gw']:
            self.apple_hotspot = True
            for s in self.connected_ssids.values():
                s["gateway"] = s["gateway"] or g
        for val in b['rssi']:
            for s in self.connected_ssids.values():
                if not s["rssi"]:
                    s["rssi"] = val
        for b2 in b['bssid']:
            self.connected_bssids.add(b2)

    def feed(self, entry, data):
        self.apply_bundle(self.build_bundle(entry.rel_path, entry.mtime, data))

    def finalize(self, export_dir):
        mac_found = os.path.join(export_dir, 'mac_found.csv')
        if os.path.isfile(mac_found):
            try:
                with open(mac_found, encoding='utf-8-sig') as f:
                    for row in csv.DictReader(f):
                        mac = (row.get('mac') or '').lower()
                        if not mac or mac == "00:00:00:00:00:00":
                            continue
                        if row.get('randomized', '').lower() in ('oui', 'yes', 'true'):
                            continue
                        if mac not in self.connected_bssids:
                            self.scanned_bssids[mac] = (row.get('vendor', 'Inconnu'), row.get('date_modification', ''))
            except Exception as e:
                logging.debug(f"lecture mac_found: {e}")

        def _clean(s):
            for a, b in ((r'\xe2\x80\x99', "'"), (r'\xe2\x80\x98', "'"),
                         ('’', "'"), ('‘', "'"), ('\\', '')):
                s = s.replace(a, b)
            return s.strip().strip('"').strip("'").strip()
        cleaned = {}
        for ssid, d in self.connected_ssids.items():
            cs = _clean(ssid)
            if not cs:
                continue
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
                typ = "CONNECTÉ (tethering iPhone)" if (self.apple_hotspot and ssid.lower().startswith("iphone")) else "CONNECTÉ"
                indice = f"RSSI {d['rssi']} dBm" if d['rssi'] else ""
                bssid = ";".join(sorted(self.connected_bssids)) if self.connected_bssids else ""
                w.writerow([typ, ssid, bssid, "Apple (hotspot)" if ssid.lower().startswith("iphone") else "", d['gateway'], indice, d.get('date', ''), d['src']])
                rows.append([typ, ssid])
            for mac, (vendor, sdate) in self.scanned_bssids.items():
                w.writerow(["VU EN SCAN (non connecté)", "", mac, vendor, "", "géoloc WiFi possible", sdate, "mac_found.csv"])
                rows.append(["SCAN", mac])
        finally:
            f.close()
        return rows


def extract_wifi(src_dir, export_dir, skip_md5=None, **kwargs):
    """Point d'entrée autonome : une passe sur les .log/.txt (comportement
    identique à l'orchestrateur, mais pour ce seul module)."""
    c = WifiConsumer()
    try:
        for entry in iter_entries(src_dir, include_ext=('.log', '.txt')):
            if entry.is_os and should_skip(entry.path, skip_md5):
                continue
            c.feed(entry, read_text_cached(entry))
    except Exception as e:
        logging.warning(f"extract_wifi: {e}")
    return c.finalize(export_dir)
