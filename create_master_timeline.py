# create_master_timeline.py — AFAP
# Auteur : Vincent Chapeau — Teel Technologies Canada (vincent.chapeau@teeltechcanada.com)
#
# Construit UNE table maître unique, importable (Mercure), consolidant tous les
# événements horodatés : opérations clé, lectures EEPROM, sessions diagnostic,
# compte (création/KYC), réseau (scan vs connecté), médias, enregistrement
# appareil. Chaque ligne est auto-portante (scellé, SN, compte répétés).
#
# Colonne date_corrigee : remplie si un décalage horloge a été fourni
# (voir clock_offset.py / options CLI --tablet-time / --real-time).
#
# Produit : Chronologie_MAITRE.csv  (+ s'appuie sur les CSV des autres modules)

import os
import re
import csv
import json
import zipfile
import logging
import datetime
from core_scanner import iter_entries, iter_text_lines_entry, open_csv
from clock_offset import ClockOffset

MAKES = ("Toyota", "Lexus", "Nissan", "Renault", "Citroen", "Peugeot", "VW",
         "Volkswagen", "Audi", "BMW", "Mini", "Mercedes", "Ford", "Hyundai", "Kia")
COLS = ["no", "date_tablette", "heure_tablette", "heure_fin", "duree", "date_corrigee",
        "categorie", "constructeur", "modele", "operation", "detail", "mac_address",
        "fiabilite", "scelle", "sn_tablette", "compte_autel", "source_fichier", "horodatage"]


def _dt_from_name(s):
    m = re.search(r'(20\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})', s)
    if not m:
        return ""
    y, mo, da, h, mi, se = map(int, m.groups())
    if 2020 <= y <= 2035 and 1 <= mo <= 12 and 1 <= da <= 31 and h < 24 and mi < 60 and se < 60:
        return f"{y:04d}-{mo:02d}-{da:02d} {h:02d}:{mi:02d}:{se:02d}"
    return ""


def _field(d, name):
    m = re.search(name + r'["\']?\s*[:=]\s*["\']?(\d{4}[-/]\d\d[-/]\d\d[ T]\d\d:\d\d:\d\d)', d)
    return m.group(1).replace("/", "-") if m else ""


def _dur(a, b):
    try:
        f = "%Y-%m-%d %H:%M:%S"
        return str(datetime.datetime.strptime(b, f) - datetime.datetime.strptime(a, f))
    except Exception:
        return ""


def create_master_timeline(src_dir, export_dir, skip_md5=None, serial="inconnu",
                           scelle="", clock=None, account=None, **kwargs):
    clock = clock or ClockOffset.from_json(export_dir)
    scelle = scelle or os.path.basename(src_dir.rstrip("/\\"))
    ACCOUNT_CREATED = "2100-01-01"
    account_email = ""

    # --- identité compte (depuis account_identity.csv si présent) ---
    acc_path = os.path.join(export_dir, 'account_identity.csv')
    acc = {}
    if os.path.isfile(acc_path):
        try:
            with open(acc_path, encoding='utf-8-sig') as f:
                for r in csv.DictReader(f):
                    acc[r['element']] = r['valeur']
        except Exception:
            pass
    account_email = acc.get("E-mail du compte", "") or acc.get("Compte Autel (autelId)", "")
    creation = acc.get("Création du compte (déduite)", "")
    if creation:
        ACCOUNT_CREATED = creation[:10]

    events = []

    def add(hor, cat, constr="", modele="", operation="", detail="", src="",
            fiab="RTC tablette", fin="", mac=""):
        if not hor:
            return
        d = hor.replace("/", "-")
        day = d[:10]
        compte = account_email if (account_email and day >= ACCOUNT_CREATED) else \
            ("non déterminé (antérieur au compte)" if day < ACCOUNT_CREATED else "")
        events.append(dict(
            date_tablette=day, heure_tablette=d[11:19],
            heure_fin=(fin[11:19] if len(fin) >= 13 else fin),
            duree=_dur(d, fin) if fin else "",
            date_corrigee=clock.correct(d), categorie=cat, constructeur=constr,
            modele=modele, operation=operation, detail=detail, mac_address=mac,
            fiabilite=fiab, scelle=scelle, sn_tablette=serial,
            compte_autel=compte, source_fichier=src, horodatage=d))

    # --- opérations clé + sessions + EEPROM depuis la source (DataLogging/UserData) ---
    try:
        for entry in iter_entries(src_dir, include_ext=('.zip',)):
            rel = entry.rel_path.replace('\\', '/')
            if '/DataLogging/' not in '/' + rel:
                continue
            constr_dir = ""
            parts = rel.split('/')
            if 'DataLogging' in parts:
                i = parts.index('DataLogging')
                if i + 1 < len(parts):
                    constr_dir = parts[i + 1]
            # session (horodatage = nom)
            add(_dt_from_name(os.path.basename(rel)), "Session diagnostic", constr_dir,
                "", "", os.path.basename(rel), rel)
            # opération clé (lire le _main.log interne)
            try:
                with entry.open_binary() as b:
                    zf = zipfile.ZipFile(b)
                    for n in zf.namelist():
                        if not n.lower().endswith("main.log"):
                            continue
                        data = zf.read(n).decode("utf-8", "ignore")
                        fn = ""
                        for m in re.finditer(r'"FuncName"\s*:\s*"([^"]{2,90})"', data):
                            if "," not in m.group(1) and m.group(1).lower() != "keytool":
                                fn = m.group(1)
                                break
                        if not fn:
                            continue
                        st = _field(data, "FuncStartTime")
                        et = _field(data, "FuncEndTime")
                        veh = ""
                        for mm in re.finditer(r'title\\?"\s*:\s*\\?"([^"\\]{3,50})', data):
                            if any(mk.lower() in mm.group(1).lower() for mk in MAKES):
                                veh = mm.group(1).strip()
                                break
                        add(st or _dt_from_name(os.path.basename(rel)), "Opération clé",
                            constr_dir or "Toyota", veh, fn,
                            "mode OBD" if "OBD" in data[:6000] else "", rel, fin=et)
            except Exception:
                pass
    except Exception as e:
        logging.warning(f"master: DataLogging: {e}")

    # EEPROM
    try:
        for entry in iter_entries(src_dir):
            rel = entry.rel_path.replace('\\', '/')
            base = os.path.basename(rel)
            if '/UserData/' in '/' + rel and 'eeprom' in base.lower():
                constr = rel.split('/')[-2] if '/' in rel else ""
                d = _dt_from_name(base)
                if not d and entry.mtime:
                    d = datetime.datetime.fromtimestamp(entry.mtime).strftime("%Y-%m-%d %H:%M:%S")
                add(d, "Lecture EEPROM immobiliseur", constr, "", "", base, rel)
    except Exception as e:
        logging.warning(f"master: EEPROM: {e}")

    # --- compte / appareil ---
    if creation:
        detail = " ; ".join(f"{k} {v}" for k, v in acc.items() if k in (
            "E-mail du compte", "Pseudo (nickname)", "Username interne Autel",
            "userId numérique", "Rôle", "Pays", "Téléphone"))
        add(creation.replace(" UTC", ""), "Compte Autel", "", "",
            "Création du compte (déduite)", detail, "userId (ns-epoch)", fiab="Déduit (ns-epoch)")
    reg = acc.get("Enregistrement appareil (revendeur)", "")
    if reg:
        add(reg if len(reg) > 10 else reg + " 00:00:00", "Appareil", "", "",
            "Enregistrement tablette par le revendeur",
            f"sealerAutelID={acc.get('Revendeur (sealerAutelID)','?')} (propriété appareil, pas du compte)",
            "AppLog (contrat/regTime)")

    # --- réseau (wifi_networks.csv) ---
    wifi = os.path.join(export_dir, 'wifi_networks.csv')
    if os.path.isfile(wifi):
        try:
            with open(wifi, encoding='utf-8-sig') as f:
                for r in csv.DictReader(f):
                    st = r.get('statut', '')
                    date = r.get('date', '')
                    if not date:
                        continue
                    if st.startswith("CONNECT"):
                        op = "CONNEXION WiFi/tethering : " + r.get('ssid', '')
                        det = f"{st} ; passerelle {r.get('passerelle','')} ; {r.get('indice','')}"
                    else:
                        op = "SCAN WiFi (non connecté)"
                        det = f"{r.get('vendor','')} ; géoloc WiFi possible"
                    add(date, "Réseau", "", "", op, det, r.get('source', ''),
                        mac=r.get('bssid_ou_mac', ''))
        except Exception as e:
            logging.warning(f"master: wifi: {e}")

    # --- Bluetooth appairé (bluetooth_devices.csv) ---
    bt = os.path.join(export_dir, 'bluetooth_devices.csv')
    if os.path.isfile(bt):
        try:
            with open(bt, encoding='utf-8-sig') as f:
                for r in csv.DictReader(f):
                    if r.get('statut','').startswith('APPAIR') and r.get('mac'):
                        add(r.get('date','') or "", "Bluetooth", "", "",
                            "Appareil Bluetooth appaire (bonded)",
                            f"{r.get('type_mac','')} ; {r.get('fabricant_oui','')} ; {r.get('profil','')} ; {r.get('noms_associes','')} ; NON etabli = telephone",
                            "AppLog (Bluetooth)", mac=r.get('mac',''))
        except Exception as e:
            logging.warning(f"master: bluetooth: {e}")

    # --- médias (DCIM) + KYC (kyc_qr.csv) ---
    try:
        for entry in iter_entries(src_dir, include_ext=('.jpg', '.jpeg', '.png')):
            rel = entry.rel_path.replace('\\', '/')
            if '/DCIM/' not in '/' + rel and '/UserCenter/' not in '/' + rel:
                continue
            d = _dt_from_name(os.path.basename(rel))
            if not d and entry.mtime:
                d = datetime.datetime.fromtimestamp(entry.mtime).strftime("%Y-%m-%d %H:%M:%S")
            label = "Photo de profil (avatar)" if 'UserCenter' in rel else "Média (photo)"
            add(d, "Média (photo)", "", "", label, os.path.basename(rel), rel)
    except Exception:
        pass
    kyc = os.path.join(export_dir, 'kyc_qr.csv')
    if os.path.isfile(kyc):
        try:
            with open(kyc, encoding='utf-8-sig') as f:
                for r in csv.DictReader(f):
                    if 'KYC' in r.get('type', ''):
                        add(r.get('jwt_iat_utc', '').replace(" UTC", "") or r.get('date_fichier', ''),
                            "Compte Autel", "", "", "Vérification identité KYC",
                            f"{r.get('type','')} — {r.get('autelId','')} / {r.get('nickname','')}",
                            r.get('image', ''), fiab="RTC/UTC jeton")
        except Exception:
            pass

    # --- identité matérielle (device_bootlog.csv, si module bootlog exécuté) ---
    blog = os.path.join(export_dir, 'device_bootlog.csv')
    if os.path.isfile(blog):
        try:
            bl = {}
            with open(blog, encoding='utf-8-sig') as bf:
                for r in csv.DictReader(bf):
                    bl.setdefault(r['element'], r['valeur'])
            rtc = bl.get("RTC tablette au boot", "")
            hw_keys = ("SoC serial (chip ID)", "eMMC nom/taille", "eMMC Manufacturer ID",
                       "SN Autel (serial#)", "U-Boot version", "Kernel version",
                       "Batterie cycles (cc)", "WiFi country")
            detail = " ; ".join(f"{k}={bl[k]}" for k in hw_keys if bl.get(k))
            if detail:
                add(rtc or "", "Appareil", "", "", "Identité matérielle (log UART)",
                    detail, "device_bootlog.csv", fiab="Boot UART")
            if bl.get("NV (nv_a/nv_b)"):
                add(rtc or "", "Appareil", "", "", "Anomalie NV",
                    bl["NV (nv_a/nv_b)"], "device_bootlog.csv", fiab="Boot UART")
            if bl.get("Extinction volontaire (reason)"):
                add(rtc or "", "Appareil", "", "", "Extinction volontaire (securityd)",
                    bl.get("powerctl déclenché par", bl["Extinction volontaire (reason)"]),
                    "device_bootlog.csv", fiab="Boot UART")
        except Exception as e:
            logging.warning(f"master: device_bootlog: {e}")

    # --- tri, dédoublonnage, écriture ---
    seen = set()
    out = []
    for e in sorted(events, key=lambda x: x["horodatage"]):
        k = (e["horodatage"], e["categorie"], e["detail"][:40], e["mac_address"])
        if k in seen:
            continue
        seen.add(k)
        out.append(e)
    for i, e in enumerate(out, 1):
        e["no"] = i

    f, w = open_csv(export_dir, 'Chronologie_MAITRE.csv', COLS)
    try:
        for e in out:
            w.writerow([e.get(c, "") for c in COLS])
    finally:
        f.close()

    # notice d'import
    try:
        with open(os.path.join(export_dir, 'LISEZ-MOI_import_Mercure.txt'), 'w', encoding='utf-8') as nf:
            nf.write("IMPORT MERCURE — Chronologie_MAITRE.csv\n")
            nf.write("Fichier unique à importer. 1 ligne = 1 événement. UTF-8 BOM, séparateur virgule.\n")
            nf.write("Colonnes : " + ", ".join(COLS) + "\n\n")
            nf.write(clock.human() + "\n")
            nf.write("Réserves : activité antérieure à la création du compte non attribuée ; "
                     "aucun regroupement 'même véhicule' présumé sans identifiant technique.\n")
    except Exception:
        pass

    logging.info(f"Table maître : {len(out)} événements — {clock.human()}")
    return out
