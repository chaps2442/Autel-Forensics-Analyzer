# parse_uart_bootlog.py — AFAP
# Auteur : Vincent Chapeau — Teel Technologies Canada (vincent.chapeau@teeltechcanada.com)
#
# Analyse un LOG CONSOLE UART (bootrom + U-Boot + kernel) sauvegardé en .txt/.log.
# Extrait les identifiants MATÉRIELS et de firmware qui n'existent PAS dans un
# dump logique/sdcard (ils vivent sous le système de fichiers) :
#   - ID unique du SoC (cpuinfo Serial)         - CID / modèle / taille eMMC
#   - SN Autel (serial# / androidboot.serialno)  - versions U-Boot / kernel / bootrom
#   - RTC de la tablette au boot                 - cycles batterie (usure)
#   - pays WiFi, veritymode                      - état NV (read_nv fail)
#   - anomalie securityd (auto-shutdown)
#
# BONUS horloge : la ligne "setting system clock to <UTC>" donne l'heure RTC de
# la tablette au boot. Si on connaît l'heure réelle correspondante (--real-time),
# on calcule automatiquement le décalage et on l'écrit dans clock_offset.json
# (repris ensuite par create_master_timeline pour remplir date_corrigee).
#
# Produit : device_bootlog.csv
#
# Le log est fourni via --bootlog <fichier>, ou détecté dans la source
# (fichier contenant "bootlog"/"uart" dans le nom).

import os
import re
import logging
import datetime
from core_scanner import open_csv

RX = {
    "SoC serial (chip ID)":      re.compile(r'cpuinfo:\s*Serial\s*:\s*([0-9a-fA-F]{8,})'),
    "SN Autel (serial#)":        re.compile(r'serial#\s*=\s*(\S+)'),
    "SN Autel (androidboot)":    re.compile(r'androidboot\.serialno=(\S+)'),
    "eMMC nom/taille":           re.compile(r'mmcblk\d+:\s*mmc\d+:\w+\s+(\S+\s+[\d.]+\s*[GM]iB)'),
    "eMMC Manufacturer ID":      re.compile(r'Manufacturer ID:\s*(\w+)'),
    "eMMC OEM":                  re.compile(r'OEM:\s*(\w+)'),
    "eMMC Name":                 re.compile(r'^\s*Name:\s*(\S+)', re.M),
    "U-Boot version":            re.compile(r'(U-Boot \d{4}\.\d{2}[^\n,]*)'),
    "U-Boot build":              re.compile(r'Build:\s*(V[\d.]+)'),
    "Kernel version":            re.compile(r'Linux version (\S+)'),
    "Bootrom (Boot1)":           re.compile(r'Boot1 Release Time:\s*([^,]+),\s*version:\s*(\S+)'),
    "RTC tablette au boot":      re.compile(r'setting system clock to (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s*UTC'),
    "Batterie cycles (cc)":      re.compile(r'battery[^\n]*\bcc=(\d+)'),
    "Batterie pleine charge µAh": re.compile(r'battery[^\n]*\bfc=(\d+)'),
    "WiFi country":              re.compile(r'androidboot\.wificountrycode=(\w+)'),
    "Vérification (veritymode)": re.compile(r'androidboot\.veritymode=(\w+)'),
    "SELinux":                   re.compile(r'androidboot\.selinux=(\w+)'),
}
NV_FAIL_RX = re.compile(r'read_nv:\s*check fail|autel_nv_fixup[^\n]*read_nv fail')
SHUTDOWN_RX = re.compile(r"Reboot start, reason:\s*([^\n\r]+)")
POWERCTL_RX = re.compile(r"sys\.powerctl='([^']+)'[^\n]*pid:\s*\d+\s*\((\w+)\)")


def find_bootlog(src_dir, bootlog=None):
    """Chemin du log : explicite, sinon détecté dans src_dir (nom bootlog/uart)."""
    if bootlog and os.path.isfile(bootlog):
        return bootlog
    if src_dir and os.path.isdir(src_dir):
        for root, _, files in os.walk(src_dir):
            for fn in files:
                low = fn.lower()
                if (low.endswith(('.log', '.txt')) and
                        ('bootlog' in low or 'uart' in low or 'console' in low)):
                    return os.path.join(root, fn)
    return None


def detect_tablet_time(bootlog_path):
    """Retourne l'heure RTC de la tablette au boot ('YYYY-MM-DD HH:MM:SS') ou ''."""
    if not bootlog_path or not os.path.isfile(bootlog_path):
        return ""
    try:
        data = open(bootlog_path, encoding='utf-8', errors='ignore').read()
    except Exception:
        return ""
    m = RX["RTC tablette au boot"].search(data)
    return m.group(1) if m else ""


def parse_uart_bootlog(src_dir, export_dir, skip_md5=None, bootlog=None,
                       real_time=None, **kwargs):
    path = find_bootlog(src_dir, bootlog)
    f, w = open_csv(export_dir, 'device_bootlog.csv', ['element', 'valeur', 'source'])
    rows = []
    if not path:
        logging.info("parse_uart_bootlog : aucun log UART fourni (--bootlog) ni détecté.")
        f.close()
        return rows
    try:
        data = open(path, encoding='utf-8', errors='ignore').read()
    except Exception as e:
        logging.warning(f"parse_uart_bootlog : lecture {path} : {e}")
        f.close()
        return rows

    src_name = os.path.basename(path)

    def emit(label, value):
        if value:
            w.writerow([label, value, src_name])
            rows.append([label, value])

    for label, rx in RX.items():
        m = rx.search(data)
        if not m:
            continue
        val = " ".join(g for g in m.groups() if g) if m.groups() else m.group(0)
        emit(label, val.strip())

    # anomalies
    if NV_FAIL_RX.search(data):
        emit("NV (nv_a/nv_b)", "ÉCHEC lecture / CRC (partition NV corrompue ou effacée)")
    ms = SHUTDOWN_RX.search(data)
    if ms:
        emit("Extinction volontaire (reason)", ms.group(1).strip())
    mp = POWERCTL_RX.search(data)
    if mp:
        emit("powerctl déclenché par", f"{mp.group(1)} (process: {mp.group(2)})")

    # BONUS horloge : RTC boot + real_time -> offset auto
    rtc = detect_tablet_time(path)
    if rtc:
        emit("Décalage horloge — heure tablette (RTC boot)", rtc)
        if real_time:
            try:
                from clock_offset import ClockOffset
                clk = ClockOffset.from_args(tablet_time=rtc, real_time=real_time)
                clk.to_json(export_dir)
                emit("Décalage horloge — calculé", clk.human())
                logging.info(f"parse_uart_bootlog : décalage horloge auto = {clk.offset_seconds:+d} s "
                             f"(RTC {rtc} vs réel {real_time})")
            except Exception as e:
                logging.debug(f"calcul offset via bootlog: {e}")

    logging.info(f"parse_uart_bootlog : {len(rows)} éléments extraits de {src_name}")
    f.close()
    return rows
