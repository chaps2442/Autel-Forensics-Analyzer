# scan_text.py — AFAP
# Auteur : Vincent Chapeau — Teel Technologies Canada (vincent.chapeau@teeltechcanada.com)
#
# Orchestrateur "PASSE UNIQUE" + MULTIPROCESSING des extracteurs texte.
#
# Objectif : lire chaque .log/.txt une seule fois ET répartir le travail LOURD
# (regex) sur plusieurs cœurs. Les workers ne renvoient que des "bundles"
# d'événements bruts (picklables) ; le PARENT les rejoue DANS L'ORDRE DES
# FICHIERS via apply_bundle, ce qui reproduit EXACTEMENT le résultat séquentiel
# (indispensable : le volet WiFi propage passerelle/RSSI à travers les fichiers).
#
# Sécurité : si le multiprocessing échoue pour une raison quelconque, on retombe
# AUTOMATIQUEMENT en séquentiel (résultat identique). La correction prime sur la
# vitesse.
#
# IMPORTANT : extract_mac doit tourner AVANT (WifiConsumer lit mac_found.csv).
#
# Produit (via les consommateurs) : account_identity.csv, wifi_networks.csv,
#   bluetooth_devices.csv.

import os
import logging
import hashlib
import multiprocessing
from core_scanner import iter_entries, run_text_consumers, _long_path_aware
from extract_account import AccountConsumer
from extract_wifi import WifiConsumer
from extract_bluetooth import BluetoothConsumer

# En dessous de ce nombre de fichiers, le séquentiel est plus rapide
# (le coût de création des processus dépasse le gain).
_PARALLEL_MIN_FILES = 12
_MAX_PROCS = 8

_SKIP = set()  # skiplist MD5, injectée dans chaque worker via l'initializer


def _winit(skip):
    global _SKIP
    _SKIP = skip or set()


def _process_file(task):
    """Worker : lit UN fichier (une seule fois), applique la skiplist, puis
    produit les bundles bruts des trois extracteurs. Aucun état partagé."""
    path, rel_path, mtime = task
    try:
        with open(_long_path_aware(path), 'rb') as f:
            raw = f.read()
    except Exception:
        return None
    if _SKIP and hashlib.md5(raw).hexdigest().lower() in _SKIP:
        return None
    text = raw.decode('utf-8', 'ignore')
    return (AccountConsumer.build_bundle(rel_path, mtime, text),
            WifiConsumer.build_bundle(rel_path, mtime, text),
            BluetoothConsumer.build_bundle(rel_path, mtime, text))


def scan_text_single_pass(src_dir, export_dir, skip_md5=None, **kwargs):
    """Passe unique compte + WiFi + Bluetooth. Parallélise sur les fichiers
    lorsque la source est un DOSSIER et qu'il y a plusieurs cœurs ; sinon (ou en
    cas d'échec, ou pour une archive) exécute la passe séquentielle. Le résultat
    est identique dans tous les cas."""
    acc, wifi, bt = AccountConsumer(), WifiConsumer(), BluetoothConsumer()

    tasks = []
    if os.path.isdir(src_dir):
        for entry in iter_entries(src_dir, include_ext=('.log', '.txt')):
            if entry.is_os:
                tasks.append((entry.path, entry.rel_path, entry.mtime))

    parallel = (os.cpu_count() or 1) > 1 and len(tasks) >= _PARALLEL_MIN_FILES
    done = False
    if parallel:
        try:
            nproc = min(os.cpu_count() or 1, _MAX_PROCS)
            chunk = max(1, len(tasks) // (nproc * 4) or 1)
            with multiprocessing.Pool(processes=nproc, initializer=_winit, initargs=(skip_md5,)) as pool:
                # pool.map conserve l'ORDRE des tâches = ordre des fichiers.
                for res in pool.map(_process_file, tasks, chunksize=chunk):
                    if res is None:
                        continue
                    ab, wb, bb = res
                    acc.apply_bundle(ab)
                    wifi.apply_bundle(wb)
                    bt.apply_bundle(bb)
            done = True
            logging.info(f"scan_text : passe unique parallèle ({nproc} procs, {len(tasks)} fichiers)")
        except Exception as e:
            logging.warning(f"scan_text : multiprocessing indisponible ({e}) -> séquentiel")
            acc, wifi, bt = AccountConsumer(), WifiConsumer(), BluetoothConsumer()
            done = False

    if not done:
        run_text_consumers(src_dir, [acc, wifi, bt], include_ext=('.log', '.txt'), skip_md5=skip_md5)

    all_rows = []
    for c in (acc, wifi, bt):
        try:
            r = c.finalize(export_dir)
            if r:
                all_rows.extend(r)
        except Exception as e:
            logging.warning(f"scan_text_single_pass finalize {getattr(c, 'name', c)}: {e}")
    return all_rows
