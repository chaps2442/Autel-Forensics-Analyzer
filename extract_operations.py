# extract_operations.py — AFAP v2.4.0
# Auteur : Vincent Chapeau — Teel Technologies Canada (vincent.chapeau@teeltechcanada.com)
#
# Operations vehicule reellement executees, extraites des sessions de
# diagnostic/programmation situees sous MaxiApScan/DataLogging/.
#
# DEUX AGENCEMENTS pris en charge (selon modele/firmware) :
#   - KM100E : DataLogging/<Marque>/NormalSys_<AAAAMMJJHHMMSS>_<id>.zip
#              (archive contenant *_main.log) + NormalSlience_*.txt (flux CAN)
#   - KM100  : DataLogging/data/NormalSys_<AAAAMMJJHHMMSS>_<id>_main.log
#              (log brut non zippe, sans dossier par marque)
#
# Le *_main.log expose : "FuncName" (fonction executee), "Model", "Year",
# "MenuPath" (region/type de cle/fonction), "carName" (marque, repli).
#
# COMPLEMENTAIRE de extract_cloud_e_data : sur les extractions "sdcard-only"
# ou Scan/CloudEData est ABSENT (cas KM100E), les operations ne se trouvent
# QUE dans DataLogging. Ce module les recupere.
#
# Fichiers nommes par horodatage (pas de couleur/plaque) : le vehicule est
# identifie par marque + modele. Toyota/Lexus n'inscrivent pas le VIN dans la
# cle (absence de VIN = caracteristique, pas lacune).

import io
import os
import re
import zipfile
from core_scanner import iter_entries, open_csv

HEADER = ['datetime_tablette', 'marque', 'modele', 'annee', 'fonction',
          'type_session', 'menu_path', 'source']

_NAME_RE = re.compile(r'Normal(?:Sys|Slience)_(\d{14})_')
_NOT_BRAND = {'data', 'keytooldiag', 'keytoolvideo', ''}


def _parse_main_log(text):
    def g(pat):
        m = re.search(pat, text)
        return m.group(1) if m else ''
    func = g(r'"FuncName":"([^"]{2,})"')
    model = g(r'"Model":"([^"]+)"')
    year = g(r'"Year":"([^"]+)"')
    menu = g(r'"MenuPath":"([^"]{0,120})')
    brand = g(r'"carName":"([^",]+)')
    if not brand and menu:
        brand = menu.split('/', 1)[0]
    return func, model, year, menu, brand


def _fmt(ts):
    try:
        return "%s-%s-%s %s:%s:%s" % (ts[0:4], ts[4:6], ts[6:8],
                                      ts[8:10], ts[10:12], ts[12:14])
    except Exception:
        return ts


def _read(entry, n=None):
    with entry.open_binary() as f:
        return f.read() if n is None else f.read(n)


def _score(o):
    # priorite : fonction nommee > marque via dossier > source hors miroir data/
    return (1 if o['func'] else 0,
            1 if o['path_brand'] else 0,
            0 if '/data/' in ('/' + o['src']) else 1)


def extract_operations(src_dir, export_dir, skip_md5=None, **kwargs):
    seen = {}
    for entry in iter_entries(src_dir):
        rel = entry.rel_path.replace('\\', '/')
        if '/MaxiApScan/DataLogging/' not in '/' + rel:
            continue
        name = os.path.basename(rel)
        m = _NAME_RE.match(name)
        if not m:
            continue
        ts = m.group(1)
        low = name.lower()
        after = rel.split('MaxiApScan/DataLogging/', 1)[1]
        path_brand = after.split('/', 1)[0]
        if path_brand.lower() in _NOT_BRAND:
            path_brand = ''

        func = model = year = menu = log_brand = ''
        kind = 'session'
        try:
            if low.endswith('.zip'):
                zf = zipfile.ZipFile(io.BytesIO(_read(entry)))
                for nm in zf.namelist():
                    if nm.endswith('_main.log'):
                        func, model, year, menu, log_brand = _parse_main_log(
                            zf.read(nm).decode('utf-8', 'replace'))
                        break
                kind = 'operation' if func else 'session'
            elif low.endswith('.log'):
                func, model, year, menu, log_brand = _parse_main_log(
                    _read(entry).decode('utf-8', 'replace'))
                kind = 'operation' if func else 'communication'
            else:  # .txt (NormalSlience) : communication, vide si 0 octet
                kind = 'vide' if len(_read(entry, 64)) == 0 else 'communication'
        except Exception:
            kind = 'session'

        o = {'ts': ts, 'brand': path_brand or log_brand, 'model': model,
             'year': year, 'func': func, 'kind': kind, 'menu': menu,
             'src': rel, 'path_brand': path_brand}
        # cle = horodatage : fusionne le miroir data/ avec le dossier par marque
        cur = seen.get(ts)
        if cur is None or _score(o) > _score(cur):
            seen[ts] = o

    rows = sorted(seen.values(), key=lambda o: o['ts'])
    if not rows:
        return []
    f, w = open_csv(export_dir, 'vehicle_operations.csv', HEADER)
    try:
        for o in rows:
            w.writerow([_fmt(o['ts']), o['brand'], o['model'], o['year'],
                        o['func'], o['kind'], o['menu'], o['src']])
    finally:
        f.close()
    return rows
