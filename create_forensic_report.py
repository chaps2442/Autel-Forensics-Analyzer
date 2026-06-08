# create_forensic_report.py — AFAP v2.1.0
# Auteur : Vincent Chapeau — Teel Technologies Canada (vincent.chapeau@teeltechcanada.com)
#
# Génère un VRAI rapport forensique consolidé en Markdown.
# Sections numérotées :
#   0. Synthèse exécutive (executive summary) ← NOUVEAU en v2.1
#   1. Identification de la tablette
#   2. Opérations véhicule (CloudEData)
#   3. Usage par marque
#   4. Logs VCI
#   5. Stockage externe
#   6. ES File Explorer
#   7. Secrets
#   8. EventLog
#   9. WAL SQLite
#   10. Modules historiques
#   A. Méthodologie & limites
#
# Bilingue : la langue est définie via i18n.set_lang() AVANT l'appel.

import csv
import datetime
import logging
import os
from collections import Counter, defaultdict

try:
    from i18n import T, get_lang
except ImportError:
    # Fallback si i18n.py absent
    def T(k, **kw): return k
    def get_lang(): return 'fr'

# ----------------------------------------------------------------------
def _read(path):
    if not os.path.isfile(path):
        return []
    try:
        with open(path, 'r', encoding='utf-8-sig', newline='') as f:
            return list(csv.DictReader(f))
    except Exception as e:
        logging.warning(f"Lecture CSV {path} : {e}")
        return []

# ----------------------------------------------------------------------
def _tablet_info(export_dir):
    rows = _read(os.path.join(export_dir, 'tablet_info.csv'))
    return {r['Information']: r['Valeur'] for r in rows if r.get('Information')}

# ----------------------------------------------------------------------
def _section_exec_summary(export_dir, info):
    """Section 0 - Executive Summary : 5-8 bullets sur les findings critiques."""
    bullets = []

    cloud = _read(os.path.join(export_dir, 'cloud_e_data.csv'))
    if cloud:
        bullets.append(T('exec.ops', n=len(cloud)))

    vci_idx = _read(os.path.join(export_dir, 'vci_logs_index.csv'))
    if vci_idx:
        days = sorted({r['datetime_log'][:10] for r in vci_idx if r.get('datetime_log')})
        if days:
            bullets.append(T('exec.days', n=len(days), first=days[0], last=days[-1]))

    vci_evt = _read(os.path.join(export_dir, 'vci_logs_events.csv'))
    vins = sorted({r['detail'] for r in vci_evt if r.get('evenement') == 'VIN_IN_LOG'})
    if vins:
        bullets.append(T('exec.vins', n=len(vins)))

    mu = _read(os.path.join(export_dir, 'modules_usage.csv'))
    used = [r for r in mu if (r.get('freq_utilisation') or '0').isdigit() and int(r['freq_utilisation']) > 0]
    if used:
        used.sort(key=lambda r: -int(r['freq_utilisation']))
        top = used[0]
        bullets.append(T('exec.brand', brand=top.get('car_name',''), n=top.get('freq_utilisation',''), total=len(mu)))

    ext = _read(os.path.join(export_dir, 'external_storage_seen.csv'))
    if ext:
        uuids = ', '.join(f"`{r.get('volume_id','')}`" for r in ext[:5])
        bullets.append(T('exec.vol', n=len(ext), uuids=uuids))

    sec = _read(os.path.join(export_dir, 'secrets_found.csv'))
    if sec:
        bullets.append(T('exec.secrets', n=len(sec)))

    wal = _read(os.path.join(export_dir, 'wal_indicators.csv'))
    wal_nz = [w for w in wal if int(w.get('wal_size_bytes') or 0) > 0]
    if wal_nz:
        bullets.append(T('exec.wal', n=len(wal_nz)))

    apps = _read(os.path.join(export_dir, 'es_installed_apps.csv'))
    suspects = {'com.example.copytool', 'com.autel.factorytest', 'com.google.zxing.client.android'}
    suspect_apps = [a.get('package') for a in apps if a.get('package') in suspects]
    if suspect_apps:
        bullets.append(T('exec.suspect_apps', apps=', '.join(f"`{p}`" for p in suspect_apps)))

    out = [f"## 0. {T('section.exec')}\n"]
    if not bullets:
        out.append(T('exec.no_data'))
        out.append("")
        return '\n'.join(out)
    out.append(T('exec.intro') + "\n")
    for b in bullets:
        out.append(f"- {b}")
    out.append("")
    return '\n'.join(out)

# ----------------------------------------------------------------------
def _section_identification(info):
    out = [f"## 1. {T('section.id')}\n"]
    labels = [
        ('Serial',                T('id.serial')),
        ('Product model',         T('id.model')),
        ('Os version',            T('id.os')),
        ('App version',           T('id.app')),
        ('Vci name',              T('id.vci')),
        ('Vci firmware',          T('id.vci_fw')),
        ('Vci software',          T('id.vci_sw')),
        ('Langue',                T('id.lang')),
        ('Zone vehicule',         T('id.area')),
        ('Derniere ip observee',  T('id.ip')),
    ]
    out.append("| Champ | Valeur |\n|---|---|" if get_lang()=='fr' else "| Field | Value |\n|---|---|")
    for k, label in labels:
        v = info.get(k, '')
        if v and v != 'inconnu':
            out.append(f"| {label} | `{v}` |")
    out.append("")
    return '\n'.join(out)

# ----------------------------------------------------------------------
def _section_cloud_e_data(export_dir):
    rows = _read(os.path.join(export_dir, 'cloud_e_data.csv'))
    if not rows: return ""
    out = [f"## 2. {T('section.ops')}\n"]
    out.append(f"**{len(rows)}** opération(s) documentée(s).\n" if get_lang()=='fr'
               else f"**{len(rows)}** operation(s) documented.\n")
    out.append("| Date | Marque/Modèle | Année | Fonction | Mode | VIN | IP |" if get_lang()=='fr'
               else "| Date | Make/Model | Year | Function | Mode | VIN | IP |")
    out.append("|---|---|---|---|---|---|---|")
    for r in rows[:50]:
        out.append("| {date} | {brand} {model} | {year} | {func} | {mode} | {vin} | {ip} |".format(
            date=r.get('date_operation',''), brand=r.get('vehicle_brand',''),
            model=r.get('vehicle_model',''), year=r.get('vehicle_year',''),
            func=r.get('func_name',''), mode=r.get('func_mode',''),
            vin=r.get('vehicle_vin','') or T('msg.not_found'),
            ip=r.get('ip_locale','')))
    if len(rows) > 50:
        out.append("| … | … | … | … | … | … | … |")
    out.append("")
    return '\n'.join(out)

# ----------------------------------------------------------------------
def _section_module_usage(export_dir):
    rows = _read(os.path.join(export_dir, 'modules_usage.csv'))
    if not rows: return ""
    used = [r for r in rows if (r.get('freq_utilisation') or '0').isdigit() and int(r['freq_utilisation']) > 0]
    used.sort(key=lambda r: -int(r['freq_utilisation']))
    out = [f"## 3. {T('section.usage')}\n"]
    msg = (f"{len(used)} module(s) utilisé(s) sur {len(rows)} disponibles."
           if get_lang()=='fr' else
           f"{len(used)} module(s) used out of {len(rows)} available.")
    out.append(msg + "\n")
    if used:
        out.append("| # | Marque | Version | Lib (MB) | Util. |" if get_lang()=='fr'
                   else "| # | Make | Version | Lib (MB) | Uses |")
        out.append("|---:|---|---|---:|---:|")
        for i, r in enumerate(used[:15], 1):
            out.append(f"| {i} | {r.get('car_name','')} | {r.get('version_installee','')} | {r.get('lib_size_MB','')} | **{r.get('freq_utilisation','')}** |")
        out.append("")
    return '\n'.join(out)

# ----------------------------------------------------------------------
def _section_vci_logs(export_dir):
    idx = _read(os.path.join(export_dir, 'vci_logs_index.csv'))
    evt = _read(os.path.join(export_dir, 'vci_logs_events.csv'))
    if not idx and not evt: return ""
    out = [f"## 4. {T('section.vci')}\n"]
    if idx:
        days = sorted({r['datetime_log'][:10] for r in idx if r.get('datetime_log')})
        total_size = sum(int(r.get('size_bytes') or 0) for r in idx)
        if get_lang()=='fr':
            out.append(f"**{len(idx)} VciLog**, **{len(days)} jour(s)** "
                       f"(du {days[0] if days else '?'} au {days[-1] if days else '?'}), "
                       f"**{total_size/1e6:.1f} MB**.\n")
        else:
            out.append(f"**{len(idx)} VciLog files**, **{len(days)} day(s)** "
                       f"(from {days[0] if days else '?'} to {days[-1] if days else '?'}), "
                       f"**{total_size/1e6:.1f} MB**.\n")
    if evt:
        cnt = Counter(r['evenement'] for r in evt)
        out.append("**Événements :**\n" if get_lang()=='fr' else "**Events:**\n")
        out.append("| Type | # |")
        out.append("|---|---:|")
        for k, v in cnt.most_common():
            out.append(f"| {k} | {v} |")
        out.append("")
        vins = sorted({r['detail'] for r in evt if r['evenement'] == 'VIN_IN_LOG'})
        if vins:
            out.append("**VINs :**" if get_lang()=='fr' else "**VINs:**")
            for v in vins[:30]: out.append(f"- `{v}`")
            if len(vins) > 30: out.append(T('msg.see_more', n=len(vins)-30, path='vci_logs_events.csv'))
            out.append("")
    return '\n'.join(out)

# ----------------------------------------------------------------------
def _section_external_storage(export_dir):
    rows = _read(os.path.join(export_dir, 'external_storage_seen.csv'))
    if not rows: return ""
    out = [f"## 5. {T('section.storage')}\n"]
    out.append(f"**{len(rows)} volume(s)** UUID FAT/exFAT :\n")
    out.append("| UUID | Mount | Paths | Sources |")
    out.append("|---|---|---:|---|")
    for r in rows:
        out.append(f"| `{r['volume_id']}` | `{r['mount_path']}` | {r['nb_paths_seen']} | {r['sources']} |")
    out.append("")
    return '\n'.join(out)

# ----------------------------------------------------------------------
def _section_es_history(export_dir):
    visit = _read(os.path.join(export_dir, 'es_visit_history.csv'))
    apps  = _read(os.path.join(export_dir, 'es_installed_apps.csv'))
    if not visit and not apps: return ""
    out = [f"## 6. {T('section.es')}\n"]
    if visit:
        out.append(f"**{len(visit)}** " + ("entrée(s) visit_history :" if get_lang()=='fr' else "visit_history entries:"))
        out.append("\n| # | Type | Path |")
        out.append("|---:|---|---|")
        for r in visit[:30]:
            t = ('dossier' if get_lang()=='fr' else 'folder') if r.get('isdir')=='1' else ('fichier' if get_lang()=='fr' else 'file')
            out.append(f"| {r.get('id','')} | {t} | `{r.get('path','')}` |")
        out.append("")
    if apps:
        out.append(f"**{len(apps)} apps :**\n")
        out.append("| Package | Name |")
        out.append("|---|---|")
        for r in apps:
            out.append(f"| `{r.get('package','')}` | {r.get('app_name','')} |")
        out.append("")
        suspects = ['com.example.copytool', 'com.autel.factorytest', 'com.google.zxing.client.android']
        present = [r for r in apps if r.get('package') in suspects]
        if present:
            out.append("> " + T('exec.suspect_apps', apps=', '.join(f"`{r['package']}`" for r in present)))
            out.append("")
    return '\n'.join(out)

# ----------------------------------------------------------------------
def _section_secrets(export_dir):
    rows = _read(os.path.join(export_dir, 'secrets_found.csv'))
    if not rows: return ""
    out = [f"## 7. {T('section.secrets')}\n"]
    grouped = defaultdict(list)
    for r in rows: grouped[r.get('type','?')].append(r)
    out.append("| Type | # | " + ("Exemples" if get_lang()=='fr' else "Examples") + " |")
    out.append("|---|---:|---|")
    for k, items in sorted(grouped.items()):
        ex = ', '.join(os.path.basename(it['source_path']) for it in items[:3])
        out.append(f"| {k} | {len(items)} | {ex} |")
    out.append("")
    return '\n'.join(out)

# ----------------------------------------------------------------------
def _section_event_log(export_dir):
    rows = _read(os.path.join(export_dir, 'event_log_timeline.csv'))
    if not rows: return ""
    out = [f"## 8. {T('section.events')}\n"]
    out.append(f"**{len(rows)} event(s)**.\n")
    return '\n'.join(out)

# ----------------------------------------------------------------------
def _section_wal_indicators(export_dir):
    rows = _read(os.path.join(export_dir, 'wal_indicators.csv'))
    if not rows: return ""
    out = [f"## 9. {T('section.wal')}\n"]
    out.append(f"**{len(rows)} WAL** détecté(s).\n" if get_lang()=='fr'
               else f"**{len(rows)} WAL** detected.\n")
    out.append("| DB | WAL bytes | Frames | SHM | Journal |")
    out.append("|---|---:|---:|:-:|:-:|")
    for r in rows:
        out.append(f"| `{r.get('db_path','')}` | {r.get('wal_size_bytes','0')} | "
                   f"{r.get('estimated_frames','0')} | {r.get('shm_present','Non')} | "
                   f"{r.get('has_dash_journal','Non')} |")
    out.append("")
    if get_lang()=='fr':
        out.append("**Outils recommandés** : Sanderson Forensics Browser for SQLite, FQLite, Oxygen Forensic SQLite Viewer.")
    else:
        out.append("**Recommended tools**: Sanderson Forensics Browser for SQLite, FQLite, Oxygen Forensic SQLite Viewer.")
    out.append("")
    return '\n'.join(out)

# ----------------------------------------------------------------------
def _section_standard_modules(export_dir):
    out = [f"## 10. {T('section.std')}\n"]
    files = [
        ('vins_extraits.csv',         "VINs (binaires + textes, validation WMI + check-digit ISO 3779)"),
        ('mac_found.csv',             "MAC (Wi-Fi/Bluetooth) + OUI vendor + locally-administered"),
        ('mac_connections_found.csv', "Connexions/déconnexions MAC horodatées"),
        ('log_events_found.csv',      "Événements parsés des logs applicatifs"),
        ('userId_found.csv',          "Identifiants utilisateur Autel"),
        ('endpoints_found.csv',       "URLs / endpoints HTTP(S)"),
        ('pwd_sn_found.csv',          "Couples sérial / mot de passe"),
        ('vehicule_refs_found.csv',   "Refs pièces véhicule (OEM, FCCID)"),
    ]
    out.append("| CSV | " + ("Contenu" if get_lang()=='fr' else "Content") + " | "
               + ("Lignes" if get_lang()=='fr' else "Rows") + " |")
    out.append("|---|---|---:|")
    for fn, desc in files:
        out.append(f"| `{fn}` | {desc} | {len(_read(os.path.join(export_dir, fn)))} |")
    out.append("")
    return '\n'.join(out)

# ----------------------------------------------------------------------
def _section_methodology():
    if get_lang() == 'en':
        return """## A. Methodology & limitations

**Sources covered**: external partition (`/sdcard`), SQLite databases if present, and `/data/data/` (only on full physical extractions).

**Limitations**:
- On `sdcard-only` extractions, `masdas.db` is absent and several modules will be empty — the report falls back to alternative sources (CloudEData, VciLogs).
- The `Scan/EventLog/<epoch_ms>` payload format is proprietary and not decoded.
- SQLite WAL files are automatically merged on read-only opening; deleted-transaction carving requires a specialized tool (out of scope).

**MD5 skiplist**: `hash_skiplist.txt` contains reference hashes from 3 witness tablets (Brugge, Versailles, +1) to filter out standard OS/Autel artifacts. Applied only to disk files (not VFS archives).
"""
    return """## A. Méthodologie & limites

**Sources couvertes** : partition externe (`/sdcard`), bases SQLite si présentes, et `/data/data/` (uniquement sur extraction physique complète).

**Limites** :
- Sur extraction « sdcard-only », `masdas.db` est absent et plusieurs modules seront vides — le rapport bascule sur sources alternatives (CloudEData, VciLogs).
- Le payload des `Scan/EventLog/<epoch_ms>` est propriétaire, non décodé.
- Les WAL SQLite sont fusionnés automatiquement en lecture seule ; le carving de transactions effacées nécessite un outil spécialisé (hors périmètre).

**Skiplist MD5** : `hash_skiplist.txt` contient les hashs de référence de 3 tablettes témoins (Brugge, Versailles, +1) pour filtrer les artefacts standards. Appliquée uniquement aux fichiers disque (pas aux archives VFS).
"""

# ----------------------------------------------------------------------
def create_forensic_report(src_dir, export_dir, skip_md5=None, **kwargs):
    info = _tablet_info(export_dir)
    serial = info.get('Serial', 'inconnu')
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    parts = [f"# {T('report.title')}\n",
             f"**{T('report.serial')} :** `{serial}`  ",
             f"**{T('report.model')} :** `{info.get('Product model', 'inconnu')}`  ",
             f"**{T('report.source')} :** `{src_dir}`  ",
             f"**{T('report.generated')} :** {now}  ",
             f"**{T('report.tool')} :** Autel Forensics Analyzer PRO (AFAP) v2.1.0\n",
             "---\n"]

    parts.append(_section_exec_summary(export_dir, info))
    parts.append(_section_identification(info))
    parts.append(_section_cloud_e_data(export_dir))
    parts.append(_section_module_usage(export_dir))
    parts.append(_section_vci_logs(export_dir))
    parts.append(_section_external_storage(export_dir))
    parts.append(_section_es_history(export_dir))
    parts.append(_section_secrets(export_dir))
    parts.append(_section_event_log(export_dir))
    parts.append(_section_wal_indicators(export_dir))
    parts.append(_section_standard_modules(export_dir))
    parts.append(_section_methodology())

    parts.append("\n---\n")
    parts.append(f"*AFAP v2.1.0 — Vincent Chapeau, Teel Technologies Canada.*\n")

    out_path = os.path.join(export_dir, 'rapport_forensique.md')
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(parts))
    logging.info(f"Rapport forensique généré : {out_path}")
    return [{'rapport': out_path}]
