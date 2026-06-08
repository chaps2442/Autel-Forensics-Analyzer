# create_forensic_report.py — AFAP v2.0.0
# Auteur : Vincent Chapeau — Teel Technologies Canada (vincent.chapeau@teeltechcanada.com)
#
# Génère un VRAI rapport forensique consolidé en Markdown à partir de tous les
# CSV produits par les autres modules. Ce rapport est destiné à être inséré
# tel quel dans un dossier d'expertise judiciaire ou technique.
#
# Il N'écrit PAS lui-même de CSV — il lit les CSV existants dans export_dir.
# Doit donc être exécuté EN DERNIER.
#
# Sortie : rapport_forensique.md (+ une copie Timeline_Chronologique.html déjà
# produite par create_timeline_report.py).

import csv
import datetime
import logging
import os
from collections import Counter, defaultdict

# ----------------------------------------------------------------------
# Petits helpers de lecture CSV (tous nos CSV sont utf-8-sig)
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

def _count(rows): return len(rows)

# ----------------------------------------------------------------------
def _tablet_info(export_dir):
    rows = _read(os.path.join(export_dir, 'tablet_info.csv'))
    return {r['Information']: r['Valeur'] for r in rows if r.get('Information')}

# ----------------------------------------------------------------------
def _section_identification(info):
    out = ["## 1. Identification de la tablette\n"]
    labels = [
        ('Serial', 'Numéro de série'),
        ('Product model', 'Modèle'),
        ('Os version', 'Version OS'),
        ('App version', 'Version application'),
        ('Vci name', 'VCI (Vehicle Communication Interface)'),
        ('Vci firmware', '  Firmware VCI'),
        ('Vci software', '  Software VCI'),
        ('Langue', 'Langue'),
        ('Zone vehicule', 'Zone véhicule'),
        ('Derniere ip observee', 'Dernière IP locale observée'),
    ]
    out.append("| Champ | Valeur |\n|---|---|")
    for k, label in labels:
        v = info.get(k, '')
        if v and v != 'inconnu':
            out.append(f"| {label} | `{v}` |")
    out.append("")
    out.append("> *Source : `build.prop` (extraction complète) ou JSON `Scan/CloudEData/*.json` (extraction « sdcard-only ») ou en-tête des `Scan/Data/.VciLog/*.log`. Voir `tablet_info.csv`.*\n")
    return '\n'.join(out)

# ----------------------------------------------------------------------
def _section_cloud_e_data(export_dir):
    rows = _read(os.path.join(export_dir, 'cloud_e_data.csv'))
    if not rows:
        return ""
    out = ["## 2. Opérations véhicule documentées (CloudEData)\n"]
    out.append(f"**{len(rows)}** opération(s) documentée(s) par la télémétrie cloud de l'application Autel. Chaque JSON `Scan/CloudEData/<epoch>_<SN>.json` correspond à *une* fonction Autel exécutée sur un véhicule.\n")
    out.append("| Date | Marque/Modèle | Année | Fonction | Mode | VIN | IP locale |")
    out.append("|---|---|---|---|---|---|---|")
    for r in rows[:50]:
        out.append("| {date} | {brand} {model} | {year} | {func} | {mode} | {vin} | {ip} |".format(
            date=r.get('date_operation',''), brand=r.get('vehicle_brand',''),
            model=r.get('vehicle_model',''), year=r.get('vehicle_year',''),
            func=r.get('func_name',''), mode=r.get('func_mode',''),
            vin=r.get('vehicle_vin','') or '(non renseigné)',
            ip=r.get('ip_locale','')
        ))
    if len(rows) > 50:
        out.append(f"| … | … | … | … | … | … | … |  *(détails complets : `cloud_e_data.csv`)*")
    out.append("\n> *Ces JSON sont émis par l'app pour upload vers le backend Autel après chaque action véhicule réussie. Ils sont une **preuve directe** de l'utilisation de la tablette sur un véhicule donné.*\n")
    return '\n'.join(out)

# ----------------------------------------------------------------------
def _section_module_usage(export_dir):
    rows = _read(os.path.join(export_dir, 'modules_usage.csv'))
    if not rows:
        return ""
    # Filtrer les modules avec usage > 0
    used = [r for r in rows if (r.get('freq_utilisation') or '0').isdigit() and int(r['freq_utilisation']) > 0]
    used.sort(key=lambda r: -int(r['freq_utilisation']))
    out = ["## 3. Usage par marque / module véhicule\n"]
    out.append(f"Le compteur d'usage interne de l'app (`Scan/Update/.FREQUENCY`) montre **{len(used)} module(s)** utilisé(s) au moins une fois sur **{len(rows)} disponibles**.\n")
    if used:
        out.append("**Top 15 :**\n")
        out.append("| Rang | Marque | Version installée | Lib (MB) | Utilisations |")
        out.append("|---:|---|---|---:|---:|")
        for i, r in enumerate(used[:15], 1):
            out.append(f"| {i} | {r.get('car_name','')} | {r.get('version_installee','')} | {r.get('lib_size_MB','')} | **{r.get('freq_utilisation','')}** |")
        out.append("")
        out.append(f"*Détails complets : `modules_usage.csv` ({len(rows)} lignes).*\n")
        # Indicateur de spécialisation
        if used and int(used[0]['freq_utilisation']) > sum(int(r['freq_utilisation']) for r in used[1:]):
            out.append(f"> ⚠️ **Tablette spécialisée {used[0].get('car_name','')}** — ce constructeur représente la majorité de l'activité.\n")
    return '\n'.join(out)

# ----------------------------------------------------------------------
def _section_vci_logs(export_dir):
    idx = _read(os.path.join(export_dir, 'vci_logs_index.csv'))
    evt = _read(os.path.join(export_dir, 'vci_logs_events.csv'))
    if not idx and not evt:
        return ""
    out = ["## 4. Logs VCI (communications OBD avec véhicule)\n"]
    if idx:
        days = sorted({r['datetime_log'][:10] for r in idx if r.get('datetime_log')})
        total_size = sum(int(r.get('size_bytes') or 0) for r in idx)
        out.append(f"**{len(idx)} fichier(s) VciLog** couvrant **{len(days)} jour(s) d'activité réelle** "
                   f"(du {days[0] if days else '?'} au {days[-1] if days else '?'}), "
                   f"volume cumulé : **{total_size/1e6:.1f} MB**.\n")
        out.append("Jours observés : `" + ', '.join(days) + "`\n")
    if evt:
        cnt = Counter(r['evenement'] for r in evt)
        out.append("**Événements parsés :**\n")
        out.append("| Type d'événement | Occurrences |")
        out.append("|---|---:|")
        for k, v in cnt.most_common():
            out.append(f"| {k} | {v} |")
        out.append("")
        # VINs uniques observés dans les VciLogs
        vins = sorted({r['detail'] for r in evt if r['evenement'] == 'VIN_IN_LOG'})
        if vins:
            out.append(f"**VINs uniques observés dans les VciLogs ({len(vins)}) :**")
            out.append('\n'.join(f"- `{v}`" for v in vins[:30]))
            if len(vins) > 30:
                out.append(f"- *(et {len(vins)-30} autres — voir `vci_logs_events.csv`)*")
            out.append("")
    out.append("> *Ces logs sont écrits par la lib `LIB_PASSTHRU` (ISO 22900 / SAE J2534) pendant chaque session OBD. Ils contiennent les commandes bas-niveau échangées avec le véhicule.*\n")
    return '\n'.join(out)

# ----------------------------------------------------------------------
def _section_external_storage(export_dir):
    rows = _read(os.path.join(export_dir, 'external_storage_seen.csv'))
    if not rows:
        return ""
    out = ["## 5. Supports de stockage externes (SD/USB)\n"]
    out.append(f"**{len(rows)} volume(s) externe(s)** identifié(s) par leur UUID FAT/exFAT :\n")
    out.append("| UUID | Chemin de montage | Chemins observés | Sources |")
    out.append("|---|---|---:|---|")
    for r in rows:
        out.append(f"| `{r['volume_id']}` | `{r['mount_path']}` | {r['nb_paths_seen']} | {r['sources']} |")
    out.append("")
    out.append("> *L'UUID FAT/exFAT est gravé dans le secteur de boot du volume — il permet d'identifier formellement le support physique correspondant.*\n")
    return '\n'.join(out)

# ----------------------------------------------------------------------
def _section_es_history(export_dir):
    visit = _read(os.path.join(export_dir, 'es_visit_history.csv'))
    apps  = _read(os.path.join(export_dir, 'es_installed_apps.csv'))
    if not visit and not apps:
        return ""
    out = ["## 6. ES File Explorer — historique & apps connues\n"]
    if visit:
        out.append(f"**Historique de navigation ({len(visit)} entrées)** — fichiers/dossiers consultés par l'utilisateur :\n")
        out.append("| # | Type | Chemin |")
        out.append("|---:|---|---|")
        for r in visit[:30]:
            t = 'dossier' if r.get('isdir') == '1' else 'fichier'
            out.append(f"| {r.get('id','')} | {t} | `{r.get('path','')}` |")
        if len(visit) > 30:
            out.append(f"| … | … | *(détails complets : `es_visit_history.csv`)* |")
        out.append("")
    if apps:
        out.append(f"**Apps installées vues par ES File Explorer ({len(apps)}) :**\n")
        out.append("| Package | Nom affiché |")
        out.append("|---|---|")
        for r in apps:
            out.append(f"| `{r.get('package','')}` | {r.get('app_name','')} |")
        out.append("")
        # Flag interne tools si présents
        suspects = ['com.example.copytool', 'com.autel.factorytest', 'com.google.zxing.client.android']
        present = [r for r in apps if r.get('package') in suspects]
        if present:
            out.append("> ⚠️ Présence d'outils internes Autel (non destinés au client final) : "
                       + ', '.join(f"`{r['package']}`" for r in present) + ".\n")
    return '\n'.join(out)

# ----------------------------------------------------------------------
def _section_secrets(export_dir):
    rows = _read(os.path.join(export_dir, 'secrets_found.csv'))
    if not rows:
        return ""
    out = ["## 7. Secrets & matériel cryptographique\n"]
    grouped = defaultdict(list)
    for r in rows:
        grouped[r.get('type','?')].append(r)
    out.append("| Catégorie | Nombre | Exemples |")
    out.append("|---|---:|---|")
    for k, items in sorted(grouped.items()):
        examples = ', '.join(os.path.basename(it['source_path']) for it in items[:3])
        out.append(f"| {k} | {len(items)} | {examples} |")
    out.append("\n*Les fichiers sont copiés tels quels dans `secrets/`. Voir `secrets_found.csv` pour l'inventaire détaillé.*\n")
    return '\n'.join(out)

# ----------------------------------------------------------------------
def _section_event_log(export_dir):
    rows = _read(os.path.join(export_dir, 'event_log_timeline.csv'))
    if not rows:
        return ""
    out = ["## 8. EventLog applicatif (format binaire encodé)\n"]
    out.append(f"**{len(rows)} event(s)** chronologisés. Le format de payload n'est pas décodé par AFAP (encodage propriétaire Autel), mais les timestamps des noms de fichiers permettent une corrélation avec les VciLogs.\n")
    if rows:
        out.append("| # | Date/heure | Taille | Aperçu hex (80 premiers caractères) |")
        out.append("|---:|---|---:|---|")
        for i, r in enumerate(rows[:10], 1):
            out.append(f"| {i} | {r.get('datetime_local','')} | {r.get('size_bytes','')} | `{r.get('preview_hex','')[:60]}…` |")
        if len(rows) > 10:
            out.append(f"| … | … | … | *(voir `event_log_timeline.csv` et `event_log/` pour les binaires)* |")
        out.append("")
    return '\n'.join(out)

# ----------------------------------------------------------------------
def _section_standard_modules(export_dir):
    """Synthèse des modules historiques AFAP."""
    out = ["## 10. Synthèse des modules d'extraction historiques\n"]
    files = [
        ('vins_extraits.csv', 'VINs extraits (binaires + textes, validation WMI + check-digit ISO 3779)'),
        ('mac_found.csv', 'Adresses MAC (Wi-Fi/Bluetooth) avec OUI vendor et flag locally-administered'),
        ('mac_connections_found.csv', 'Événements de connexion/déconnexion MAC horodatés'),
        ('log_events_found.csv', 'Événements parsés depuis les logs applicatifs (15 patterns)'),
        ('userId_found.csv', 'Identifiants utilisateur Autel trouvés dans les logs'),
        ('endpoints_found.csv', 'URLs / endpoints HTTP(S) contactés'),
        ('pwd_sn_found.csv', 'Couples sérial / mot de passe en clair dans les logs'),
        ('vehicule_refs_found.csv', 'Références de pièces et menus véhicule (OEM, FCCID, MenuPath)'),
    ]
    out.append("| Fichier CSV | Contenu | Lignes |")
    out.append("|---|---|---:|")
    for fn, desc in files:
        rows = _read(os.path.join(export_dir, fn))
        out.append(f"| `{fn}` | {desc} | {len(rows)} |")
    # Tables SQLite
    sqlite_csvs = [f for f in os.listdir(export_dir) if f.startswith('masdas.db_') or '_tb_history_menu.csv' in f or '_tb_user_info.csv' in f or '_tb_vci_record.csv' in f]
    for fn in sqlite_csvs:
        rows = _read(os.path.join(export_dir, fn))
        out.append(f"| `{fn}` | Export SQLite (table directement utilisable) | {len(rows)} |")
    out.append("")
    return '\n'.join(out)


# ----------------------------------------------------------------------
def _section_wal_indicators(export_dir):
    """Section sur les WAL/SHM présents — recommandation outils tiers."""
    rows = _read(os.path.join(export_dir, 'wal_indicators.csv'))
    if not rows:
        return ""
    out = ["## 9. Bases SQLite — fichiers WAL/SHM détectés (récupération de transactions effacées)\n"]
    out.append(f"**{len(rows)} WAL** détecté(s) à côté des bases SQLite de cette tablette. "
               "Le WAL (Write-Ahead Log) contient les **transactions récentes** non encore "
               "fusionnées dans la base principale ; il peut renfermer des enregistrements "
               "**effacés** mais encore présents en clair.\n")
    out.append("| Base | WAL (octets) | Frames | SHM | Journal |")
    out.append("|---|---:|---:|:-:|:-:|")
    for r in rows:
        out.append(f"| `{r.get('db_path','')}` | {r.get('wal_size_bytes','0')} | "
                   f"{r.get('estimated_frames','0')} | {r.get('shm_present','Non')} | "
                   f"{r.get('has_dash_journal','Non')} |")
    out.append("")
    out.append("### Recommandation forensique")
    out.append("AFAP **ne réalise pas** le carving des WAL — l'API SQLite standard fusionne "
               "automatiquement le WAL à l'ouverture en lecture seule, donc les transactions "
               "déjà appliquées sont visibles dans les CSV produits, mais les **transactions "
               "effacées via VACUUM ou un INSERT/DELETE rapide ne sont pas récupérables** "
               "par ce simple mécanisme.\n")
    out.append("Pour aller plus loin, utiliser un outil spécialisé :\n")
    out.append("- **Sanderson Forensics — Forensic Browser for SQLite** (commercial) "
               "— le plus complet pour parser un WAL et exposer chaque frame.")
    out.append("- **FQLite** (open-source) — récupération de cellules effacées + analyse WAL.")
    out.append("- **Oxygen Forensic SQLite Viewer** — intégré aux suites mobiles, "
               "lecture WAL + carving de pages libres.")
    out.append("- **DCode / undark / sqliteparse** — utilitaires CLI pour le carving brut.\n")
    out.append("Les WAL listés ci-dessus sont les **candidats prioritaires** : plus la taille "
               "est élevée, plus le potentiel de récupération est grand. Les frames sont une "
               "estimation grossière (`(taille - 32) / (24 + page_size)`).\n")
    return '\n'.join(out)

# ----------------------------------------------------------------------
def _section_methodology():
    return """## A. Méthodologie & limites

**Sources couvertes :**
- Partition externe (`/sdcard` / `storage/emulated/0`) : DCIM, Download, Scan/, MaxiApScan/, Android/data/ …
- Bases SQLite applicatives (masdas.db et autres) si présentes.
- Partition `/data/data/` si fournie (extraction physique complète).

**Limites connues :**
- Sur une extraction « sdcard-only » (sans `/data/data/`), `masdas.db` est absent et plusieurs modules (VINs venant des bases internes, comptes, sessions HTTP) seront vides — le rapport bascule alors sur les sources alternatives (CloudEData, VciLogs).
- Le format des journaux `Scan/EventLog/<epoch_ms>` n'est pas décodé (payload propriétaire) — seul l'horodatage est exploité.
- Les WAL SQLite (`*.db-wal`) sont automatiquement intégrés à la base par le moteur SQLite à l'ouverture en lecture seule ; pour récupérer des transactions effacées, un carving spécifique du WAL serait nécessaire (hors périmètre AFAP).

**Liste d'exclusion par hash :**
- `hash_skiplist.txt` (MD5 lowercase) contient les empreintes de fichiers de référence connus (apportés par 3 tablettes témoins : Brugge, Versailles, +1) pour ne pas polluer les résultats avec des artefacts standards de l'OS / des libs Autel non-utilisateur.
- Cette skiplist est appliquée *uniquement* aux fichiers réels du disque (pas aux archives lues en VFS).
"""

# ----------------------------------------------------------------------
def create_forensic_report(src_dir, export_dir, skip_md5=None, **kwargs):
    """Génère rapport_forensique.md à partir des CSV produits."""
    info = _tablet_info(export_dir)
    serial = info.get('Serial', 'inconnu')
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    parts = []
    parts.append(f"# Rapport d'analyse forensique — Tablette Autel\n")
    parts.append(f"**Numéro de série :** `{serial}`  ")
    parts.append(f"**Modèle :** `{info.get('Product model', 'inconnu')}`  ")
    parts.append(f"**Source :** `{src_dir}`  ")
    parts.append(f"**Généré le :** {now}  ")
    parts.append(f"**Outil :** Autel Forensics Analyzer PRO (AFAP) v2.0.0\n")
    parts.append("---\n")

    parts.append(_section_identification(info))
    parts.append(_section_cloud_e_data(export_dir))
    parts.append(_section_module_usage(export_dir))
    parts.append(_section_vci_logs(export_dir))
    parts.append(_section_external_storage(export_dir))
    parts.append(_section_es_history(export_dir))
    parts.append(_section_secrets(export_dir))
    parts.append(_section_event_log(export_dir))
    parts.append(_section_standard_modules(export_dir))
    parts.append(_section_wal_indicators(export_dir))
    parts.append(_section_methodology())

    parts.append("\n---\n")
    parts.append(f"*Rapport généré automatiquement par AFAP v2.0.0 — Vincent Chapeau, Teel Technologies Canada.*\n")
    parts.append(f"*Pour la chronologie graphique interactive, ouvrir `Timeline_Chronologique.html`.*\n")

    out_path = os.path.join(export_dir, 'rapport_forensique.md')
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(parts))
    logging.info(f"Rapport forensique généré : {out_path}")
    return [{'rapport': out_path}]
