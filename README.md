# Autel Forensics Analyzer PRO (AFAP) v2.0.0

> **Auteur :** Vincent Chapeau — Teel Technologies Canada
> **Contact :** vincent.chapeau@teeltechcanada.com
> **Licence :** MIT

Outil d'analyse forensique pour extractions de tablettes Autel
(MaxiIM **KM100**, **KM100X**, et modèles à venir).

L'outil prend en entrée :
- un **dossier** d'extraction logique/physique,
- une **archive `.zip` / `.7z`** (lue directement en VFS — pas de
  décompression complète requise).

Il produit un dossier `Analyse_<SN>_<timestamp>/` contenant les CSV
détaillés, un rapport **markdown consolidé** `rapport_forensique.md`
et une **chronologie graphique** `Timeline_Chronologique.html`.

---

## Modules v2.0.0 (ajoutés)

| Module | Source(s) | CSV produit(s) |
|---|---|---|
| `extract_cloud_e_data`     | `Scan/CloudEData/*.json`            | `cloud_e_data.csv` |
| `extract_module_usage`     | `Scan/Update/.FREQUENCY` × `copyData/CopyInfos.db` × `.AllUpdateList` | `modules_usage.csv` |
| `extract_vci_logs`         | `Scan/Data/.VciLog/*.log`           | `vci_logs_index.csv`, `vci_logs_events.csv` |
| `extract_es_history`       | `com.estrongs.android.pop/cache/visit_history` + `appinfo.db` | `es_visit_history.csv`, `es_installed_apps.csv` |
| `extract_external_storage` | UUID FAT/exFAT croisés sur multi-sources | `external_storage_seen.csv` |
| `extract_secrets`          | `Scan/Data/pem/`, `ImCertificate/`, `.licence.ini`, `tmp/rdp_client.ini`, JPush, `.auth_all_car`, `data/.push_deviceid` | `secrets_found.csv` + copies dans `secrets/` |
| `extract_event_log`        | `Scan/EventLog/<epoch_ms>` (hex)    | `event_log_timeline.csv` + dump hex/bin dans `event_log/` |
| `extract_wal_indicators`   | `*.db-wal`, `*.db-shm`, `*.db-journal` | `wal_indicators.csv` |
| `create_forensic_report`   | (lit les CSV produits)              | `rapport_forensique.md` |

Le module `utils.get_tablet_info()` a été étendu : il prend en charge
les extractions « sdcard-only » (sans `build.prop`) en faisant un fallback
sur les JSON `Scan/CloudEData/*.json` puis sur les entêtes des VciLogs.

---

## Modules historiques préservés (v1.x → v8.x)

- `extract_all_vins` — VINs binaires + textes, validation WMI + check-digit ISO 3779
- `extract_all_log_events` — événements applicatifs (15 patterns regex)
- `extract_mac` — MAC + OUI vendor + flag locally-administered, connexions horodatées
- `extract_user_and_endpoints` — `userId` + URLs dans les logs
- `extract_passwords` — paires SN/password (texte ou JSON `queryAppInfo`)
- `extract_vehicle_refs` — `mainItem`, références OEM / FCCID
- `extract_dcim_media` — copie DCIM
- `export_sqlite_tables` — `tb_history_menu`, `tb_user_info`, `tb_vci_record` (et toute autre DB SQLite trouvée)
- `create_timeline_report` — `Timeline_Chronologique.html`

---

## Récupération de transactions effacées (WAL)

AFAP **détecte et signale** les fichiers WAL/SHM présents (voir
`wal_indicators.csv` + section 9 du rapport), mais **n'effectue pas** le
carving de transactions effacées (ce n'est pas le rôle d'AFAP — l'API
SQLite standard fusionne automatiquement le WAL en lecture seule).

Pour récupérer les enregistrements effacés depuis un WAL, utiliser un
outil forensique spécialisé :

- **Sanderson Forensics — Forensic Browser for SQLite** (commercial)
- **FQLite** (open-source)
- **Oxygen Forensic SQLite Viewer**

Le rapport indique automatiquement quels WAL sont les candidats
prioritaires (triés par taille).

---

## Skiplist par hash MD5

`hash_skiplist.txt` (7 505 entrées) contient les empreintes de fichiers
de référence connus, apportés par **trois tablettes témoins** (Brugge,
Versailles, +1) — ces fichiers standards de l'OS / des libs Autel
sont automatiquement écartés du scan VIN binaire pour éviter le bruit.

La skiplist est appliquée **uniquement** aux fichiers réels du disque ;
en lecture VFS sur archive `.zip`/`.7z`, elle est inopérante (limitation
connue — un hash sur le flux décompressé serait coûteux).

---

## Dépendances

- Python 3.8+
- `py7zr` (recommandé) — pour lire les `.7z` sans décompression
- `psutil` (optionnel) — affichage CPU/RAM dans la GUI

```bash
pip install py7zr psutil
```

---

## Lancement

```bash
python main.py
```

Interface graphique → sélectionner la source (dossier / `.zip` / `.7z`)
et le dossier d'export → bouton **Analyser**.

Le bouton **« Ouvrir le rapport »** à la fin de l'analyse ouvre
`rapport_forensique.md` (fallback Timeline HTML).

---

## Auteur

Vincent Chapeau
Teel Technologies Canada
`vincent.chapeau@teeltechcanada.com`
