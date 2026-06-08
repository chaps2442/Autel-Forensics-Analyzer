# Changelog AFAP

## v2.0.0 — 2026-05-11

Refonte unifiée du moteur d'analyse et **8 nouveaux modules** ciblés sur les
artefacts qui n'étaient pas couverts par les versions précédentes,
notamment les **extractions « sdcard-only »** (sans `/data/data/`).

### Ajouts

- `extract_cloud_e_data.py` — parse `Scan/CloudEData/*.json` : chaque JSON
  documente une opération véhicule (PEPS, antidémarreur, programmation clé,
  etc.) avec marque, modèle, année, VIN, IP locale au moment de l'op.
- `extract_module_usage.py` — croise `Scan/Update/.FREQUENCY` ×
  `copyData/CopyInfos.db::CARBASE_INFO` × `.AllUpdateList` pour quantifier
  l'usage par marque (compteur interne de l'app). Révèle aussi si une lib
  véhicule a été effectivement téléchargée (`CAR_LIB_SIZE > 0`).
- `extract_vci_logs.py` — parse `Scan/Data/.VciLog/*.log` (logs OBD du VCI) :
  - extrait l'entête identité (SN, FW VCI, OS) ;
  - extrait les VINs en clair présents dans les échanges PassThru ;
  - parse les commandes `LIB_PASSTHRU` ISO 22900 / SAE J2534
    (`PassThruIoctl`, ChannelID, IoctlID, result) ;
  - chronologie par jour d'activité réelle.
- `extract_es_history.py` — parse les SQLite de ES File Explorer
  (`Android/data/com.estrongs.android.pop/`) : `visit_history` (chemins
  consultés par l'utilisateur) et `appinfo.db` (apps installées).
- `extract_external_storage.py` — détecte les supports SD/USB montés à un
  moment donné, identifiés par leur **UUID FAT/exFAT** (format `XXXX-XXXX`),
  en croisant `visit_history` ES + JSON updates + logs.
- `extract_secrets.py` — ramasse les artefacts cryptographiques :
  `Scan/Data/pem/*.pem`, `Scan/Data/ImCertificate/*.txt`, `Scan/.licence.ini`,
  `tmp/rdp_client.ini` (clés statiques VCI DTxx), `.auth_all_car`,
  `data/.push_deviceid`, JPush (`/.jpush/.jpush_uid.bat`, `/.jpush/.jdevice_id_map.bat`).
  Copie binaire des fichiers dans `<export>/secrets/`.
- `extract_event_log.py` — chronologise `Scan/EventLog/<epoch_ms>` (format
  binaire propriétaire non décodé, mais timestamps exploités pour corréler
  avec les VciLogs). Copie binaire dans `<export>/event_log/`.
- `create_forensic_report.py` — génère un **rapport markdown consolidé**
  `rapport_forensique.md` avec sections numérotées et explications, conçu
  pour être inséré directement dans un dossier d'expertise.

### Modifications

- `utils.py::get_tablet_info()` — fallback en cascade :
  1. `build.prop`
  2. `Scan/CloudEData/*.json` (SN, OS, app, VCI, langue, zone, IP)
  3. en-tête des VciLogs

  Le dict de retour est enrichi : `os_version`, `app_version`, `vci_name`,
  `vci_firmware`, `vci_software`, `langue`, `zone_vehicule`,
  `derniere_ip_observee` — visibles dans `tablet_info.csv` et le rapport.
- `main.py` — pipeline étendu (17 modules) + bouton « Rapport » ouvre
  maintenant `rapport_forensique.md` par défaut (fallback Timeline HTML).

### Notes

- Tous les modules respectent la signature standard
  `(src_dir, export_dir, skip_md5=None, **kwargs) -> list[row]`
  et sortent leurs CSV en `utf-8-sig`.
- Les modules de rapport (`create_timeline_report`, `create_forensic_report`)
  **lisent** les CSV produits par les autres — ils doivent rester en fin de
  pipeline.
- `hash_skiplist.txt` (7 505 hashs, issus de 3 tablettes témoins) est
  appliqué uniquement aux fichiers réels du disque (pas aux flux d'archive).

---

## v1.1 Beta — août 2025

Version publique précédente : 8 modules (VINs, log_events, MAC,
user/endpoints, passwords, vehicle_refs, DCIM, SQLite tables) + interface
Tkinter et décompression `.zip` / `.7z` en `tempfile`.

## v8.0.x (interne) — août 2025

Refactoring vers architecture VFS (lecture directe `.zip`/`.7z` sans
décompression) via `core_scanner` + `fs_provider`. Ajout de
`create_timeline_report` (HTML chronologique).
