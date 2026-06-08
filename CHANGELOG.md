# Changelog AFAP

## v2.1.0 — 2026-06-08

Trois ajouts majeurs orientés terrain :

### Synthèse exécutive (section 0 du rapport)

`create_forensic_report.py` ajoute une **section "Synthèse exécutive"** en
tête du rapport markdown : 5 à 8 bullet points avec les findings critiques
(jours d'activité, opérations véhicule, marque dominante, VINs uniques,
supports externes, secrets, WAL, outils internes Autel suspects).
Permet au client/magistrat de saisir l'essentiel en 30 secondes avant
les sections détaillées.

### Bilingue FR / EN

Nouveau module `i18n.py` (dictionnaire FR + EN). Le rapport markdown est
intégralement traduit (en-tête, sections, libellés). Bascule via :
- GUI : nouveau radio « Français / English » sous Export
- CLI : flag `--lang en` (défaut `fr`)

Les valeurs brutes (FuncName Autel, chemins fichiers, etc.) restent en
langue d'origine.

### Mode CLI (`cli.py`)

Entrypoint sans GUI Tkinter — utilisable en automation / SSH / batch :

```bash
python cli.py --source ./KM100_B --out ./out [--lang en]
                                              [--modules cloud,vci,wal]
                                              [--skip vins,logs]
                                              [--skiplist <file>]
                                              [--quiet]
```

Imprime le chemin du dossier `Analyse_<SN>_<timestamp>` sur stdout pour
piping.

---

## v2.0.0 — 2026-05-11

Refonte unifiée + **9 modules ajoutés** ciblés sur les artefacts non
couverts par les versions précédentes, notamment les **extractions
« sdcard-only »** (sans `/data/data/`).

### Ajouts

- `extract_cloud_e_data` — opérations véhicule depuis `Scan/CloudEData/*.json`
- `extract_module_usage` — usage par marque via `.FREQUENCY × CARBASE_INFO`
- `extract_vci_logs` — journaux VCI (Scan/Data/.VciLog/*.log) PassThru ISO 22900
- `extract_es_history` — historique ES File Explorer + apps connues
- `extract_external_storage` — SD/USB par UUID FAT/exFAT (XXXX-XXXX)
- `extract_secrets` — PEM, certificats, licence Scan, clés VCI statiques, JPush
- `extract_event_log` — `Scan/EventLog/<epoch_ms>` (décodage hex → bin)
- `extract_wal_indicators` — détection WAL/SHM + section dédiée du rapport
- `create_forensic_report` — `rapport_forensique.md` consolidé

### Modifications

- `utils.get_tablet_info()` — fallback CloudEData puis VciLog header
- `main.py` — pipeline étendu (17 modules)

---

## v1.1 Beta — août 2025

Version publique précédente : 8 modules + GUI Tkinter + décompression
`.zip` / `.7z` en `tempfile`.
