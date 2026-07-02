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

## v2.2.0 — Identité compte, réseau, KYC, table maître, décalage horloge

- **clock_offset.py** + options CLI `--tablet-time` / `--real-time` (ou
  `--clock-offset-seconds`) : relever l'heure affichée sur la tablette et
  l'heure réelle au moment de l'extraction ; AFAP calcule le décalage et
  remplit la colonne `date_corrigee` de la table maître. Décalage persisté
  dans `clock_offset.json`.
- **extract_account** (`account`) → `account_identity.csv` : e-mail, pseudo,
  username interne, userId, pays, rôle, téléphone ; datation du compte par
  décodage du userId (nanosecondes epoch) ; distinction appareil/compte
  (regTime + sealerAutelID revendeur).
- **extract_wifi** (`wifi`) → `wifi_networks.csv` : réseau CONNECTÉ (tethering
  iPhone via passerelle 172.20.10.x, SSID nominatif) vs VU EN SCAN (box
  voisines géolocalisables), avec BSSID/MAC.
- **extract_kyc_qr** (`kyc`) → `kyc_qr.csv` : décodage des QR des photos
  (DCIM), repérage des pages KYC Autel (complete-info) + décodage du JWT
  embarqué. Nécessite opencv-python-headless + zxing-cpp.
- **create_master_timeline** (`master`) → `Chronologie_MAITRE.csv` : table
  unique importable (Mercure) consolidant opérations clé, EEPROM, sessions,
  compte, réseau, médias, appareil ; colonnes `date_tablette` et
  `date_corrigee` ; + notice `LISEZ-MOI_import_Mercure.txt`.

## v2.2.1 — Performance (cache MD5/skiplist) + appli timeline à décalage horloge

- **core_scanner** : cache MD5 partagé. Chaque fichier n'est haché qu'UNE fois
  par run ; les fichiers du `hash_skiplist.txt` sont donc écartés sans être
  re-traités par chaque module. (Aucune fonction retirée.)
- **create_timeline_html** (`htimeline`) → `Timeline_interactive.html` :
  application autonome avec filtres (catégorie, constructeur, mois, plage,
  recherche), colonne MAC, export CSV filtré, et surtout un **champ de saisie
  du décalage horloge constaté à l'extraction** (heure tablette / heure réelle
  ou secondes) recalculant la colonne « heure corrigée » EN DIRECT.
- **extract_bluetooth / extract_wifi** : horodatage désormais tiré de la ligne
  de log Android (heure précise de connexion / d'appairage) et non de la date
  du fichier ; l'appareil Bluetooth appairé remonte daté dans la table maître.

## v2.2.1 (suite) — Rapport enrichi + test de fumée

- **create_forensic_report** : 4 nouvelles sections auto-générées (11 Compte
  Autel & identité, 12 Réseau & tethering, 13 Bluetooth, 14 KYC) — affichées
  seulement si les CSV correspondants existent. Aucune section existante retirée.
- **test_v22.py** : test de fumée autonome (18 assertions) sur une extraction
  synthétique — valide horloge, compte, WiFi, Bluetooth, table maître.
  Lancement : `python test_v22.py`.

## v2.2.2 — Perf : mutualisation des lectures (début refactor « passe unique »)

- **core_scanner** : cache du LISTING d'un dossier (`_dir_listing`) — l'arbre
  n'est parcouru (os.walk + stat) qu'une fois par run, quel que soit le nombre
  de modules ; filtrage par extension en mémoire.
- **core_scanner** : `read_text_cached(entry)` — cache texte plafonné (800 Mo)
  pour ne lire chaque `.log/.txt` qu'une fois ; réutilisé par account/wifi/bt.
- Résultats identiques (test_v22 : 18/18). Aucune fonction retirée ; les
  modules existants bénéficient automatiquement du cache de listing.

### Reste (prochaine session)
- Orchestrateur « une seule passe » : lire chaque fichier une fois et alimenter
  tous les extracteurs texte via callbacks (gros gain restant).
- Découpler la table maître des libellés FR (clés stables).
- Base OUI complète (résoudre 5C:36:16).

## v2.3.0 — Log UART / identité matérielle + décalage horloge auto

- **parse_uart_bootlog** (`bootlog`, option `--bootlog <fichier>`) →
  `device_bootlog.csv` : extrait d'un log console UART les identifiants
  MATÉRIELS absents d'un dump (ID SoC/chip, CID+modèle eMMC, versions
  U-Boot/kernel/bootrom), le SN, la RTC de la tablette au boot, les cycles
  batterie, le pays WiFi, veritymode, l'état NV (read_nv fail) et l'anomalie
  securityd (auto-shutdown).
- **Décalage horloge automatique** : si `--bootlog` contient la ligne RTC
  ("setting system clock to …") et que `--real-time` est fourni, le décalage
  est calculé tout seul et écrit dans clock_offset.json → colonne date_corrigee
  remplie sans saisie manuelle.
- **create_master_timeline** intègre l'identité matérielle du bootlog (ligne
  « Identité matérielle (log UART) » + anomalies NV/securityd), datée à la RTC.
- Toujours produits en parallèle : Chronologie_MAITRE.csv (import Mercure) et
  Timeline_interactive.html (avec champ décalage éditable).

## v2.3.0 (GUI) — Interface graphique étendue

- main.py (GUI Tkinter) expose les nouveautés v2.2/2.3 :
  - champ **Log console UART** (fichier .txt/.log) → identité matérielle ;
  - cadre **Décalage horloge** : heure tablette (ou lue dans le log UART),
    heure réelle **pré-remplie avec l'horloge du PC** (bouton « ↻ heure PC »,
    éditable si le PC n'est pas à l'heure), ou décalage direct en secondes ;
  - modules ajoutés au pipeline : account, bootlog, wifi, bt, kyc, master
    (Chronologie_MAITRE.csv), htimeline (Timeline_interactive.html).
- Aucune fonction retirée ; les modules historiques restent identiques.

## v2.3.1 — Rangement de l'export en 2 dossiers

- **finalize_export** (dernier module) : range le dossier d'analyse en
  `01_SYNTHESE_ENQUETEUR/` (rapport, Chronologie_MAITRE.csv, timelines) et
  `02_DETAIL_FORENSIC/` (CSV par module, logs, dumps), avec un unique
  **LISEZ-MOI.txt** à la racine orientant les deux publics. `run_analysis.log`
  reste à la racine. GUI : le bouton « Ouvrir le rapport » pointe vers
  01_SYNTHESE_ENQUETEUR.
