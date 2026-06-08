# i18n.py — AFAP v2.1.0
# Auteur : Vincent Chapeau — Teel Technologies Canada (vincent.chapeau@teeltechcanada.com)
#
# Système de traduction minimaliste : dictionnaire `STRINGS[lang][key]`
# avec fallback automatique sur FR si la clé n'existe pas en EN.
#
# Usage :
#     from i18n import T, set_lang
#     set_lang('en')                 # ou 'fr' (défaut)
#     msg = T('report.section1')

STRINGS = {
    'fr': {
        # ---------- En-tête de rapport ----------
        'report.title':       "Rapport d'analyse forensique — Tablette Autel",
        'report.serial':      "Numéro de série",
        'report.model':       "Modèle",
        'report.source':      "Source",
        'report.generated':   "Généré le",
        'report.tool':        "Outil",

        # ---------- Sections ----------
        'section.exec':       "Synthèse exécutive",
        'section.id':         "Identification de la tablette",
        'section.ops':        "Opérations véhicule documentées (CloudEData)",
        'section.usage':      "Usage par marque / module véhicule",
        'section.vci':        "Logs VCI (communications OBD avec véhicule)",
        'section.storage':    "Supports de stockage externes (SD/USB)",
        'section.es':         "ES File Explorer — historique & apps connues",
        'section.secrets':    "Secrets & matériel cryptographique",
        'section.events':     "EventLog applicatif (format binaire encodé)",
        'section.wal':        "Bases SQLite — fichiers WAL/SHM détectés",
        'section.std':        "Synthèse des modules d'extraction historiques",
        'section.methodo':    "Méthodologie & limites",

        # ---------- Labels champs identification ----------
        'id.serial':          "Numéro de série",
        'id.model':           "Modèle",
        'id.os':              "Version OS",
        'id.app':             "Version application",
        'id.vci':             "VCI (Vehicle Communication Interface)",
        'id.vci_fw':          "  Firmware VCI",
        'id.vci_sw':          "  Software VCI",
        'id.lang':            "Langue",
        'id.area':            "Zone véhicule",
        'id.ip':              "Dernière IP locale observée",

        # ---------- Synthèse exécutive ----------
        'exec.intro':         "Cette analyse révèle les éléments forensiques majeurs suivants :",
        'exec.days':          "**{n} jours d'activité réelle** documentés (du {first} au {last})",
        'exec.ops':           "**{n} opération(s) véhicule** documentée(s) par télémétrie cloud",
        'exec.brand':         "Tablette **spécialisée {brand}** — {n} utilisations sur {total} modules",
        'exec.vins':          "**{n} VIN(s) unique(s)** observé(s) dans les logs VCI",
        'exec.vol':           "**{n} support(s) externe(s)** SD/USB monté(s) (UUID : {uuids})",
        'exec.secrets':       "**{n} artefact(s)** cryptographique(s) / d'authentification ramassé(s)",
        'exec.wal':           "**{n} WAL SQLite** détecté(s) — récupération possible de transactions effacées",
        'exec.suspect_apps':  "Présence d'outils internes Autel (non destinés au client final) : {apps}",
        'exec.no_data':       "Aucun élément forensique majeur trouvé dans cette extraction.",

        # ---------- Petits messages ----------
        'msg.not_found':      "(non renseigné)",
        'msg.see_csv':        "Détails complets : `{path}`",
        'msg.see_more':       "*(et {n} autres — voir `{path}`)*",
    },

    'en': {
        # ---------- Report header ----------
        'report.title':       "Forensic analysis report — Autel tablet",
        'report.serial':      "Serial number",
        'report.model':       "Model",
        'report.source':      "Source",
        'report.generated':   "Generated on",
        'report.tool':        "Tool",

        # ---------- Sections ----------
        'section.exec':       "Executive Summary",
        'section.id':         "Tablet identification",
        'section.ops':        "Documented vehicle operations (CloudEData)",
        'section.usage':      "Usage by manufacturer / vehicle module",
        'section.vci':        "VCI logs (OBD communications with vehicle)",
        'section.storage':    "External storage media (SD/USB)",
        'section.es':         "ES File Explorer — history & known apps",
        'section.secrets':    "Secrets & cryptographic material",
        'section.events':     "Application EventLog (binary encoded format)",
        'section.wal':        "SQLite databases — WAL/SHM files detected",
        'section.std':        "Summary of legacy extraction modules",
        'section.methodo':    "Methodology & limitations",

        # ---------- Identification field labels ----------
        'id.serial':          "Serial number",
        'id.model':           "Model",
        'id.os':              "OS version",
        'id.app':             "Application version",
        'id.vci':             "VCI (Vehicle Communication Interface)",
        'id.vci_fw':          "  VCI firmware",
        'id.vci_sw':          "  VCI software",
        'id.lang':             "Language",
        'id.area':            "Vehicle area",
        'id.ip':              "Last local IP observed",

        # ---------- Executive Summary ----------
        'exec.intro':         "This analysis reveals the following major forensic findings:",
        'exec.days':          "**{n} days of actual activity** documented (from {first} to {last})",
        'exec.ops':           "**{n} vehicle operation(s)** documented by cloud telemetry",
        'exec.brand':         "Tablet **specialized in {brand}** — {n} uses out of {total} modules",
        'exec.vins':          "**{n} unique VIN(s)** observed in VCI logs",
        'exec.vol':           "**{n} external storage device(s)** SD/USB mounted (UUID: {uuids})",
        'exec.secrets':       "**{n} cryptographic/authentication artifact(s)** collected",
        'exec.wal':           "**{n} SQLite WAL** detected — possible recovery of deleted transactions",
        'exec.suspect_apps':  "Presence of Autel internal tools (not intended for end users): {apps}",
        'exec.no_data':       "No major forensic finding in this extraction.",

        # ---------- Small messages ----------
        'msg.not_found':      "(not provided)",
        'msg.see_csv':        "Full details: `{path}`",
        'msg.see_more':       "*(and {n} more — see `{path}`)*",
    },
}

_CURRENT_LANG = 'fr'

def set_lang(lang: str):
    """Active la langue (fr / en). Inconnue → fr."""
    global _CURRENT_LANG
    _CURRENT_LANG = lang if lang in STRINGS else 'fr'

def get_lang():
    return _CURRENT_LANG

def T(key: str, **kwargs) -> str:
    """Récupère une string traduite ; fallback FR si manquante en EN."""
    val = STRINGS.get(_CURRENT_LANG, {}).get(key) or STRINGS['fr'].get(key) or key
    if kwargs:
        try:
            return val.format(**kwargs)
        except Exception:
            return val
    return val
