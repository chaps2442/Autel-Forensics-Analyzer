# finalize_export.py — AFAP
# Auteur : Vincent Chapeau — Teel Technologies Canada (vincent.chapeau@teeltechcanada.com)
#
# Range le dossier d'export en deux sous-dossiers, avec un seul LISEZ-MOI à la
# racine orientant les deux publics :
#   01_SYNTHESE_ENQUETEUR/  -> livrables de synthèse (rapport, table maître, timelines)
#   02_DETAIL_FORENSIC/     -> CSV détaillés par module, logs, dumps (secrets/, event_log/)
#
# À exécuter EN DERNIER (après report/master/htimeline) : à ce stade tous les
# modules ont déjà lu les CSV, on peut donc DÉPLACER sans rien casser.
#
# Produit : arborescence rangée + LISEZ-MOI.txt (racine).

import os
import shutil
import logging

# Livrables destinés à l'enquêteur (synthèse) -> 01_SYNTHESE_ENQUETEUR
SYNTHESE = {
    'rapport_forensique.md',
    'Chronologie_MAITRE.csv',
    'Timeline_interactive.html',
    'Timeline_Chronologique.html',
    'LISEZ-MOI_import_Mercure.txt',
}
DIR_ENQ = '01_SYNTHESE_ENQUETEUR'
DIR_FOR = '02_DETAIL_FORENSIC'
_SELF = {DIR_ENQ, DIR_FOR, 'LISEZ-MOI.txt', 'run_analysis.log'}

_README = """AFAP — Organisation de ce dossier d'analyse
=============================================

Ce dossier contient deux niveaux de lecture :

  01_SYNTHESE_ENQUETEUR/
     Pour l'enquêteur. Vue consolidée, prête à exploiter :
       - rapport_forensique.md      : rapport narratif
       - Chronologie_MAITRE.csv     : chronologie unique (importable Mercure)
       - Timeline_interactive.html  : chronologie filtrable + correction d'horloge
       (chaque ligne de la chronologie indique son fichier source d'origine,
        que l'on retrouve dans 02_DETAIL_FORENSIC/)

  02_DETAIL_FORENSIC/
     Pour l'analyse fine / forensique. Les CSV détaillés par module (VIN, MAC,
     compte, WiFi, Bluetooth, log UART, KYC, logs VCI, ...), les journaux et les
     dumps (secrets/, event_log/). Granularité maximale, traçabilité par source.

Réserve horloge : les heures sont celles de l'horloge interne (RTC) de la
tablette. La colonne date_corrigee de la chronologie contient l'heure recalée
si un décalage a été renseigné à l'extraction.
"""


def finalize_export(src_dir, export_dir, skip_md5=None, **kwargs):
    try:
        enq = os.path.join(export_dir, DIR_ENQ)
        det = os.path.join(export_dir, DIR_FOR)
        os.makedirs(enq, exist_ok=True)
        os.makedirs(det, exist_ok=True)

        moved = 0
        for name in os.listdir(export_dir):
            if name in _SELF:
                continue
            src = os.path.join(export_dir, name)
            dest_dir = enq if name in SYNTHESE else det
            try:
                shutil.move(src, os.path.join(dest_dir, name))
                moved += 1
            except Exception as e:
                logging.warning(f"finalize_export: déplacement {name}: {e}")

        with open(os.path.join(export_dir, 'LISEZ-MOI.txt'), 'w', encoding='utf-8') as f:
            f.write(_README)

        logging.info(f"finalize_export : {moved} éléments rangés "
                     f"({DIR_ENQ} / {DIR_FOR}) + LISEZ-MOI.txt")
        return [DIR_ENQ, DIR_FOR]
    except Exception as e:
        logging.warning(f"finalize_export: {e}")
        return []
