# export_docx.py — AFAP v2.4.0
# Auteur : Vincent Chapeau — Teel Technologies Canada (vincent.chapeau@teeltechcanada.com)
#
# Convertit le rapport consolide rapport_forensique.md en rapport_forensique.docx
# a la charte Teel (logo, pagination) via pandoc + gabarit TEEL_reference.docx.
# Module du pipeline : a placer APRES 'report' (qui produit le .md).
# Sans effet si pandoc est absent (retourne [] et journalise) : l'export docx
# est optionnel, le .md reste la sortie de reference.
#
# Dependances : pandoc (obligatoire pour cet export), gabarit TEEL_reference.docx
# a cote de ce module (facultatif : sans lui, docx pandoc par defaut).

import logging
import os
import shutil
import subprocess
import tempfile


def _reference_doc():
    here = os.path.dirname(os.path.abspath(__file__))
    for c in (os.path.join(here, 'TEEL_reference.docx'), 'TEEL_reference.docx'):
        if os.path.isfile(c):
            return c
    return None


def export_docx(src_dir, export_dir, skip_md5=None, **kwargs):
    md_path = os.path.join(export_dir, 'rapport_forensique.md')
    if not os.path.isfile(md_path):
        logging.info("export_docx : rapport_forensique.md absent, saute.")
        return []
    if not shutil.which('pandoc'):
        logging.warning("export_docx : pandoc introuvable, export docx saute.")
        return []

    md = open(md_path, encoding='utf-8').read()
    first = md.split('\n', 1)[0]
    title = first.lstrip('# ').strip() if first.startswith('#') else 'Rapport forensique AFAP'
    body = md.split('\n', 1)[1] if md.startswith('#') else md
    yaml = ('---\ntitle: "%s"\n'
            'author: "Autel Forensics Analyzer PRO (AFAP) - Teel Technologies Canada"\n'
            'lang: fr-FR\n---\n\n' % title.replace('"', "'"))

    out_docx = os.path.join(export_dir, 'rapport_forensique.docx')
    tmp = None
    try:
        with tempfile.NamedTemporaryFile('w', suffix='.md', delete=False,
                                         encoding='utf-8') as f:
            f.write(yaml + body)
            tmp = f.name
        cmd = ['pandoc', tmp, '-o', out_docx, '-f', 'markdown+pipe_tables']
        ref = _reference_doc()
        if ref:
            cmd.append('--reference-doc=' + ref)
        subprocess.run(cmd, check=True, capture_output=True)
    except Exception as e:
        logging.warning("export_docx : pandoc a echoue : %s", e)
        return []
    finally:
        if tmp and os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except Exception:
                pass
    if os.path.isfile(out_docx):
        logging.info("export_docx : %s", out_docx)
        return [{'docx': out_docx}]
    return []
