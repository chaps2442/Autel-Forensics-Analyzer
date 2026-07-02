# clock_offset.py — AFAP
# Auteur : Vincent Chapeau — Teel Technologies Canada (vincent.chapeau@teeltechcanada.com)
#
# Gestion du décalage de l'horloge (RTC) de la tablette.
#
# Principe : au moment de l'extraction, l'opérateur relève l'heure AFFICHÉE
# sur la tablette et l'heure RÉELLE de référence (montre/horloge fiable) au
# même instant. Le décalage se calcule :
#
#       offset_seconds = heure_tablette - heure_reelle
#
# Une date enregistrée par la tablette est alors corrigée :
#
#       date_corrigee = date_enregistree - offset_seconds
#
# On peut aussi fournir directement --clock-offset-seconds.
#
# L'objet ClockOffset est sérialisé dans clock_offset.json (export) et relu
# par create_master_timeline pour remplir la colonne date_corrigee.

import json
import os
import datetime

FMTS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y/%m/%d %H:%M:%S",
        "%d/%m/%Y %H:%M:%S", "%Y-%m-%d %H:%M")


def _parse(dt_str):
    if not dt_str:
        return None
    s = dt_str.strip().replace("T", " ")
    for f in FMTS:
        try:
            return datetime.datetime.strptime(dt_str.strip(), f)
        except ValueError:
            continue
    # dernier essai : tronquer les millisecondes
    for f in FMTS:
        try:
            return datetime.datetime.strptime(s[:19], f)
        except ValueError:
            continue
    return None


class ClockOffset:
    """Décalage horloge tablette vs référence réelle."""

    def __init__(self, offset_seconds=0, tablet_time=None, real_time=None, note=""):
        self.offset_seconds = int(offset_seconds)
        self.tablet_time = tablet_time
        self.real_time = real_time
        self.note = note

    @property
    def active(self):
        return self.offset_seconds != 0

    @classmethod
    def from_args(cls, tablet_time=None, real_time=None, offset_seconds=None):
        """Construit à partir des arguments CLI. Priorité à offset_seconds direct."""
        if offset_seconds is not None:
            return cls(offset_seconds=offset_seconds,
                       note=f"offset fourni directement ({offset_seconds} s)")
        t = _parse(tablet_time)
        r = _parse(real_time)
        if t and r:
            off = int((t - r).total_seconds())
            return cls(offset_seconds=off, tablet_time=tablet_time, real_time=real_time,
                       note=f"tablette {tablet_time} vs réel {real_time} => {off:+d} s")
        return cls(0, note="aucun décalage fourni (dates non corrigées)")

    def correct(self, dt_str):
        """Retourne la date corrigée 'YYYY-MM-DD HH:MM:SS' ou '' si non calculable."""
        if not self.active:
            return ""
        d = _parse(dt_str)
        if not d:
            return ""
        return (d - datetime.timedelta(seconds=self.offset_seconds)).strftime("%Y-%m-%d %H:%M:%S")

    def human(self):
        if not self.active:
            return "Aucun décalage appliqué (dates = horloge RTC brute)"
        sign = "en avance" if self.offset_seconds > 0 else "en retard"
        return (f"Décalage RTC : la tablette est {sign} de "
                f"{abs(self.offset_seconds)} s ({self.offset_seconds:+d} s). "
                f"date_corrigee = date_tablette - ({self.offset_seconds:+d} s). {self.note}")

    def to_json(self, export_dir):
        p = os.path.join(export_dir, "clock_offset.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump({"offset_seconds": self.offset_seconds, "tablet_time": self.tablet_time,
                       "real_time": self.real_time, "note": self.note}, f, ensure_ascii=False, indent=2)
        return p

    @classmethod
    def from_json(cls, export_dir):
        p = os.path.join(export_dir, "clock_offset.json")
        if not os.path.isfile(p):
            return cls(0)
        try:
            with open(p, encoding="utf-8") as f:
                d = json.load(f)
            return cls(d.get("offset_seconds", 0), d.get("tablet_time"),
                       d.get("real_time"), d.get("note", ""))
        except Exception:
            return cls(0)
