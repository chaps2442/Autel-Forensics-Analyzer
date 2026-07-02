# extract_account.py — AFAP
# Auteur : Vincent Chapeau — Teel Technologies Canada (vincent.chapeau@teeltechcanada.com)
#
# Identité du compte Autel + datation du compte via le userId.
#
# - Extrait des enregistrements applicatifs User{autelId=..., nickname=..., ...}
#   et des réponses serveur UserCenter (getDevStatus / bindAccount) : e-mail,
#   pseudo, username interne, userId numérique, pays, indicatif, rôle, téléphone.
# - Datation du compte : le userId Autel est un identifiant horodaté dont la
#   valeur = nanosecondes depuis l'epoch Unix ; userId / 1e9 => date de création.
# - Distingue l'APPAREIL (regTime / fitStartDate / sealerAutelID = revendeur)
#   du COMPTE (création déduite du userId).
#
# Produit : account_identity.csv

import re
import csv
import base64
import json
import logging
import datetime
from core_scanner import iter_entries, iter_text_lines_entry, should_skip, open_csv, read_text_cached

USER_RE = re.compile(r"autelId='([^']*)',\s*nickname='([^']*)'")
KV_RE = {
    "autelId": re.compile(r'"?autelId"?\s*[:=]\s*"?([A-Za-z0-9._%+\-@]{3,60})'),
    "email": re.compile(r'"email"\s*:\s*"([A-Za-z0-9._%+\-@]{3,60})"'),
    "username": re.compile(r"username=['\"]?(autel_[A-Za-z0-9]+)"),
    "nickname": re.compile(r"nickname=['\"]?([^',\"}]{1,40})"),
    "country": re.compile(r"country=['\"]?([A-Z]{3,})"),
    "cc": re.compile(r'"cc"\s*:\s*"(\+\d{1,3})"'),
    "role": re.compile(r"roles=['\"]?([A-Z_]+)"),
    "sn": re.compile(r'"sn"\s*:\s*"([A-Z0-9]{8,})"'),
    "regTime": re.compile(r'regTime[\'"]?\s*[:=]\s*[\'"]?(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)'),
    "fitStartDate": re.compile(r'fitStartDate"\s*:\s*"(\d{4}-\d\d-\d\d)'),
    "sealer": re.compile(r'sealerAutelID[\'"]?\s*[:=]\s*[\'"]?(\d+)'),
}
JWT_RE = re.compile(r'eyJ[A-Za-z0-9_\-]+\.(eyJ[A-Za-z0-9_\-]+)\.')
EMAIL_RE = re.compile(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')


def userid_to_creation(uid):
    """userId (ns depuis epoch Unix) -> date de création UTC, ou '' si implausible."""
    try:
        n = int(uid)
    except (TypeError, ValueError):
        return ""
    secs = n / 1_000_000_000.0
    if 1_262_300_000 < secs < 2_524_600_000:  # ~2010..2050
        return datetime.datetime.utcfromtimestamp(secs).strftime("%Y-%m-%d %H:%M:%S") + " UTC"
    return ""


def _decode_jwt(payload_b64):
    payload_b64 += "=" * (-len(payload_b64) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(payload_b64))
    except Exception:
        return None


def extract_account(src_dir, export_dir, skip_md5=None, **kwargs):
    found = {}          # champ -> Counter(valeur)
    phone_empty = False
    jwt_userid = None

    def add(field, value):
        if not value:
            return
        found.setdefault(field, {})
        found[field][value] = found[field].get(value, 0) + 1

    try:
        for entry in iter_entries(src_dir, include_ext=('.log', '.txt')):
            if entry.is_os and should_skip(entry.path, skip_md5):
                continue
            data = read_text_cached(entry)

            for m in USER_RE.finditer(data):
                add("autelId (User{})", m.group(1))
                add("nickname", m.group(2))
            for field, rx in KV_RE.items():
                for m in rx.finditer(data):
                    add(field, m.group(1))
            for e in EMAIL_RE.finditer(data):
                v = e.group(0)
                if "autel.com" not in v and not v[0].isdigit() and "drm@" not in v:
                    add("email (brut)", v)
            if re.search(r'phoneNumber\s*[:=]\s*,|"phoneNumber":""|phoneNumber=,', data):
                phone_empty = True
            for m in JWT_RE.finditer(data):
                j = _decode_jwt(m.group(1))
                if j and str(j.get("sub", "")).isdigit() and len(str(j.get("sub"))) >= 15:
                    jwt_userid = str(j.get("sub"))
    except Exception as e:
        logging.warning(f"extract_account: {e}")

    def top(field):
        d = found.get(field, {})
        return max(d, key=d.get) if d else ""

    userid = top("userId") or jwt_userid or ""
    # userId peut aussi apparaître dans autelId si compte = email ; on prend le JWT sub sinon
    if not userid:
        for f in found:
            for v in found[f]:
                if v.isdigit() and len(v) >= 15:
                    userid = v
                    break

    rows = []
    def emit(label, value, note=""):
        if value:
            rows.append([label, value, note])

    emit("Compte Autel (autelId)", top("autelId (User{})") or top("autelId"))
    emit("E-mail du compte", top("email") or top("email (brut)"))
    emit("Pseudo (nickname)", top("nickname"))
    emit("Username interne Autel", top("username"))
    emit("userId numérique", userid, "identifiant horodaté (ns epoch)")
    if userid:
        emit("Création du compte (déduite)", userid_to_creation(userid),
             "userId / 1e9 = secondes depuis epoch Unix")
    emit("Pays", top("country"))
    emit("Indicatif", top("cc"))
    emit("Rôle", top("role"))
    emit("Téléphone", "AUCUN (champ phoneNumber vide)" if phone_empty else (top("phone") or ""),
         "constat" if phone_empty else "")
    emit("SN tablette", top("sn"))
    emit("Enregistrement appareil (revendeur)", top("regTime") or top("fitStartDate"),
         "propriété APPAREIL, pas du compte")
    emit("Revendeur (sealerAutelID)", top("sealer"), "distinct du compte")

    f, w = open_csv(export_dir, 'account_identity.csv',
                    ['element', 'valeur', 'note'])
    try:
        for r in rows:
            w.writerow(r)
    finally:
        f.close()
    return rows
