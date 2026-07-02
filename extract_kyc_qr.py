# extract_kyc_qr.py — AFAP
# Auteur : Vincent Chapeau — Teel Technologies Canada (vincent.chapeau@teeltechcanada.com)
#
# Décodage des QR codes présents dans les images (DCIM / Pictures).
# Cible en priorité les pages de vérification d'identité (KYC) Autel
# (URL *complete-info*), et décode le JWT embarqué (autelId, nickname, SN...).
#
# Dépendances optionnelles : opencv-python(-headless) + zxing-cpp.
# Si absentes, le module se désactive proprement (retourne []).
#
# Produit : kyc_qr.csv

import os
import re
import csv
import json
import base64
import logging
import tempfile
import datetime
from core_scanner import iter_entries, open_csv

IMG_EXT = ('.jpg', '.jpeg', '.png')
JWT_RE = re.compile(r'eyJ[A-Za-z0-9_\-]+\.(eyJ[A-Za-z0-9_\-]+)\.')


def _decode_jwt(b64):
    b64 += "=" * (-len(b64) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(b64))
    except Exception:
        return None


def _try_import():
    try:
        import cv2
        import zxingcpp
        return cv2, zxingcpp
    except Exception:
        return None, None


def _decode_image(path, cv2, zxingcpp):
    """Décodage QR économe : essaie du moins cher au plus cher, sort dès un hit.
    zxing-cpp gère l'orientation en interne -> pas de rotations manuelles."""
    img = cv2.imread(path)
    if img is None:
        return None
    H, W = img.shape[:2]
    full = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    crop = full[int(H * 0.15):int(H * 0.92), int(W * 0.15):int(W * 0.78)]

    def _try(gray):
        try:
            res = zxingcpp.read_barcodes(gray)
            return res[0].text if res else None
        except Exception:
            return None

    # 1) passe rapide : image + recadrage à l'échelle native
    for g in (full, crop):
        t = _try(g)
        if t:
            return t
    # 2) escalade : upscale + Otsu (photos d'écran à moiré), crop d'abord
    for base in (crop, full):
        for scale in (2, 3):
            g = cv2.resize(base, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)
            t = _try(g) or _try(cv2.threshold(g, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1])
            if t:
                return t
    return None


def extract_kyc_qr(src_dir, export_dir, skip_md5=None, **kwargs):
    cv2, zxingcpp = _try_import()
    f, w = open_csv(export_dir, 'kyc_qr.csv',
                    ['image', 'date_fichier', 'type', 'contenu_qr',
                     'autelId', 'nickname', 'serialNo', 'jwt_iat_utc'])
    rows = []
    if cv2 is None:
        logging.warning("extract_kyc_qr désactivé : installez 'opencv-python-headless' et 'zxing-cpp'.")
        f.close()
        return rows

    try:
        for entry in iter_entries(src_dir, include_ext=IMG_EXT):
            rel = entry.rel_path.replace('\\', '/')
            # se limiter aux images utilisateur (photos), pas aux ressources d'app
            if '/Android/' in '/' + rel or '/MaxiApScan/' in '/' + rel or '/MaxiAp200/' in '/' + rel:
                continue
            try:
                mtime = datetime.datetime.fromtimestamp(entry.mtime).strftime('%Y-%m-%d %H:%M:%S') if entry.mtime else ""
            except Exception:
                mtime = ""
            # écrire dans un fichier temporaire (opencv lit un chemin)
            tmp = None
            try:
                if entry.is_os:
                    path = entry.path
                else:
                    tf = tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(rel)[1])
                    with entry.open_binary() as src:
                        tf.write(src.read())
                    tf.close()
                    tmp = path = tf.name
                text = _decode_image(path, cv2, zxingcpp)
            finally:
                if tmp and os.path.exists(tmp):
                    os.unlink(tmp)
            if not text:
                continue
            typ = "QR"
            aid = nick = sn = iat = ""
            if "complete-info" in text or "kyc" in text.lower():
                typ = "KYC Autel (vérification identité)"
            m = JWT_RE.search(text)
            if m:
                j = _decode_jwt(m.group(1))
                if j:
                    aid = j.get("autelId", "")
                    nick = j.get("nickname", "")
                    sn = j.get("serialNo", "")
                    if j.get("iat"):
                        try:
                            iat = datetime.datetime.utcfromtimestamp(int(j["iat"])).strftime("%Y-%m-%d %H:%M:%S") + " UTC"
                        except Exception:
                            pass
            w.writerow([rel, mtime, typ, text[:500], aid, nick, sn, iat])
            rows.append([rel, typ])
    except Exception as e:
        logging.warning(f"extract_kyc_qr: {e}")
    finally:
        f.close()
    return rows
