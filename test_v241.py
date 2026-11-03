# test_v241.py — AFAP — compte sur les tablettes MaxiAP / Rockchip sm2031
# Auteur : Vincent Chapeau — Teel Technologies Canada
#
# Sur cette plateforme (Android 9), le compte n'apparaît pas dans les journaux
# User{autelId=...} : il est dans les préférences partagées de com.autel.push
# (webPay.xml : AutelId, registerTime, licence_dead_line) et le userId (10
# chiffres, entre guillemets, non horodaté) dans le JSON des requêtes de
# com.autel.base.userCenter (smart_update_log.txt). Données fictives.
#
# Usage :  python test_v241.py   (code retour 0 si tout passe)

import csv
import os
import shutil
import sys
import tempfile

LOG = ('2024-05-19 06:39:55 request {"appId":"1","deviceModel":"MaxiAP200",'
       '"terminalCode":"x","version":"1.0.12","userId":"1234567890",'
       '"deviceId":"0123abc456def7890abc12de","deviceSn":"AH1DEMO00001"}\n')
PREF = ('<?xml version=\'1.0\' encoding=\'utf-8\' standalone=\'yes\' ?>\n<map>\n'
        '    <string name="AutelId">demo.user@example.org</string>\n'
        '    <string name="registerTime">2023-01-02 03:04:05</string>\n'
        '    <string name="licence_dead_line">2025-01-02</string>\n'
        '    <string name="AreaCfgCode">EU_DEMO</string>\n</map>\n')


def rows(path):
    with open(path, encoding='utf-8-sig') as f:
        return {r[0]: r[1] for r in csv.reader(f) if len(r) > 1}


def main():
    from extract_account import extract_account
    from extract_user_and_endpoints import extract_user_and_endpoints
    from scan_text import scan_text_single_pass
    src = tempfile.mkdtemp()
    outs = [tempfile.mkdtemp() for _ in range(3)]
    ok = True
    try:
        d = os.path.join(src, 'media', '0', 'Android', 'data', 'com.autel.base.userCenter',
                         'files', 'smart_update', 'log')
        os.makedirs(d)
        open(os.path.join(d, 'smart_update_log.txt'), 'w').write(LOG * 3)
        p = os.path.join(src, 'data', 'com.autel.push', 'shared_prefs')
        os.makedirs(p)
        open(os.path.join(p, 'webPay.xml'), 'w').write(PREF)
        # assez de fichiers pour la passe parallèle de scan_text (12 et plus)
        for i in range(14):
            open(os.path.join(src, f'bruit_{i}.log'), 'w').write('rien\n')

        extract_account(src, outs[0])
        scan_text_single_pass(src, outs[1])
        extract_user_and_endpoints(src, outs[2])
        a = rows(os.path.join(outs[0], 'account_identity.csv'))
        b = rows(os.path.join(outs[1], 'account_identity.csv'))
        with open(os.path.join(outs[2], 'userId_found.csv'), encoding='utf-8-sig') as f:
            uids = [r[1] for r in list(csv.reader(f))[1:]]
        checks = [
            ("compte (AutelId des préférences)", a.get("Compte Autel (autelId)") == "demo.user@example.org"),
            ("userId entre guillemets", a.get("userId numérique") == "1234567890"),
            ("deviceSn", a.get("SN tablette") == "AH1DEMO00001"),
            ("deviceId", a.get("Identifiant d'appareil (deviceId)") == "0123abc456def7890abc12de"),
            ("fin de licence", a.get("Fin de licence") == "2025-01-02"),
            ("enregistrement", a.get("Enregistrement appareil (revendeur)") == "2023-01-02 03:04:05"),
            ("passe unique == module", a == b),
            ("userId_found (guillemets)", uids == ["1234567890"] * 3),
        ]
        for name, res in checks:
            print(f"  [{'PASS' if res else 'FAIL'}] {name}")
            ok &= res
    finally:
        for x in [src] + outs:
            shutil.rmtree(x, ignore_errors=True)
    print(f"RESULTAT : {'tout PASS' if ok else 'ECHEC'}")
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
