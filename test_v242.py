# test_v242.py — AFAP — sessions DataLogging du firmware récent (KM100 2024-2025)
# Auteur : Vincent Chapeau — Teel Technologies Canada
#
# Le *_main.log des sessions récentes donne functionName, diagPath, vin,
# system, dtcCount, VCIName / vciName, vciSn (au lieu de FuncName / MenuPath).
# Les zips peuvent aussi être rangés dans DataLogging/DATA_<id>/ (pas une marque).
# Données fictives.  Usage : python test_v242.py

import csv
import os
import shutil
import sys
import tempfile
import zipfile

NEW = ('{"carName":"VW","carVersion":"V1.0","functionName":"Read codes",'
       '"diagPath":"VW/Auto scan","system":"Engine","dtcCount":"3",'
       '"vin":"WVWZZZ1KZAW000001","VCIName":"MaxiVCI V200","vciSn":"VCI0000001"}')
OLD = '{"carName":"Hyundai","FuncName":"Smart key","Model":"i30","Year":"2019","MenuPath":"Europe/Smart key"}'


def zipped(path, inner, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with zipfile.ZipFile(path, 'w') as z:
        z.writestr(inner, text)


def main():
    from extract_operations import extract_operations
    src, out = tempfile.mkdtemp(), tempfile.mkdtemp()
    ok = True
    try:
        dl = os.path.join(src, 'media', '0', 'MaxiApScan', 'DataLogging')
        zipped(os.path.join(dl, 'VW', 'NormalSys_20250117141921_1.zip'), 'NormalSys_20250117141921_1_main.log', NEW)
        zipped(os.path.join(dl, 'DATA_123456789012345', 'NormalSys_20240805042050_2.zip'), 'NormalSys_20240805042050_2_main.log', OLD)
        os.makedirs(os.path.join(dl, 'data'))
        open(os.path.join(dl, 'data', 'NormalSys_20250117141921_1_main.log'), 'w').write(NEW)
        # même horodatage : la session Toyota (fonction nommée) gagne, le VIN
        # de la copie KeytoolDiag est gardé
        zipped(os.path.join(dl, 'Toyota', 'NormalSys_20240922174111_3.zip'), 'NormalSys_20240922174111_3_main.log',
               '{"carName":"Toyota","FuncName":"Smart key","Model":"Yaris","Year":"2020"}')
        zipped(os.path.join(dl, 'KeytoolDiag', 'NormalSys_20240922174111_3.zip'), 'NormalSys_20240922174111_3_main.log',
               'D 123DIAGLOG DIAGLOG: KeyWriteStart vin=JTDKB20U900000001 ok\n{"vin":"","functionName":""}')
        extract_operations(src, out)
        with open(os.path.join(out, 'vehicle_operations.csv'), encoding='utf-8-sig') as f:
            rows = list(csv.DictReader(f))
        by = {r['datetime_tablette']: r for r in rows}
        a, b = by.get('2025-01-17 14:19:21', {}), by.get('2024-08-05 04:20:50', {})
        checks = [
            ("3 sessions (miroir data/ fusionné)", len(rows) == 3),
            ("vin= dans une ligne de journal, gardé à la fusion", by.get('2024-09-22 17:41:11', {}).get('vin') == 'JTDKB20U900000001' and by.get('2024-09-22 17:41:11', {}).get('marque') == 'Toyota'),
            ("functionName", a.get('fonction') == 'Read codes'),
            ("vin", a.get('vin') == 'WVWZZZ1KZAW000001'),
            ("système et DTC", a.get('systeme') == 'Engine' and a.get('nb_dtc') == '3'),
            ("VCI et numéro", a.get('vci') == 'MaxiVCI V200' and a.get('vci_sn') == 'VCI0000001'),
            ("marque depuis le dossier", a.get('marque') == 'VW'),
            ("DATA_ n'est pas une marque", b.get('marque') == 'Hyundai'),
            ("ancien agencement (FuncName)", b.get('fonction') == 'Smart key' and b.get('modele') == 'i30'),
        ]
        for name, res in checks:
            print(f"  [{'PASS' if res else 'FAIL'}] {name}")
            ok &= res
    finally:
        shutil.rmtree(src, ignore_errors=True)
        shutil.rmtree(out, ignore_errors=True)
    print(f"RESULTAT : {'tout PASS' if ok else 'ECHEC'}")
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
