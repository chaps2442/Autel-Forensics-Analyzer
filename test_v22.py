# test_v22.py — AFAP — test de fumée des modules v2.2
# Auteur : Vincent Chapeau — Teel Technologies Canada
#
# Crée une mini-extraction synthétique en mémoire (aucune donnée réelle),
# exécute les nouveaux modules et vérifie leurs sorties. Aucune dépendance
# externe requise (le module KYC est testé seulement si opencv+zxing présents).
#
# Usage :  python test_v22.py
# Sortie :  liste de tests PASS/FAIL + code retour 0 si tout passe.

import os
import csv
import tempfile
import shutil
import datetime

# --- données synthétiques (userId réel de démo : 2024-04-11) ---
FAKE_USERID = "1712853044076273666"
APPLOG = r'''
01-28 22:19:00.675   942   942 E szq: user == User{autelId='n.demo@example.be', nickname='Demo User', email='n.demo@example.be', username='autel_DEMO123', domain='gateway-prodeu.autel.com'}
01-28 22:19:00.675   942   942 E UC: {"autelId":"n.demo@example.be","phoneNumber":"","email":"n.demo@example.be","cc":"+32","country":"BELGIUM","roles":"NORMAL_USER"}
01-28 22:19:00.675   942   942 E szq: token='Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxNzEyODUzMDQ0MDc2MjczNjY2In0.sig'
01-28 22:19:00.675   942   942 E UC: contractName='MaxiIM KM100E' regTime='2023-10-13 15:29:35' sealerAutelID='119215' "sn":"AH1DEMO0001"
01-28 23:15:11.100   407   484 I WifiHal: connectToNetwork "iPhone de Demo"
01-28 23:15:12.200   407   484 D DhcpClient: Confirmed lease: IP 172.20.10.2 Gateway 172.20.10.1
01-28 23:15:12.300   407   484 D WifiInfo: SignalStrength: -35 SSID: "iPhone de Demo"
01-28 23:15:13.400   407   484 D wpa: bssid=76:4b:13:06:aa:ad
01-28 22:51:51.000   407   484 I MacHal: MAC address: 10:68:38:5e:c8:11
01-28 23:05:51.000   407   484 I WifiScan: 8C:9A:8F:AD:C3:28 Sagemcom seen
01-29 20:21:33.000   244   244 D A2dpService: Bond state changed for device: 5C:36:16:33:95:1A state: 12
01-29 20:21:33.100   244   244 D AdapterProperties: Adding bonded device:5C:36:16:33:95:1A
'''

RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  — {detail}" if detail and not cond else ""))


def rows_of(path):
    if not os.path.isfile(path):
        return []
    with open(path, encoding='utf-8-sig') as f:
        return list(csv.DictReader(f))


def main():
    src = tempfile.mkdtemp(prefix="afap_src_")
    out = tempfile.mkdtemp(prefix="afap_out_")
    try:
        # arborescence minimale
        logdir = os.path.join(src, "AppLog", "ser_20260128224951")
        os.makedirs(logdir)
        with open(os.path.join(logdir, "2026-01-28 224951-1.log"), "w", encoding="utf-8") as f:
            f.write(APPLOG)

        from clock_offset import ClockOffset
        from extract_account import extract_account
        from extract_mac import extract_mac
        from extract_wifi import extract_wifi
        from extract_bluetooth import extract_bluetooth
        from create_master_timeline import create_master_timeline

        # 1) horloge : +180 s
        clk = ClockOffset.from_args(offset_seconds=180)
        clk.to_json(out)
        check("clock offset calcule", clk.offset_seconds == 180)
        check("clock correction", clk.correct("2026-01-28 22:17:30") == "2026-01-28 22:14:30",
              clk.correct("2026-01-28 22:17:30"))

        # 2) compte
        extract_account(src, out)
        acc = {r['element']: r['valeur'] for r in rows_of(os.path.join(out, 'account_identity.csv'))}
        check("compte e-mail", acc.get("E-mail du compte") == "n.demo@example.be", str(acc.get("E-mail du compte")))
        check("compte userId", acc.get("userId numérique") == FAKE_USERID, str(acc.get("userId numérique")))
        check("compte creation 2024-04-11", (acc.get("Création du compte (déduite)", "").startswith("2024-04-11")),
              str(acc.get("Création du compte (déduite)")))
        check("telephone vide detecte", "AUCUN" in acc.get("Téléphone", ""), str(acc.get("Téléphone")))
        check("revendeur sealer", acc.get("Revendeur (sealerAutelID)") == "119215", str(acc.get("Revendeur (sealerAutelID)")))

        # 3) MAC + WiFi (wifi lit mac_found.csv)
        extract_mac(src, out)
        extract_wifi(src, out)
        wifi = rows_of(os.path.join(out, 'wifi_networks.csv'))
        conn = [r for r in wifi if r['statut'].startswith('CONNECT')]
        check("wifi tethering connecte", any("iPhone" in r['ssid'] for r in conn),
              str([r['ssid'] for r in conn]))
        check("wifi passerelle apple", any(r['passerelle'].startswith('172.20.10') for r in conn),
              str([r['passerelle'] for r in conn]))
        check("wifi heure precise", any(r.get('date', '').startswith('2026-01-28 23:15') for r in conn),
              str([r.get('date') for r in conn]))

        # 4) Bluetooth
        extract_bluetooth(src, out)
        bt = rows_of(os.path.join(out, 'bluetooth_devices.csv'))
        bonded = [r for r in bt if 'APPAIR' in r['statut']]
        check("bt appareil bonded", any(r['mac'] == '5C:36:16:33:95:1A' for r in bonded),
              str([r['mac'] for r in bonded]))
        check("bt mac fixe", any(r['type_mac'].startswith('FIXE') for r in bonded))
        check("bt date de ligne", any(r.get('date', '').startswith('2026-01-29 20:21') for r in bonded),
              str([r.get('date') for r in bonded]))

        # 5) table maitre + date_corrigee
        create_master_timeline(src, out, serial="AH1DEMO0001", scelle="DEMO", clock=clk)
        master = rows_of(os.path.join(out, 'Chronologie_MAITRE.csv'))
        check("table maitre non vide", len(master) > 0, f"{len(master)} lignes")
        check("table maitre 18 colonnes", (len(master[0]) == 18 if master else False))
        has_corr = any(r.get('date_corrigee') for r in master)
        check("date_corrigee remplie", has_corr)
        cats = {r['categorie'] for r in master}
        check("categorie Reseau presente", any('seau' in c for c in cats), str(cats))
        check("categorie Bluetooth presente", 'Bluetooth' in cats, str(cats))

        # 6) PASSE UNIQUE (v2.3.2) : resultat identique aux modules separes
        from scan_text import scan_text_single_pass
        out2 = tempfile.mkdtemp(prefix="afap_out2_")
        try:
            extract_mac(src, out2)              # le volet WiFi lit mac_found.csv
            scan_text_single_pass(src, out2)
            for fn in ('account_identity.csv', 'wifi_networks.csv', 'bluetooth_devices.csv'):
                pa, pb = os.path.join(out, fn), os.path.join(out2, fn)
                a = open(pa, encoding='utf-8-sig').read() if os.path.isfile(pa) else None
                b = open(pb, encoding='utf-8-sig').read() if os.path.isfile(pb) else None
                check(f"passe unique == modules ({fn})",
                      a is not None and a == b,
                      "sortie differente" if a != b else "")
        finally:
            shutil.rmtree(out2, ignore_errors=True)

        # 7) PASSE UNIQUE PARALLELE (v2.3.2) == sequentielle (byte-identique)
        import scan_text as _st
        src2 = tempfile.mkdtemp(prefix="afap_par_")
        oP = tempfile.mkdtemp(prefix="afap_oP_")
        oS = tempfile.mkdtemp(prefix="afap_oS_")
        try:
            dd = os.path.join(src2, "AppLog", "ser")
            os.makedirs(dd)
            for i in range(16):
                with open(os.path.join(dd, f"l{i}.log"), "w", encoding="utf-8") as f:
                    f.write(APPLOG)
            _save = _st._PARALLEL_MIN_FILES
            extract_mac(src2, oS)
            _st._PARALLEL_MIN_FILES = 10**9            # force le sequentiel
            _st.scan_text_single_pass(src2, oS)
            extract_mac(src2, oP)
            _st._PARALLEL_MIN_FILES = 12               # force le parallele
            _st.scan_text_single_pass(src2, oP)
            _st._PARALLEL_MIN_FILES = _save
            for fn in ('account_identity.csv', 'wifi_networks.csv', 'bluetooth_devices.csv'):
                a = open(os.path.join(oS, fn), encoding='utf-8-sig').read()
                b = open(os.path.join(oP, fn), encoding='utf-8-sig').read()
                check(f"parallele == sequentiel ({fn})", a == b, "sortie differente")
        finally:
            for _d in (src2, oP, oS):
                shutil.rmtree(_d, ignore_errors=True)

        # bilan
        n_ok = sum(1 for _, ok, _ in RESULTS if ok)
        n = len(RESULTS)
        print(f"\n{'='*48}\nRESULTAT : {n_ok}/{n} tests PASS")
        return 0 if n_ok == n else 1
    finally:
        shutil.rmtree(src, ignore_errors=True)
        shutil.rmtree(out, ignore_errors=True)


if __name__ == '__main__':
    import sys
    print("AFAP — test de fumée v2.2\n" + "-" * 30)
    sys.exit(main())
