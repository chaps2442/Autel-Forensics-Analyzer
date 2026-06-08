# utils.py — AFAP v2.0.0
# Auteur : Vincent Chapeau — Teel Technologies Canada (vincent.chapeau@teeltechcanada.com)
import logging, csv, os, re, json
from core_scanner import iter_entries, iter_text_lines_entry

def setup_logging(export_dir):
    log_file = os.path.join(export_dir, 'run_analysis.log')
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.FileHandler(log_file, encoding='utf-8'), logging.StreamHandler()]
    )

def _read_first_lines(entry, max_lines=40):
    out = []
    try:
        with entry.open_text() as f:
            for i, line in enumerate(f):
                if i >= max_lines: break
                out.append(line)
    except Exception: pass
    return out

def get_tablet_info(src_path: str) -> dict:
    info = {"serial":"inconnu","product_model":"inconnu","os_version":"","app_version":"",
            "vci_name":"","vci_firmware":"","vci_software":"","langue":"",
            "zone_vehicule":"","derniere_ip_observee":""}
    serial_re = re.compile(r'ro\.serialno=([A-Z0-9]+)')
    model_re  = re.compile(r'ro\.product\.model=(.+)')
    try:
        for entry in iter_entries(src_path):
            rel = entry.rel_path.replace('\\', '/')
            if rel.endswith('build.prop') or '/build.prop' in rel:
                for line in iter_text_lines_entry(entry):
                    if m := serial_re.search(line): info['serial'] = m.group(1).strip()
                    if m := model_re.search(line): info['product_model'] = m.group(1).strip()
                if info['serial'] != 'inconnu': continue
            if '/Scan/CloudEData/' in '/' + rel and rel.lower().endswith('.json'):
                try:
                    with entry.open_text() as f: data = json.load(f)
                    if info['serial']=='inconnu':
                        info['serial'] = data.get('ProductSN') or data.get('productSN') or info['serial']
                    if info['product_model']=='inconnu':
                        info['product_model'] = (data.get('strProductType ') or data.get('strProductType') or info['product_model']).strip()
                    info['os_version']   = info['os_version']   or data.get('OSVersion','')      or (data.get('osVersion ')      or '').strip()
                    info['app_version']  = info['app_version']  or data.get('AppVersion','')     or (data.get('appVersion ')     or '').strip()
                    info['vci_name']     = info['vci_name']     or data.get('VCIName','')        or (data.get('vciName ')        or '').strip()
                    info['vci_firmware'] = info['vci_firmware'] or data.get('VCIFirmVersion','') or (data.get('vciFirmVersion ') or '').strip()
                    info['vci_software'] = info['vci_software'] or data.get('VCISoftVersion','') or (data.get('vciSoftVersion ') or '').strip()
                    info['langue']        = info['langue']        or data.get('strLanguage','')
                    info['zone_vehicule'] = info['zone_vehicule'] or data.get('VehicleArea','')
                    info['derniere_ip_observee'] = info['derniere_ip_observee'] or data.get('ip','')
                except Exception as e:
                    logging.debug(f"CloudEData {rel}: {e}")
            if '/.VciLog/' in '/'+rel and rel.lower().endswith('.log') and info['serial']=='inconnu':
                for line in _read_first_lines(entry, 15):
                    if m := re.match(r'\s*Sn:\s*(\S+)', line): info['serial']=m.group(1).strip()
                    if m := re.match(r'\s*SubProduct:\s*(\S+)', line):
                        if info['product_model']=='inconnu': info['product_model']=m.group(1).strip()
                    if m := re.match(r'\s*Os version:\s*(\S+)', line):
                        info['os_version'] = info['os_version'] or m.group(1).strip()
                    if m := re.match(r'\s*Vci Name:\s*([^,]+)', line):
                        info['vci_name'] = info['vci_name'] or m.group(1).strip()
                    if m := re.search(r'Fw Version:\s*(\S+)', line):
                        info['vci_firmware'] = info['vci_firmware'] or m.group(1).strip()
    except Exception as e:
        logging.warning(f"Erreur get_tablet_info : {e}")
    return info

def export_tablet_info_csv(export_dir, tablet_info: dict):
    path = os.path.join(export_dir, 'tablet_info.csv')
    with open(path, 'w', newline='', encoding='utf-8-sig') as f:
        w = csv.writer(f)
        w.writerow(['Information','Valeur'])
        for k, v in tablet_info.items():
            w.writerow([k.replace('_',' ').capitalize(), v])
