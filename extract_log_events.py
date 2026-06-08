# extract_log_events.py
# Auteur : Vincent Chapeau — Teel Technologies Canada (vincent.chapeau@teeltechcanada.com)
import re, csv, logging, datetime
from core_scanner import iter_entries, iter_text_lines_entry, should_skip, open_csv

PATTERNS = {
    # --- Patterns Autel App & Diag ---
    "DEVICE_CREDENTIALS": re.compile(r'sn: (\w+)\s+pwd:(\w+)'),
    "DEVICE_INFO": re.compile(r'device_serialno: (\w+).*?device_password: (\w+)'),
    "BLUETOOTH_PASSKEY": re.compile(r'passkey:(\d+)'),
    "VEHICLE_DIAG_ACTION": re.compile(r'UserActInfoUploadManager:.*?jsonStr = (\{.*?\})'),
    "VEHICLE_SET": re.compile(r'SetVehicleMake:\s*(.*?)$'),
    "VIN_HISTORY": re.compile(r'SetScanInput.*("vtHis":\[.*?\])'),

    # --- Patterns génériques Android (Logcat) ---
    "SYSTEM_BOOT": re.compile(r'Entered the Android system server!'),
    "SYSTEM_SLEEP": re.compile(r'PowerManagerService: Going to sleep \(uid (\d+)\)'),
    "USER_UNLOCK": re.compile(r'ActivityManager: User (\d+) state changed from RUNNING_LOCKED to RUNNING_UNLOCKED'),
    "WIFI_CONNECTION": re.compile(r'Switching to new default network:.*?SSID: \"([^\"]+)\"'),
    "WIFI_SCANNED_SSID": re.compile(r'Skip scan ssid for single scan:\s*(.*)'),
    "APP_START": re.compile(r'ActivityManager: START u0 \{.*?cmp=([^ /\}]+).*?\}'),
    "BLUETOOTH_ADAPTER_INFO": re.compile(r'BluetoothManagerService: Stored Bluetoothaddress: (.*)'),
    "BLUETOOTH_STORED_DEVICE": re.compile(r'Stored bluetooth Name=(.*?),Address=(.*?)'),
    "BLUETOOTH_FOUND_DEVICE": re.compile(r'search_result_file_init: addr:(\[.*?\]) name:(\[.*?\])'),
    "GENERIC_EXCEPTION": re.compile(r'(Exception:.*)')
}

def extract_all_log_events(src_dir, export_dir, skip_md5=None, **kwargs):
    header = ['source_path','line_number','event_type','detail_1','detail_2','detail_3','detail_4','detail_5', 'date_modification']
    f_csv, writer = open_csv(export_dir, 'log_events_found.csv', header)
    rows = []
    
    try:
        for entry in iter_entries(src_dir, include_ext=('.log','.txt')):
            if entry.is_os and should_skip(entry.path, skip_md5): continue
            
            try:
                mtime = datetime.datetime.fromtimestamp(entry.mtime).strftime('%Y-%m-%d %H:%M:%S') if entry.mtime else "Date Inconnue"
            except Exception:
                mtime = "Date Inconnue"

            try:
                for lineno, line in enumerate(iter_text_lines_entry(entry), 1):
                    for etype, pat in PATTERNS.items():
                        for m in pat.finditer(line):
                            details = [d.strip() for d in m.groups()]
                            details = (details + [''] * 5)[:5]
                            row = [entry.rel_path, lineno, etype] + details + [mtime]
                            writer.writerow(row)
                            rows.append(row)
            except Exception as e:
                logging.warning(f"Erreur lecture {entry.rel_path}: {e}")
    finally:
        if f_csv:
            f_csv.close()
    return rows
