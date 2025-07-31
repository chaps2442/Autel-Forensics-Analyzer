# extract_user_and_endpoints.py
import os, csv, re

def extract_user_and_endpoints(src_dir, export_dir, skip_md5=None, progress_callback=None, **kwargs):
    out_u = os.path.join(export_dir, 'userId_found.csv')
    out_e = os.path.join(export_dir, 'endpoints_found.csv')
    users_found, endpoints_found = [], []
    files_to_scan = [os.path.join(root, fname) for root, _, fnames in os.walk(src_dir) for fname in fnames if fname.lower().endswith(('.log','.txt'))]
    total_files = len(files_to_scan)
    if progress_callback: progress_callback(0, total_files)

    with open(out_u, 'w', newline='', encoding='utf-8-sig') as fu, open(out_e, 'w', newline='', encoding='utf-8-sig') as fe:
        wu, we = csv.writer(fu), csv.writer(fe)
        wu.writerow(['userId','path']); we.writerow(['endpoint','path'])
        uid_re = re.compile(r'userId[:=]\s*(\d+)')
        url_re = re.compile(r'https?://[^\s\'"]+')
        for i, full_path in enumerate(files_to_scan, 1):
            if progress_callback: progress_callback(i, total_files)
            rel_path = os.path.relpath(full_path, src_dir)
            try:
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as rf:
                    data = rf.read()
                    for m in uid_re.finditer(data):
                        users_found.append(m.group(1)); wu.writerow([m.group(1), rel_path])
                    for m in url_re.finditer(data):
                        endpoints_found.append(m.group(0)); we.writerow([m.group(0), rel_path])
            except Exception: continue
    return users_found + endpoints_found