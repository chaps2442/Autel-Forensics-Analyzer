# extract_passwords.py
import os, csv, re

def extract_passwords(src_dir, export_dir, skip_md5=None, progress_callback=None, **kwargs):
    out = os.path.join(export_dir, 'pwd_sn_found.csv')
    passwords_found, seen = [], set()
    files_to_scan = [os.path.join(root, fname) for root, _, fnames in os.walk(src_dir) for fname in fnames if fname.lower().endswith(('.log','.txt'))]
    total_files = len(files_to_scan)
    if progress_callback: progress_callback(0, total_files)
    
    with open(out, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f)
        writer.writerow(['serial','pwd','path'])
        sn_re = re.compile(r'sn[:=]\s*(\S+)')
        pwd_re = re.compile(r'pwd[:=]\s*(\S+)')
        for i, full_path in enumerate(files_to_scan, 1):
            if progress_callback: progress_callback(i, total_files)
            rel_path = os.path.relpath(full_path, src_dir)
            try:
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as rf:
                    text = rf.read()
                    sns, pwds = sn_re.findall(text), pwd_re.findall(text)
                    for sn, pwd in zip(sns, pwds):
                        if (sn, pwd) not in seen:
                            seen.add((sn, pwd)); row = [sn, pwd, rel_path]; passwords_found.append(row); writer.writerow(row)
            except Exception: continue
    return passwords_found