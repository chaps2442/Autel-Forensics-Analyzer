# extract_dcim_media.py
import os, shutil

def extract_dcim_media(src_dir, export_dir, skip_md5=None, progress_callback=None, **kwargs):
    dcim_dir = os.path.join(src_dir, 'DCIM')
    media_found = []
    if not os.path.isdir(dcim_dir):
        if progress_callback: progress_callback(1, 1)
        return media_found
    
    all_media = [os.path.join(root, fname) for root, _, fnames in os.walk(dcim_dir) for fname in fnames if fname.lower().endswith(('.jpg', '.png', '.mp4', '.mov'))]
    total_media = len(all_media)
    if progress_callback: progress_callback(0, total_media)

    for i, full_path in enumerate(all_media, 1):
        if progress_callback: progress_callback(i, total_media)
        rel_path = os.path.relpath(full_path, src_dir)
        dst_path = os.path.join(export_dir, rel_path)
        os.makedirs(os.path.dirname(dst_path), exist_ok=True)
        shutil.copy2(full_path, dst_path)
        media_found.append(rel_path)
        
    return media_found