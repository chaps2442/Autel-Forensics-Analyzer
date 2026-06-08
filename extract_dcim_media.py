# extract_dcim_media.py (version VFS)
# Auteur : Vincent Chapeau — Teel Technologies Canada (vincent.chapeau@teeltechcanada.com)
import os
import logging
from core_scanner import iter_entries

def extract_dcim_media(src_dir, export_dir, **kwargs):
    media_found = []
    MEDIA_EXT = ('.jpg','.jpeg','.png','.mp4','.mov')
    
    for entry in iter_entries(src_dir):
        if '/dcim/' in entry.rel_path.lower() and entry.rel_path.lower().endswith(MEDIA_EXT):
            try:
                relative_path = entry.rel_path.lstrip('/')
                dst_path = os.path.join(export_dir, relative_path)
                os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                
                with entry.open_binary() as f_in, open(dst_path, 'wb') as f_out:
                    f_out.write(f_in.read())
                
                media_found.append(relative_path)
            except Exception as e:
                logging.warning(f"Copie DCIM échouée pour {entry.rel_path}: {e}")
                
    return media_found
