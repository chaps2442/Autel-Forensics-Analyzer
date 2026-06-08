# core_scanner.py
# Auteur : Vincent Chapeau — Teel Technologies Canada (vincent.chapeau@teeltechcanada.com)
import os
import hashlib
import csv
import logging
import sys
import io
import datetime
from dataclasses import dataclass
from typing import Iterator, Optional
from fs_provider import open_source

def _long_path_aware(path: str) -> str:
    """Préfixe le chemin pour gérer les chemins longs sur Windows."""
    if sys.platform == 'win32':
        abs_path = os.path.abspath(path)
        return f"\\\\?\\{abs_path}"
    return path

def relpath_safe(path, start=os.curdir):
    """Version sécurisée de os.path.relpath."""
    try:
        return os.path.relpath(path, start)
    except ValueError:
        return os.path.abspath(path)

def iter_files(src_dir, include_ext=None, exclude_ext=None):
    """Générateur qui parcourt tous les fichiers d'un répertoire (compatible chemins longs)."""
    include = {ext.lower() for ext in include_ext} if include_ext else None
    exclude = {ext.lower() for ext in exclude_ext} if exclude_ext else None
    
    walk_root = _long_path_aware(src_dir)
    for root, _, fnames in os.walk(walk_root):
        for fname in fnames:
            ext = os.path.splitext(fname)[1].lower()
            if include and ext not in include: continue
            if exclude and ext in exclude: continue
            
            full_path = os.path.join(root, fname)
            if full_path.startswith('\\\\?\\'):
                full_path = full_path[4:]

            yield full_path

def file_md5(path):
    """Calcule le hash MD5 d'un fichier."""
    aware_path = _long_path_aware(path)
    if not os.path.isfile(aware_path): return None
    h = hashlib.md5()
    try:
        with open(aware_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return h.hexdigest().lower()
    except (IOError, OSError): return None

def should_skip(path, skip_md5_set):
    """Vérifie si un fichier doit être ignoré sur base de son MD5."""
    if not skip_md5_set: return False
    hash_val = file_md5(path)
    return hash_val and hash_val in skip_md5_set

def open_csv(export_dir, filename, header):
    """Ouvre un fichier CSV pour l'écriture."""
    path = os.path.join(export_dir, filename)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    f = open(path, 'w', newline='', encoding='utf-8-sig')
    writer = csv.writer(f)
    writer.writerow(header)
    return f, writer

# --- ARCHITECTURE VFS ---
@dataclass
class Entry:
    """Classe unifiée pour représenter un fichier, qu'il soit sur le disque ou dans une archive."""
    rel_path: str
    mtime: Optional[float]
    is_os: bool
    path: Optional[str] = None
    v_open_bin: Optional[callable] = None

    def open_binary(self):
        if self.is_os:
            return open(_long_path_aware(self.path), 'rb')
        return self.v_open_bin()
        
    def open_text(self, encoding='utf-8', errors='ignore'):
        if self.is_os:
            return open(_long_path_aware(self.path), 'r', encoding=encoding, errors=errors)
        return io.TextIOWrapper(self.v_open_bin(), encoding=encoding, errors=errors)

def iter_entries(src: str, include_ext=None, exclude_ext=None) -> Iterator[Entry]:
    """Itérateur unifié qui lit les fichiers d'un dossier OU d'une archive."""
    include = {e.lower() for e in include_ext} if include_ext else None
    exclude = {e.lower() for e in exclude_ext} if exclude_ext else None

    if os.path.isdir(src):
        for full_path in iter_files(src, include_ext=include_ext, exclude_ext=exclude_ext):
            rel = relpath_safe(full_path, src)
            try:
                mtime = os.path.getmtime(_long_path_aware(full_path))
            except Exception: mtime = None
            yield Entry(rel_path=rel, mtime=mtime, is_os=True, path=full_path)
    else:
        # --- LA CORRECTION EST ICI ---
        # On retire le try/except pour laisser l'erreur remonter à main.py
        with open_source(src) as vfs:
            for vf in vfs.iter_files():
                ext = os.path.splitext(vf.vfs_path)[1].lower()
                if include and ext not in include: continue
                if exclude and ext in exclude: continue
                yield Entry(rel_path=vf.vfs_path, mtime=vf.mtime, is_os=False, v_open_bin=vf.open_binary)

def iter_text_lines_entry(entry: Entry):
    """Lit les lignes de texte d'un objet Entry."""
    try:
        with entry.open_text() as f:
            for line in f:
                yield line
    except Exception as e:
        logging.warning(f"Impossible de lire en mode texte {entry.rel_path}: {e}")

def iter_binary_chunks_entry(entry: Entry, chunk_size=1048576, overlap=128):
    """Lit les blocs binaires d'un objet Entry."""
    try:
        with entry.open_binary() as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk: break
                yield chunk
                if len(chunk) == chunk_size:
                    f.seek(f.tell() - overlap)
    except Exception as e:
        logging.warning(f"Impossible de lire en mode binaire {entry.rel_path}: {e}")
