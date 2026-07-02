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

# Cache MD5 partagé entre modules : un fichier n'est haché qu'UNE fois par run,
# ce qui évite de re-traiter/re-hacher les fichiers du skiplist à chaque module.
_MD5_CACHE = {}

def file_md5(path):
    """Calcule (et met en cache) le hash MD5 d'un fichier."""
    aware_path = _long_path_aware(path)
    if aware_path in _MD5_CACHE:
        return _MD5_CACHE[aware_path]
    if not os.path.isfile(aware_path):
        _MD5_CACHE[aware_path] = None
        return None
    h = hashlib.md5()
    try:
        with open(aware_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        val = h.hexdigest().lower()
    except (IOError, OSError):
        val = None
    _MD5_CACHE[aware_path] = val
    return val

def should_skip(path, skip_md5_set):
    """Vérifie si un fichier doit être ignoré sur base de son MD5 (skiplist)."""
    if not skip_md5_set: return False
    hash_val = file_md5(path)
    return bool(hash_val and hash_val in skip_md5_set)

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

# Cache du LISTING d'un dossier (chemin, rel, mtime) : l'arborescence n'est
# parcourue (os.walk + stat) qu'UNE fois par run, quel que soit le nombre de
# modules. Transparent : iter_entries filtre ensuite par extension en mémoire.
# (Uniquement pour les sources DOSSIER ; les archives gardent le comportement
# d'origine pour ne pas conserver de handles ouverts.)
_DIR_LISTING_CACHE = {}

def _dir_listing(src):
    key = os.path.abspath(src)
    cached = _DIR_LISTING_CACHE.get(key)
    if cached is not None:
        return cached
    listing = []
    for full_path in iter_files(src):  # sans filtre : on liste tout une fois
        rel = relpath_safe(full_path, src)
        try:
            mtime = os.path.getmtime(_long_path_aware(full_path))
        except Exception:
            mtime = None
        listing.append((full_path, rel, mtime))
    _DIR_LISTING_CACHE[key] = listing
    return listing

def iter_entries(src: str, include_ext=None, exclude_ext=None) -> Iterator[Entry]:
    """Itérateur unifié qui lit les fichiers d'un dossier OU d'une archive."""
    include = {e.lower() for e in include_ext} if include_ext else None
    exclude = {e.lower() for e in exclude_ext} if exclude_ext else None

    if os.path.isdir(src):
        for full_path, rel, mtime in _dir_listing(src):
            ext = os.path.splitext(full_path)[1].lower()
            if include and ext not in include: continue
            if exclude and ext in exclude: continue
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

# Cache TEXTE plafonné : chaque fichier .log/.txt n'est lu qu'une fois ;
# les modules suivants (account/wifi/bt/master) réutilisent le contenu.
# Plafond mémoire pour rester sûr sur de grosses extractions (au-delà, on
# relit sans mettre en cache).
_TEXT_CACHE = {}
_TEXT_CACHE_BYTES = [0]
_TEXT_CACHE_CAP = 800 * 1024 * 1024  # 800 Mo

def read_text_cached(entry):
    """Retourne le texte intégral d'un Entry, mis en cache (dans la limite)."""
    key = entry.path if entry.is_os else ('vfs:' + entry.rel_path)
    if key in _TEXT_CACHE:
        return _TEXT_CACHE[key]
    try:
        with entry.open_text() as f:
            txt = f.read()
    except Exception as e:
        logging.debug(f"read_text_cached {entry.rel_path}: {e}")
        txt = ""
    if _TEXT_CACHE_BYTES[0] + len(txt) <= _TEXT_CACHE_CAP:
        _TEXT_CACHE[key] = txt
        _TEXT_CACHE_BYTES[0] += len(txt)
    return txt

def run_text_consumers(src, consumers, include_ext=('.log', '.txt'), skip_md5=None):
    """PASSE UNIQUE : parcourt l'arborescence texte UNE seule fois, lit chaque
    fichier UNE fois (via le cache) et le fournit à tous les consommateurs.

    Un consommateur est un objet avec :
      - .feed(entry, text)  : accumule ses résultats pour ce fichier ;
      - .finalize(export_dir) : écrit son CSV et renvoie ses lignes (appelé
        par l'appelant, PAS ici).

    Garantit une seule lecture disque par fichier, même au-delà du plafond du
    cache texte. Les fichiers du skiplist (MD5) sont écartés avant les feed().
    Renvoie la liste des consommateurs (pour enchaîner les finalize())."""
    for entry in iter_entries(src, include_ext=include_ext):
        if entry.is_os and should_skip(entry.path, skip_md5):
            continue
        text = read_text_cached(entry)
        for c in consumers:
            try:
                c.feed(entry, text)
            except Exception as e:
                logging.debug(f"consumer {getattr(c, 'name', c)} feed {entry.rel_path}: {e}")
    return consumers


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
