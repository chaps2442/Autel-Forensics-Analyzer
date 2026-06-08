# Auteur : Vincent Chapeau — Teel Technologies Canada (vincent.chapeau@teeltechcanada.com)

# fs_provider.py
# Abstraction de source de fichiers : dossier OS, archive .7z (streaming), ZIP (streaming).
# Objectif: éviter la décompression complète et exposer un VFS unifié.

import os
import io
import time
import zipfile
from dataclasses import dataclass
from typing import Iterable, Iterator, Optional, Tuple

try:
    import py7zr
    _HAS_PY7ZR = True
except Exception:
    _HAS_PY7ZR = False

@dataclass
class VFile:
    vfs_path: str
    size: int
    mtime: float
    open_binary: callable  # () -> file-like (rb)
    open_text: callable    # (encoding='utf-8', errors='ignore') -> text file-like

class BaseSource:
    def iter_files(self) -> Iterator[VFile]:
        raise NotImplementedError

class OSPathSource(BaseSource):
    def __init__(self, root_dir: str):
        self.root_dir = root_dir

    def iter_files(self) -> Iterator[VFile]:
        base = self.root_dir
        for dp, _, files in os.walk(base):
            for f in files:
                full = os.path.join(dp, f)
                rel = os.path.relpath(full, base)
                try:
                    st = os.stat(full)
                    size = st.st_size
                    mtime = st.st_mtime
                except Exception:
                    size = 0; mtime = 0.0

                def _open_bin(p=full):
                    return open(p, 'rb')

                def _open_txt(p=full, encoding='utf-8', errors='ignore'):
                    return open(p, 'r', encoding=encoding, errors=errors)

                yield VFile(rel, size, mtime, _open_bin, _open_txt)

class ZipSource(BaseSource):
    def __init__(self, zip_path: str):
        self.zip_path = zip_path
        self._zip = zipfile.ZipFile(zip_path, 'r')

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def iter_files(self) -> Iterator[VFile]:
        for zinfo in self._zip.infolist():
            if zinfo.is_dir():
                continue
            rel = zinfo.filename
            size = zinfo.file_size
            # Convert DOS date to epoch
            try:
                mtime = time.mktime((*zinfo.date_time, 0, 0, -1))
            except Exception:
                mtime = 0.0

            def _open_bin(zi=rel):
                return self._zip.open(zi, 'r')

            def _open_txt(zi=rel, encoding='utf-8', errors='ignore'):
                raw = self._zip.open(zi, 'r')
                return io.TextIOWrapper(raw, encoding=encoding, errors=errors)

            yield VFile(rel, size, mtime, _open_bin, _open_txt)

    def close(self):
        try:
            self._zip.close()
        except Exception:
            pass

class SevenZipSource(BaseSource):
    def __init__(self, seven_zip_path: str):
        if not _HAS_PY7ZR:
            raise RuntimeError("py7zr n'est pas installé. Installez-le pour le support .7z.")
        self.path = seven_zip_path
        self._z = py7zr.SevenZipFile(seven_zip_path, mode='r')

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def iter_files(self) -> Iterator[VFile]:
        # py7zr ne permet pas l'accès random; on lit fichier par fichier en streaming.
        # On utilise readall() par lots de noms (permet d'avoir un dict {name: bytes-like}).
        # Pour limiter la mémoire, on itère par chunks de N fichiers.
        # py7zr ne permet pas l'accès random; on lit fichier par fichier en streaming.
        # On utilise readall() par lots de noms (permet d'avoir un dict {name: bytes-like}).
        # Pour limiter la mémoire, on itère par chunks de N fichiers.
        # Correction: py7zr.SevenZipFile.read() ne prend pas de liste de noms.
        # Il faut ouvrir chaque fichier individuellement.
        for m in self._z.list():
            if m.is_directory:
                continue
            name = m.filename
            size = m.uncompressed
            mtime = m.creationtime.timestamp() if m.creationtime else 0.0

            def _open_bin(file_name=name):
                # py7zr.open() returns a file-like object
                return self._z.open(file_name)

            def _open_txt(file_name=name, encoding='utf-8', errors='ignore'):
                raw = self._z.open(file_name)
                return io.TextIOWrapper(raw, encoding=encoding, errors=errors)

            yield VFile(name, size, mtime, _open_bin, _open_txt)

    def close(self):
        try:
            self._z.close()
        except Exception:
            pass

def open_source(path: str) -> BaseSource:
    lower = path.lower()
    if os.path.isdir(path):
        return OSPathSource(path)
    if lower.endswith('.zip'):
        return ZipSource(path)
    if lower.endswith('.7z'):
        return SevenZipSource(path)
    # Default: folder
    return OSPathSource(path)
