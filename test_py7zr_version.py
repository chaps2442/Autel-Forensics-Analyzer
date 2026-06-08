import sys
import os
import py7zr

print(f"TEST_DEBUG: Python executable: {sys.executable}")
print(f"TEST_DEBUG: sys.path: {sys.path}")
print(f"TEST_DEBUG: py7zr version from test script: {py7zr.__version__}")
print(f"TEST_DEBUG: py7zr file location: {py7zr.__file__}")