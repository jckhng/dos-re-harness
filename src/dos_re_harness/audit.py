"""Conservative checks for files that should not enter a public harness tree."""

from __future__ import annotations

import re
from pathlib import Path


IGNORED_DIRECTORIES = {".git", ".work", "__pycache__", "build", "dist"}
FORBIDDEN_DIRECTORIES = {"captures", "original"}
FORBIDDEN_SUFFIXES = {
    ".7z",
    ".bin",
    ".com",
    ".exe",
    ".flac",
    ".gif",
    ".gpr",
    ".gzf",
    ".jpg",
    ".jpeg",
    ".mp3",
    ".ntr",
    ".ogg",
    ".pgm",
    ".png",
    ".sav",
    ".state",
    ".wav",
    ".zip",
}
FORBIDDEN_MAGIC = {
    b"MZ": "DOS/Windows executable",
    b"\x7fELF": "ELF executable",
    b"PK\x03\x04": "ZIP archive",
    b"\x89PNG\r\n\x1a\n": "PNG image",
}
_BACKSLASH = rb"\\"
_WINDOWS_HOME = (
    rb"[A-Za-z]:"
    + _BACKSLASH
    + b"Users"
    + _BACKSLASH
    + rb"[^\\\r\n]+"
)
_POSIX_HOME = b"/" + b"home" + rb"/[^/\s]+/"
PERSONAL_PATH = re.compile(
    b"(?:" + _WINDOWS_HOME + b"|" + _POSIX_HOME + b")",
    re.IGNORECASE,
)


def audit_public_tree(root: Path, max_file_size: int = 1_000_000) -> list[str]:
    resolved = root.resolve()
    errors: list[str] = []
    for path in sorted(resolved.rglob("*")):
        relative = path.relative_to(resolved)
        if any(part in IGNORED_DIRECTORIES for part in relative.parts):
            continue
        if path.is_symlink():
            errors.append(f"{relative}: symbolic links require manual review")
            continue
        if path.is_dir():
            if path.name.lower() in FORBIDDEN_DIRECTORIES:
                errors.append(f"{relative}: forbidden publication directory")
            continue
        if not path.is_file():
            continue
        if path.suffix.lower() in FORBIDDEN_SUFFIXES:
            errors.append(f"{relative}: forbidden publication file type")
        size = path.stat().st_size
        if size > max_file_size:
            errors.append(
                f"{relative}: {size} bytes exceeds public-tree size limit "
                f"{max_file_size}"
            )
        with path.open("rb") as handle:
            prefix = handle.read(8192)
        for magic, description in FORBIDDEN_MAGIC.items():
            if prefix.startswith(magic):
                errors.append(f"{relative}: detected {description}")
                break
        if PERSONAL_PATH.search(prefix):
            errors.append(f"{relative}: contains an absolute user-home path")
    return errors
