"""Conservative checks for files that should not enter a public harness tree."""

from __future__ import annotations

import os
import re
import json
import subprocess
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

_CONFIG_PATH_KEYS = {"cwd", "path", "root", "project", "java_home", "input_script", "backend_lock"}


def _path_findings(relative: Path, *, selected: bool) -> list[str]:
    errors = []
    if selected and any(part in IGNORED_DIRECTORIES for part in relative.parts):
        errors.append(f"{relative}: private/generated publication path")
    if selected and any(part.lower() in FORBIDDEN_DIRECTORIES for part in relative.parts[:-1]):
        errors.append(f"{relative}: forbidden publication directory")
    name = relative.name.lower()
    if (name in {".env", "host.json", "cmakeuserpresets.json"}
            or (name.startswith(".env.") and name != ".env.example")
            or re.search(r"\.local\.(json|toml|ya?ml)$", name)):
        errors.append(f"{relative}: local configuration must remain private")
    if relative.suffix.lower() in FORBIDDEN_SUFFIXES:
        errors.append(f"{relative}: forbidden publication file type")
    return errors


def _absolute_config_path(value) -> bool:
    return isinstance(value, str) and bool(re.match(r"^(?:[A-Za-z]:[/\\]|/|\\\\)", value))


def _host_config(value, key="") -> bool:
    if isinstance(value, dict):
        return any(_host_config(item, name) for name, item in value.items())
    if isinstance(value, list):
        if key == "command" and value and _absolute_config_path(value[0]):
            return True
        return any(_host_config(item, key) for item in value)
    return key in _CONFIG_PATH_KEYS and _absolute_config_path(value)


def _content_findings(relative: Path, data: bytes, size: int, root: Path, max_file_size: int) -> list[str]:
    errors = []
    if size > max_file_size:
        errors.append(f"{relative}: {size} bytes exceeds public-tree size limit {max_file_size}")
    for magic, description in FORBIDDEN_MAGIC.items():
        if data.startswith(magic):
            errors.append(f"{relative}: detected {description}")
            break
    if PERSONAL_PATH.search(data):
        errors.append(f"{relative}: contains an absolute user-home path")
    # Include JSON escapes and WSL spellings of this checkout, throughout the text.
    text = data.decode("utf-16" if data.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8", errors="replace")
    normalized = re.sub(r"\\+", "/", text).casefold()
    if not PERSONAL_PATH.search(data) and re.search(r"[a-z]:/" + "users/" + r"[^/\s]+|/" + "home/" + r"[^/\s]+/", normalized):
        errors.append(f"{relative}: contains an absolute user-home path")
    workspace = root.as_posix().casefold()
    variants = [workspace]
    if re.match(r"^[a-z]:/", workspace):
        variants.append("/mnt/" + workspace[0] + workspace[2:])
    if any(value in normalized for value in variants):
        errors.append(f"{relative}: contains an absolute workspace path")
    if relative.suffix.lower() == ".json":
        try:
            if _host_config(json.loads(text)):
                errors.append(f"{relative}: contains absolute host configuration paths")
        except ValueError:
            pass
    return errors


def audit_public_tree(root: Path, max_file_size: int = 1_000_000) -> list[str]:
    if max_file_size <= 0:
        raise ValueError("max_file_size must be positive")
    resolved = root.resolve()
    errors: list[str] = []
    paths = []
    for directory, directories, files in os.walk(resolved):
        directories[:] = [name for name in directories if name not in IGNORED_DIRECTORIES]
        paths.extend(Path(directory) / name for name in (*directories, *files)
                     if name not in IGNORED_DIRECTORIES)
    for path in sorted(paths):
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
        errors.extend(_path_findings(relative, selected=False))
        size = path.stat().st_size
        with path.open("rb") as handle:
            data = handle.read(max_file_size if size <= max_file_size else 8192)
        errors.extend(_content_findings(relative, data, size, resolved, max_file_size))
    return errors


def audit_paths(root: Path, paths, max_file_size: int = 1_000_000) -> list[str]:
    """Audit an explicit publication selection without walking neighboring files."""
    root = root.resolve()
    if max_file_size <= 0:
        raise ValueError("max_file_size must be positive")
    errors = []
    for name in sorted(set(paths)):
        relative = Path(name)
        path = root / relative
        if relative.is_absolute() or ".." in relative.parts or (path.resolve() != root and root not in path.resolve().parents):
            raise ValueError("publication paths must remain relative to the root")
        errors.extend(_path_findings(relative, selected=True))
        if any(part.is_symlink() for part in [path, *list(path.parents)[:len(relative.parts) - 1]]):
            errors.append(f"{relative}: symbolic links require manual review")
        elif not path.is_file():
            errors.append(f"{relative}: missing publication file")
        else:
            size = path.stat().st_size
            with path.open("rb") as handle:
                data = handle.read(max_file_size if size <= max_file_size else 8192)
            errors.extend(_content_findings(relative, data, size, root, max_file_size))
    return errors


def audit_staged_tree(root: Path, max_file_size: int = 1_000_000) -> list[str]:
    """Read the Git index and its blobs, including force-added private paths."""
    root = root.resolve()
    if max_file_size <= 0:
        raise ValueError("max_file_size must be positive")
    env = dict(os.environ)
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY"):
        env.pop(name, None)

    def git(*args, data=None):
        try:
            result = subprocess.run(["git", "-C", str(root), *args], env=env, input=data,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        except subprocess.CalledProcessError as error:
            raise ValueError("Git publication inspection failed: " + os.fsdecode(error.stderr).strip()) from error
        return result.stdout

    if Path(os.fsdecode(git("rev-parse", "--show-toplevel")).strip()).resolve() != root:
        raise ValueError("staged publication root must be the Git repository root")
    entries = []
    errors = []
    for item in git("ls-files", "--stage", "-z").split(b"\0"):
        if not item:
            continue
        metadata, name = item.split(b"\t", 1)
        mode, identity, stage = metadata.split()
        relative = Path(os.fsdecode(name))
        errors.extend(_path_findings(relative, selected=True))
        if stage != b"0" or mode not in (b"100644", b"100755"):
            errors.append(f"{relative}: nonregular or unmerged index entry requires manual review")
            continue
        entries.append((relative, identity))
    if not entries:
        return errors
    sizes = git("cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)",
                data=b"\n".join(identity for _, identity in entries) + b"\n").splitlines()
    selected = []
    for (relative, identity), info in zip(entries, sizes):
        _, kind, size = info.split()
        size = int(size)
        if kind != b"blob":
            errors.append(f"{relative}: index object is not a blob")
        elif size > max_file_size:
            errors.extend(_content_findings(relative, b"", size, root, max_file_size))
        else:
            selected.append((relative, identity, size))
    if selected:
        blobs = git("cat-file", "--batch", data=b"\n".join(identity for _, identity, _ in selected) + b"\n")
        offset = 0
        for relative, _, size in selected:
            start = blobs.index(b"\n", offset) + 1
            errors.extend(_content_findings(relative, blobs[start:start + size], size, root, max_file_size))
            offset = start + size + 1
    return errors
