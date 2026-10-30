"""Data-free harness tests with child-scoped imports and writable scratch storage."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--temp-root", type=Path, default=ROOT / ".work/test-temp")
    parser.add_argument("--pattern", default="test*.py")
    parser.add_argument("--dependency-path", type=Path)
    args = parser.parse_args(argv)
    scratch = args.temp_root.resolve()
    try:
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            before = Path(directory) / "before"
            before.write_bytes(b"probe")
            before.replace(Path(directory) / "after").unlink()
        paths = [str(ROOT / "src")]
        if args.dependency_path:
            dependency = args.dependency_path.resolve(strict=True)
            if not dependency.is_dir():
                raise ValueError("dependency path must be a directory")
            paths.append(str(dependency))
    except (OSError, ValueError) as error:
        parser.error("test storage/dependency preflight failed: " + str(error))
    env = dict(os.environ)
    if env.get("PYTHONPATH"):
        paths.append(env["PYTHONPATH"])
    env.update(TEMP=str(scratch), TMP=str(scratch), TMPDIR=str(scratch),
               PYTHONPATH=os.pathsep.join(paths), PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run([sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests",
                             "-p", args.pattern, "-v"], cwd=ROOT, env=env, stdin=subprocess.DEVNULL)
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
