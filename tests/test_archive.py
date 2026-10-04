"""Security tests for uploaded ZIP archives."""

import io
import sys
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scanner.archive import ArchiveSecurityError, cleanup_extracted, extract_zip


def zip_bytes(entries):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, content in entries:
            archive.writestr(name, content)
    output.seek(0)
    return output


def test_safe_extraction_filters_files_and_cleans_up():
    root, stats, owns_root = extract_zip(zip_bytes([
        ("src/app.py", "token = 'example'"),
        ("image.png", "not scanned"),
    ]))
    try:
        assert owns_root is True
        assert stats.files_seen == 2
        assert stats.files_extracted == 1
        assert (root / "src" / "app.py").exists()
        assert not (root / "image.png").exists()
    finally:
        cleanup_extracted(root)
    assert not root.exists()


def test_path_traversal_is_rejected():
    try:
        extract_zip(zip_bytes([("../../outside.py", "bad")]))
    except ArchiveSecurityError:
        return
    raise AssertionError("path traversal was accepted")


def test_invalid_zip_is_rejected():
    try:
        extract_zip(io.BytesIO(b"not a zip"))
    except ArchiveSecurityError:
        return
    raise AssertionError("invalid ZIP was accepted")


if __name__ == "__main__":
    for name, test in sorted(globals().items()):
        if name.startswith("test_"):
            test()
            print(f"[PASS] {name}")