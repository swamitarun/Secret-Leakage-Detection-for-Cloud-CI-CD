"""Secure handling of user-uploaded project ZIP archives."""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
MAX_EXTRACTED_BYTES = 500 * 1024 * 1024
MAX_FILES = 10_000

ALLOWED_EXTENSIONS = {
    ".tf", ".tfvars", ".yaml", ".yml", ".json", ".py", ".env", ".txt", ".md", ".sh",
}
ALLOWED_FILENAMES = {"dockerfile", "jenkinsfile"}


class ArchiveSecurityError(ValueError):
    """Raised when an uploaded archive violates a safety limit."""


@dataclass(frozen=True)
class ArchiveStats:
    files_seen: int
    files_extracted: int
    bytes_extracted: int


def _is_supported_file(name: str) -> bool:
    path = Path(name)
    return path.name.lower() in ALLOWED_FILENAMES or path.suffix.lower() in ALLOWED_EXTENSIONS


def _safe_destination(root: Path, member_name: str) -> Path:
    """Resolve a member and reject absolute paths and traversal."""
    normalized = member_name.replace("\\", "/")
    member_path = Path(normalized)
    if member_path.is_absolute() or ".." in member_path.parts:
        raise ArchiveSecurityError(f"Unsafe archive path: {member_name}")
    destination = (root / member_path).resolve()
    if os.path.commonpath((str(root.resolve()), str(destination))) != str(root.resolve()):
        raise ArchiveSecurityError(f"Unsafe archive path: {member_name}")
    return destination


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return stat.S_ISLNK(mode)


def extract_zip(uploaded_file, destination: Path | None = None) -> tuple[Path, ArchiveStats, bool]:
    """Validate and extract a ZIP into an isolated directory.

    Returns ``(root, stats, owns_root)``. Callers must remove ``root`` when
    ``owns_root`` is true. Unsupported files are ignored, not extracted.
    """
    size = getattr(uploaded_file, "size", None)
    if size is not None and size > MAX_ARCHIVE_BYTES:
        raise ArchiveSecurityError("ZIP exceeds the maximum upload size of 100 MB")

    root = destination or Path(tempfile.mkdtemp(prefix="secret-scan-"))
    owns_root = destination is None
    root.mkdir(parents=True, exist_ok=True)
    try:
        uploaded_file.seek(0)
        with zipfile.ZipFile(uploaded_file) as archive:
            members = [info for info in archive.infolist() if not info.is_dir()]
            if len(members) > MAX_FILES:
                raise ArchiveSecurityError("ZIP contains too many files")
            total_size = sum(info.file_size for info in members)
            if total_size > MAX_EXTRACTED_BYTES:
                raise ArchiveSecurityError("ZIP expands beyond the maximum extracted size of 500 MB")

            extracted = 0
            extracted_bytes = 0
            for info in members:
                destination_path = _safe_destination(root, info.filename)
                if _is_symlink(info):
                    raise ArchiveSecurityError(f"Symlink entries are not allowed: {info.filename}")
                if not _is_supported_file(info.filename):
                    continue
                destination_path.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as source, destination_path.open("wb") as target:
                    shutil.copyfileobj(source, target, length=1024 * 1024)
                extracted += 1
                extracted_bytes += info.file_size
        return root, ArchiveStats(len(members), extracted, extracted_bytes), owns_root
    except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
        if owns_root:
            shutil.rmtree(root, ignore_errors=True)
        raise ArchiveSecurityError(f"Invalid or unreadable ZIP archive: {exc}") from exc
    except Exception:
        if owns_root:
            shutil.rmtree(root, ignore_errors=True)
        raise


def cleanup_extracted(root: Path) -> None:
    """Delete extracted user content after scanning."""
    shutil.rmtree(root, ignore_errors=True)