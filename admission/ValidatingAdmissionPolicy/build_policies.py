#!/usr/bin/env python3
import hashlib
import tarfile
import zipfile
from pathlib import Path


def write_checksum(archive_path: Path):
    hasher = hashlib.sha256()
    with archive_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    checksum_path = archive_path.with_suffix(archive_path.suffix + ".sha256")
    checksum_path.write_text(f"{hasher.hexdigest()}  {archive_path.name}\n")


def build_archives(root: Path):
    policies_dir = root / "policies"
    if not policies_dir.exists():
        raise SystemExit(f"policies directory not found: {policies_dir}")

    # The archives are written into the directory they archive, so a rebuild would
    # otherwise swallow the previous build's output and grow on every run.
    generated = {
        "policies.json",
        "policies.tar.gz",
        "policies.tar.gz.sha256",
        "policies.zip",
        "policies.zip.sha256",
    }

    tar_path = policies_dir / "policies.tar.gz"
    def tar_filter(tarinfo: tarfile.TarInfo) -> tarfile.TarInfo | None:
        name = Path(tarinfo.name)
        if name.parent == Path("policies") and name.name in generated:
            return None
        return tarinfo

    with tarfile.open(tar_path, "w:gz") as tar:
        tar.add(policies_dir, arcname="policies", filter=tar_filter)
    write_checksum(tar_path)

    zip_path = policies_dir / "policies.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for file_path in policies_dir.rglob("*"):
            if file_path.is_file():
                if file_path.parent == policies_dir and file_path.name in generated:
                    continue
                zf.write(file_path, file_path.relative_to(policies_dir))
    write_checksum(zip_path)


def main():
    root = Path(__file__).resolve().parent
    build_archives(root)


if __name__ == "__main__":
    main()
