#!/usr/bin/env python3
import argparse
import hashlib
import json
import re
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path

import yaml


def write_checksum(archive_path: Path):
    hasher = hashlib.sha256()
    with archive_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    checksum_path = archive_path.with_suffix(archive_path.suffix + ".sha256")
    checksum_path.write_text(f"{hasher.hexdigest()}  {archive_path.name}\n")


def write_readme(bundle_dir: Path, name: str, description: str, bundle_slug: str):
    lines = [f"# {name}", ""]
    if description:
        lines.append(description)
        lines.append("")
    lines.extend(
        [
            "Apply:",
            "```bash",
            "kubectl apply -f policies.yaml -f bindings.yaml",
            "```",
            "",
            "Apply only these two files. Do not apply the bundle directory: `probes/` holds",
            "deliberately non-compliant manifests used to verify that each policy denies what",
            "it should, and applying them is never intended.",
            "",
            "View online:",
            f"https://cenroq.com/policies/bundles/{bundle_slug}",
            "",
            "Contact us:",
            "https://cenroq.com",
            "",
        ]
    )
    (bundle_dir / "README.md").write_text("\n".join(lines))


def write_probes(bundle_dir: Path, policy_names: list[str], policy_index: dict[str, Path]):
    """Copy each policy's deny-case manifests into <bundle>/probes/ as plain YAML.

    kubeapt installs a bundle from a hard-coded two-filename allowlist
    (policies.yaml, bindings.yaml) and never scans the directory, so probes are
    inert on that path by construction. The kubectl fallback in bundle.json and
    README.md names those same two files for the same reason.
    """
    probes_dir = bundle_dir / "probes"
    written: dict[str, Path] = {}

    for policy_name in policy_names:
        src_dir = policy_index[policy_name].parent
        uuid = read_policy_uuid(policy_index[policy_name])
        for src in sorted(src_dir.glob("deny*.yaml")):
            if src.name == "deny.yaml":
                dest_name = f"{policy_name}.yaml"
            elif src.name.startswith("deny-"):
                suffix = src.name[len("deny-") : -len(".yaml")]
                dest_name = f"{policy_name}.{suffix}.yaml"
            else:
                continue
            if dest_name in written:
                raise SystemExit(f"probe filename collision: {dest_name}")
            header = [f"# policy: {policy_name}"]
            if uuid:
                header.append(f"# uuid: {uuid}")
            body = rewrite_probe_commands(src.read_text(), policy_name)
            probes_dir.mkdir(parents=True, exist_ok=True)
            (probes_dir / dest_name).write_text("\n".join(header) + "\n" + body)
            written[dest_name] = src

    return written


def read_policy_uuid(policy_path: Path) -> str | None:
    doc = yaml.safe_load(policy_path.read_text())
    if not isinstance(doc, dict):
        return None
    return doc.get("metadata", {}).get("annotations", {}).get("kubeapt.io/uuid")


def rewrite_probe_commands(text: str, policy_name: str) -> str:
    """Repoint '# Command:' --custom paths at the probe's bundle-relative location.

    In the repo those paths are like policies/<dir>/deny-<suffix>.yaml, which does
    not exist inside an extracted bundle. Anything that does not match is left alone.
    """
    out = []
    for line in text.split("\n"):
        if line.startswith("# Command: "):
            line = re.sub(
                r"--custom=\S*/deny-([A-Za-z0-9._-]+)\.yaml",
                lambda m: f"--custom=probes/{policy_name}.{m.group(1)}.yaml",
                line,
            )
        out.append(line)
    return "\n".join(out)


def load_policy_index(root: Path) -> dict[str, Path]:
    policy_index: dict[str, Path] = {}
    duplicates: dict[str, list[Path]] = {}
    for path in root.glob("policies/**/policy.yaml"):
        doc = yaml.safe_load(path.read_text())
        if not isinstance(doc, dict):
            continue
        name = doc.get("metadata", {}).get("name")
        if not name:
            continue
        if name in policy_index and policy_index[name] != path:
            duplicates.setdefault(name, [policy_index[name]]).append(path)
        else:
            policy_index[name] = path
    if duplicates:
        messages = []
        for name, paths in sorted(duplicates.items()):
            path_list = ", ".join(str(path) for path in paths)
            messages.append(f"{name}: {path_list}")
        raise SystemExit("duplicate policy names found:\n" + "\n".join(messages))
    return policy_index


def read_bundle(bundle_dir: Path):
    bundle_path = bundle_dir / "bundle.json"
    data = json.loads(bundle_path.read_text())
    if not isinstance(data, dict):
        raise SystemExit(f"invalid bundle format: {bundle_path}")
    name = data.get("name") or bundle_dir.name
    description = (data.get("description") or "").strip()
    version = data.get("version")
    if not version:
        raise SystemExit(f"bundle version missing: {bundle_path}")
    policies = data.get("policies", [])
    if not isinstance(policies, list):
        raise SystemExit(f"bundle policies must be a list: {bundle_path}")
    return bundle_dir.name, name, description, version, policies


def collect_bundle_dirs(bundles_dir: Path) -> list[Path]:
    bundle_dirs = []
    for path in sorted(bundles_dir.iterdir()):
        if path.is_dir() and (path / "bundle.json").exists():
            bundle_dirs.append(path)
    return bundle_dirs


def build_bundle(root: Path, bundle_dir: Path, policy_index: dict[str, Path]):
    bundle_slug, name, description, version, policy_names = read_bundle(bundle_dir)

    missing = [name for name in policy_names if name not in policy_index]
    if missing:
        missing_list = ", ".join(missing)
        raise SystemExit(f"bundle {bundle_slug} references missing policies: {missing_list}")

    deduped = list(dict.fromkeys(policy_names))
    if len(deduped) != len(policy_names):
        raise SystemExit(f"bundle {bundle_slug} has duplicate policy names")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_root = Path(tmpdir)
        bundle_dir = tmp_root / bundle_slug
        bundle_dir.mkdir(parents=True, exist_ok=True)

        policy_docs = []
        for policy_name in deduped:
            path = policy_index[policy_name]
            text = path.read_text().strip()
            if text.startswith("---"):
                lines = text.splitlines()
                text = "\n".join(lines[1:]).strip()
            policy_docs.append(text)

        policies_path = bundle_dir / "policies.yaml"
        policies_path.write_text("\n---\n".join(policy_docs).rstrip() + "\n")

        bindings_path = root / "bundles" / bundle_slug / "bindings.yaml"
        if bindings_path.exists():
            bindings_docs = []
            dangling: dict[str, int] = {}
            unbound = set(deduped)
            for doc in yaml.safe_load_all(bindings_path.read_text()):
                if not isinstance(doc, dict):
                    bindings_docs.append(doc)
                    continue
                # A binding whose policyName does not resolve is accepted by the API server
                # and then silently never enforced, so catch it at build time.
                referenced = doc.get("spec", {}).get("policyName")
                if referenced not in policy_index:
                    dangling[referenced] = dangling.get(referenced, 0) + 1
                unbound.discard(referenced)
                metadata = doc.setdefault("metadata", {})
                current_name = metadata.get("name")
                if current_name:
                    metadata["name"] = f"{bundle_slug}--{version}--{current_name}"
                labels = metadata.setdefault("labels", {})
                labels["bundle"] = bundle_slug
                annotations = metadata.setdefault("annotations", {})
                annotations["policy-bundle.cenroq.io/name"] = bundle_slug
                annotations["policy-bundle.cenroq.io/version"] = version
                bindings_docs.append(doc)
            if dangling:
                detail = ", ".join(f"{n} ({c} bindings)" for n, c in sorted(dangling.items(), key=lambda x: str(x[0])))
                raise SystemExit(
                    f"bundle {bundle_slug} has bindings referencing unknown policies: {detail}"
                )
            if unbound:
                raise SystemExit(
                    f"bundle {bundle_slug} has policies with no binding: {', '.join(sorted(unbound))}"
                )
            (bundle_dir / "bindings.yaml").write_text(
                yaml.safe_dump_all(bindings_docs, sort_keys=False, explicit_start=True)
            )

        write_probes(bundle_dir, deduped, policy_index)

        write_readme(bundle_dir, name, description, bundle_slug)

        out_dir = root / "bundles" / bundle_slug
        out_dir.mkdir(parents=True, exist_ok=True)
        tar_path = out_dir / f"{bundle_slug}_{version}.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tar:
            tar.add(bundle_dir, arcname=bundle_slug)
        write_checksum(tar_path)

        zip_path = out_dir / f"{bundle_slug}_{version}.zip"
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for file_path in bundle_dir.rglob("*"):
                if file_path.is_file():
                    zf.write(file_path, file_path.relative_to(tmp_root))
        write_checksum(zip_path)


def main():
    parser = argparse.ArgumentParser(
        description="Build bundle archives from bundles/*/bundle.json."
    )
    parser.add_argument(
        "--bundle",
        action="append",
        help="Bundle name (folder under bundles/) to build. May be repeated.",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parent
    bundles_dir = root / "bundles"
    policy_index = load_policy_index(root)

    if args.bundle:
        bundle_dirs = [bundles_dir / name for name in args.bundle]
        for path in bundle_dirs:
            if not (path / "bundle.json").exists():
                raise SystemExit(f"bundle not found: {path}")
    else:
        bundle_dirs = collect_bundle_dirs(bundles_dir)

    if not bundle_dirs:
        raise SystemExit("no bundle directories found")

    for bundle_dir in bundle_dirs:
        build_bundle(root, bundle_dir, policy_index)


if __name__ == "__main__":
    main()
