#!/usr/bin/env python3
import argparse
import gzip
import hashlib
import io
import os
import re
import sys
import tarfile

NAMES = {"jaunt-agent", "jaunt-host-users", "jaunt", "jauntd"}
VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z._+-]*")
TARGET = re.compile(r"[a-z0-9_]+(-[a-z0-9_]+){2,3}")
DOCS_URL = "https://github.com/GlobalArtInc/jaunt/blob/main/docs/install.md"


def readme(name, version, target):
    lines = [
        f"{name} {version} ({target})",
        "",
    ]
    if "linux" in target:
        lines += ["Statically linked build: no shared libraries are needed on the host.", ""]
    lines += [
        f"Install: sudo install -m 0755 {name} /usr/local/bin/{name}",
        "Verify the download: sha256sum -c SHA256SUMS",
        "Verify the provenance: gh attestation verify <file> --repo GlobalArtInc/jaunt",
        f"Documentation: {DOCS_URL}",
        "License: MIT (see LICENSE).",
        "",
    ]
    return "\n".join(lines).encode()


def add_file(archive, path, data, mode, epoch):
    info = tarfile.TarInfo(path)
    info.size = len(data)
    info.mode = mode
    info.mtime = epoch
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    archive.addfile(info, io.BytesIO(data))


def add_directory(archive, path, epoch):
    info = tarfile.TarInfo(path)
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    info.mtime = epoch
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    archive.addfile(info)


def package(binary, version, target, epoch, license_text, out_dir):
    name = os.path.basename(binary)
    if name not in NAMES:
        raise ValueError(f"unexpected binary name {name}")
    with open(binary, "rb") as handle:
        payload = handle.read()
    stem = f"{name}-{version}-{target}"
    raw = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode="w", format=tarfile.PAX_FORMAT) as archive:
            add_directory(archive, stem, epoch)
            files = [
                (name, payload, 0o755),
                ("LICENSE", license_text, 0o644),
                ("README.txt", readme(name, version, target), 0o644),
            ]
            for file_name, data, mode in sorted(files):
                add_file(archive, f"{stem}/{file_name}", data, mode, epoch)
    data = raw.getvalue()
    filename = f"{stem}.tar.gz"
    with open(os.path.join(out_dir, filename), "wb") as handle:
        handle.write(data)
    return filename, hashlib.sha256(data).hexdigest()


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--epoch", required=True, type=int)
    parser.add_argument("--license", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("binaries", nargs="+")
    args = parser.parse_args(argv)
    if VERSION.fullmatch(args.version) is None:
        parser.error("invalid version")
    if TARGET.fullmatch(args.target) is None:
        parser.error("invalid target")
    if args.epoch < 0:
        parser.error("invalid epoch")
    with open(args.license, "rb") as handle:
        license_text = handle.read()
    os.makedirs(args.out, exist_ok=True)
    sums = []
    for binary in args.binaries:
        filename, digest = package(
            binary, args.version, args.target, args.epoch, license_text, args.out
        )
        sums.append(f"{digest}  {filename}\n")
    with open(os.path.join(args.out, f"SHA256SUMS.{args.target}"), "w") as handle:
        handle.writelines(sums)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
