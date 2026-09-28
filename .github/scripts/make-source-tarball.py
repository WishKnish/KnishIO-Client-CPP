#!/usr/bin/env python3
"""Build <out>/<name>-<version>-src.tar.gz from the tracked files of this checkout,
including every initialised submodule (external/mlkem-native), with a SHAKE256SUMS manifest.

GitHub's automatic "Source code" archive omits submodules, so it cannot build. This tarball
is the buildable source distribution attached to each Release. It holds tracked files only
(no git history) and is deterministic: members sorted by path, uid/gid 0, mtime = the HEAD
commit time, gzip header mtime 0 with no file name. The same commit gives the same bytes.

usage: make-source-tarball.py --name knishio-client-c --version 1.2.3 --out dist
"""
import argparse
import gzip
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile

sys.dont_write_bytecode = True  # importing shake256sums must not leave __pycache__/ in the checkout
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from shake256sums import write_manifest  # noqa: E402


def git(*args):
    return subprocess.run(['git', *args], check=True, capture_output=True).stdout


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--name', required=True)
    ap.add_argument('--version', required=True)
    ap.add_argument('--out', required=True)
    opts = ap.parse_args()

    for line in git('submodule', 'status', '--recursive').decode().splitlines():
        if not line.startswith(' '):
            print(f'submodule not initialised at its recorded commit: {line}', file=sys.stderr)
            sys.exit(2)

    top = f'{opts.name}-{opts.version}-src'
    mtime = int(git('log', '-1', '--format=%ct').decode().strip())
    files = [p for p in git('ls-files', '-z', '--recurse-submodules').decode().split('\0') if p]

    with tempfile.TemporaryDirectory() as tmp:
        stage = os.path.join(tmp, top)
        for rel in files:
            src = os.path.join('.', rel)
            dst = os.path.join(stage, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            if os.path.islink(src):
                os.symlink(os.readlink(src), dst)
            else:
                shutil.copy2(src, dst)
        write_manifest(stage)

        members = []
        for base, dirs, names in os.walk(stage):
            members.append(base)
            members.extend(os.path.join(base, n) for n in names)
            # os.walk lists a symlink to a directory under `dirs` and does not descend into it;
            # it is still a tracked path (mlkem-native's examples use them), so keep the link.
            members.extend(os.path.join(base, d) for d in dirs if os.path.islink(os.path.join(base, d)))
        members = sorted(set(members), key=lambda p: os.path.relpath(p, tmp))

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w', format=tarfile.PAX_FORMAT) as tar:
            for path in members:
                info = tar.gettarinfo(path, arcname=os.path.relpath(path, tmp))
                info.uid = info.gid = 0
                info.uname = info.gname = ''
                info.mtime = mtime
                if info.isfile():
                    with open(path, 'rb') as fh:
                        tar.addfile(info, fh)
                else:
                    tar.addfile(info)

    os.makedirs(opts.out, exist_ok=True)
    out = os.path.join(opts.out, f'{top}.tar.gz')
    with open(out, 'wb') as raw:
        with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as gz:
            gz.write(buf.getvalue())
    print(f'{out} ({os.path.getsize(out)} bytes, {len(files)} files)')


if __name__ == '__main__':
    main()
