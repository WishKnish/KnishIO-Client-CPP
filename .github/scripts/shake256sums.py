#!/usr/bin/env python3
"""Write <dir>/SHAKE256SUMS: one `<shake256-256 hex>  <relative path>` line per file under <dir>.

FIPS 202 SHAKE256 with a 256-bit (32-byte) output, the same manifest format the release
workflows have always shipped inside each tarball. Files are walked from <dir>, SHAKE256SUMS
itself is skipped, and lines are sorted by path.
"""
import hashlib
import os
import sys

MANIFEST = 'SHAKE256SUMS'


def manifest_lines(root):
    lines = []
    cwd = os.getcwd()
    os.chdir(root)
    try:
        for base, _dirs, files in os.walk('.'):
            for name in sorted(files):
                if name == MANIFEST:
                    continue
                path = os.path.join(base, name)
                rel = os.path.relpath(path, '.')
                with open(path, 'rb') as fh:
                    digest = hashlib.shake_256(fh.read()).hexdigest(32)
                lines.append(f'{digest}  {rel}')
    finally:
        os.chdir(cwd)
    lines.sort(key=lambda line: line.split('  ', 1)[1])
    return lines


def write_manifest(root):
    lines = manifest_lines(root)
    with open(os.path.join(root, MANIFEST), 'w') as fh:
        fh.write('\n'.join(lines) + '\n')
    return len(lines)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit(f'usage: {sys.argv[0]} <dir>')
    count = write_manifest(sys.argv[1])
    print(f'{MANIFEST}: {count} files')
