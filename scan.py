#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, hashlib, tarfile, bz2, io

def get_hashes(path):
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    size = os.path.getsize(path)
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            md5.update(chunk); sha1.update(chunk); sha256.update(chunk)
    return size, md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()

def extract_control(deb_path):
    with open(deb_path, 'rb') as f:
        if f.read(8) != b"!<arch>\n":
            raise ValueError("Not a valid deb file")
        while True:
            header = f.read(60)
            if len(header) < 60: break
            name = header[0:16].decode('ascii').strip()
            size = int(header[48:58].decode('ascii').strip())
            padded = size + (size % 2)
            if name.startswith('control.tar'):
                data = f.read(size)
                ext = name.split('.')[-1] if '.' in name[11:] else ''
                mode = f"r:{ext}" if ext in ('gz','xz','bz2') else "r"
                with tarfile.open(fileobj=io.BytesIO(data), mode=mode) as tar:
                    for m in tar.getmembers():
                        if m.name.endswith('control') and m.isfile():
                            cf = tar.extractfile(m)
                            if cf: return cf.read().decode('utf-8', errors='replace')
                break
            else:
                f.seek(padded, os.SEEK_CUR)
    raise ValueError("control not found")

def main():
    repo = os.path.dirname(os.path.abspath(__file__))
    debs_dir = os.path.join(repo, 'debs')
    if not os.path.isdir(debs_dir):
        print("No debs/ directory found."); return

    debs = sorted(f for f in os.listdir(debs_dir) if f.endswith('.deb'))
    print(f"Found {len(debs)} deb(s).")

    entries = []
    for deb in debs:
        path = os.path.join(debs_dir, deb)
        print(f"  {deb}")
        try:
            ctrl = extract_control(path)
            size, md5, sha1, sha256 = get_hashes(path)
            lines = ctrl.strip().replace('\r\n','\n').replace('\r','\n').split('\n')
            out = [l for l in lines if not any(
                l.lower().startswith(x) for x in ['filename:','size:','md5sum:','sha1:','sha256:']
            )]
            out += [f"Filename: https://cdn.jsdelivr.net/gh/enix80126/jailbreak-repo@main/debs/{deb}", f"Size: {size}",
                    f"MD5sum: {md5}", f"SHA1: {sha1}", f"SHA256: {sha256}"]
            entries.append('\n'.join(out))
        except Exception as e:
            print(f"  ERROR: {e}")

    data = ('\n\n'.join(entries) + '\n').encode('utf-8')
    open(os.path.join(repo, 'Packages'), 'wb').write(data)
    open(os.path.join(repo, 'Packages.bz2'), 'wb').write(bz2.compress(data))
    print(f"Done: {len(entries)} packages written.")

if __name__ == '__main__':
    main()
