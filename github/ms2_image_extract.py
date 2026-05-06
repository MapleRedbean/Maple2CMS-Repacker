#!/usr/bin/env python3
"""
MapleStory2 Image Resource Extractor
=====================================
Extracts all image files (PNG/DDS/BMP) from MapleStory2 Image_*.m2d archives.

Usage:
    python ms2_extract.py --m2d <m2d_dir> --out <output_dir> [options]

Requirements:
    pip install pycryptodome

Input Files:
    1. Image_*.m2d files (from game Data/Resource)
    2. Image.m2h.header (decrypted CSV file list)
    3. filetable_decrypted.bin (decrypted FileTable, 40 bytes/entry)
    4. orion2_keys.json (AES key table)

How It Works:
    Each file in the M2D archive is independently encrypted:
      Base64 block -> AES-CTR decrypt (key = file_size & 0x7F) -> zlib decompress
    Counter is reset for each file. Key depends on uncompressed file size.

Author: AutoClaw
"""

import argparse, json, base64, os, struct, sys, zlib
from collections import defaultdict

try:
    from Crypto.Cipher import AES
    from Crypto.Util import Counter
except ImportError:
    print("Error: pip install pycryptodome")
    sys.exit(1)

PNG_MAGIC = b'\x89PNG'
DDS_MAGIC = b'DDS '
BMP_MAGIC = b'BM'

def load_keys(key_path):
    with open(key_path, 'rb') as f:
        data = json.load(f)
    return [bytes(k) for k in data['OS2F_USER_KEY']], [bytes(iv) for iv in data['OS2F_IV_CHAIN']]

def aes_ctr(ki, data, keys, ivs):
    """AES-CTR with 128-bit counter, independent per file."""
    iv_int = int.from_bytes(ivs[ki], 'big')
    ctr = Counter.new(128, initial_value=iv_int)
    return AES.new(keys[ki], AES.MODE_CTR, counter=ctr).decrypt(data)

def is_valid(data):
    return (data[:4] == PNG_MAGIC or data[:4] == DDS_MAGIC or data[:2] == BMP_MAGIC)

def parse_csv(csv_path):
    by_m2d = defaultdict(list)
    with open(csv_path, 'rb') as f:
        for line in f.read().split(b'\r\n'):
            if not line:
                continue
            p = line.split(b',')
            if len(p) >= 3:
                by_m2d[p[1].decode('ascii')].append((
                    int(p[0]), p[2].decode('utf-8', errors='replace')
                ))
    return by_m2d

def parse_filetable(ft_path):
    ft = {}
    with open(ft_path, 'rb') as f:
        raw = f.read()
    for i in range(len(raw) // 40):
        v = struct.unpack_from('<10I', raw, i * 40)
        ft[v[1]] = (v[2], v[4], v[8])  # block_size, file_size, offset
    return ft

def extract_file(raw_m2d, off, bs, fs, keys, ivs):
    """Extract one file: read base64 block -> decode -> AES -> zlib -> validate."""
    chunk = raw_m2d[off:off + bs]
    clean = chunk.replace(b'=', b'')
    pad = (4 - len(clean) % 4) % 4
    decoded = base64.b64decode(clean + b'=' * pad)

    ki = fs & 0x7F  # key = file_size mod 128
    dec = aes_ctr(ki, decoded, keys, ivs)
    if len(dec) >= 2 and dec[0] == 0x78:
        try:
            dec = zlib.decompress(dec)
        except zlib.error:
            pass
    return dec if is_valid(dec) else None

def main():
    p = argparse.ArgumentParser(description='MapleStory2 Image Resource Extractor')
    p.add_argument('--m2d', required=True, help='Directory with Image_*.m2d files')
    p.add_argument('--csv', default='Image.m2h.header', help='Decrypted CSV file list')
    p.add_argument('--ft', default='filetable_decrypted.bin', help='Decrypted FileTable')
    p.add_argument('--keys', default='orion2_keys.json', help='AES key table JSON')
    p.add_argument('--out', default='extracted', help='Output directory')
    p.add_argument('--dry-run', action='store_true', help='Validate only')
    args = p.parse_args()

    print("Loading...")
    keys, ivs = load_keys(args.keys)
    by_m2d = parse_csv(args.csv)
    ft = parse_filetable(args.ft)
    print(f"  Keys: {len(keys)}  Files: {sum(len(v) for v in by_m2d.values())}  M2Ds: {len(by_m2d)}")

    os.makedirs(args.out, exist_ok=True)
    total_ok, total_bad = 0, 0

    for mid, files in sorted(by_m2d.items(), key=lambda x: -len(x[1])):
        fname = f'Image_{mid}.m2d'
        fpath = os.path.join(args.m2d, fname)
        if not os.path.exists(fpath):
            continue
        with open(fpath, 'rb') as f:
            raw = f.read()

        ok, bad = 0, 0
        for idx, fp in files:
            entry = ft.get(idx)
            if not entry:
                continue
            bs, fs, off = entry
            if off + bs > len(raw):
                continue

            if args.dry_run:
                ok += 1
                continue

            data = extract_file(raw, off, bs, fs, keys, ivs)
            if data is None:
                bad += 1
                continue

            out_path = os.path.join(args.out, fp.replace('/', os.sep))
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, 'wb') as f:
                f.write(data)
            ok += 1

        pct = ok * 100 // len(files) if files else 0
        flag = " [WARN]" if bad else ""
        print(f"  {fname}: {ok}/{len(files)} ({pct}%){flag}")
        total_ok += ok
        total_bad += bad

    print(f"\nDone: {total_ok} ok, {total_bad} bad (total {total_ok + total_bad})")
    if total_bad == 0:
        print("All files extracted and validated successfully!")
    if not args.dry_run:
        print(f"Output: {os.path.abspath(args.out)}")

if __name__ == '__main__':
    main()
