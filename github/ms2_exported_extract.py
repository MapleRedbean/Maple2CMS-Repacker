#!/usr/bin/env python3
"""
MapleStory2 Exported Resource Extractor
========================================
Extracts all .flat/.xblock files from MapleStory2 Exported_*.m2d archives.

Usage:
    python ms2_exported_extract.py [options]

Requirements:
    pip install pycryptodome

Input Files (all in same directory as this script):
    1. Exported_*.m2d files (from game Data/Resource)
    2. Exported.m2h.header (decrypted CSV file list)
    3. Exported.filetable.decrypted.bin (decrypted FileTable, 40 bytes/entry)
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

BOM_UTF8 = b'\xef\xbb\xbf'
XML_HEADER = b'<?xml'
FLAT_MAGIC = b'FLAT'

def load_keys(key_path):
    with open(key_path, 'rb') as f:
        data = json.load(f)
    return [bytes(k) for k in data['OS2F_USER_KEY']], [bytes(iv) for iv in data['OS2F_IV_CHAIN']]

def aes_ctr(ki, data, keys, ivs):
    iv_int = int.from_bytes(ivs[ki], 'big')
    ctr = Counter.new(128, initial_value=iv_int)
    return AES.new(keys[ki], AES.MODE_CTR, counter=ctr).decrypt(data)

def is_valid(data):
    if len(data) < 4:
        return False
    if data[:3] == BOM_UTF8 and data[3:8] == XML_HEADER:
        return True
    if data[:5] == XML_HEADER:
        return True
    if data[:4] == FLAT_MAGIC:
        return True
    if len(data) > 10:
        printable = sum(1 for b in data[:100] if 32 <= b < 127 or b in (9, 10, 13))
        if printable > 80:
            return True
    return False

def parse_csv(csv_path):
    by_index = {}
    with open(csv_path, 'rb') as f:
        for line in f.read().split(b'\n'):
            line = line.strip()
            if not line:
                continue
            parts = line.split(b',')
            if len(parts) >= 3:
                idx = int(parts[0])
                m2d_id = parts[1].decode('ascii')
                filepath = parts[2].decode('utf-8', errors='replace')
                by_index[idx] = (m2d_id, filepath)
    return by_index

def parse_filetable(ft_path):
    ft = {}
    with open(ft_path, 'rb') as f:
        raw = f.read()
    for i in range(len(raw) // 40):
        v = struct.unpack_from('<10I', raw, i * 40)
        ft[v[1]] = {
            'flag': v[0],
            'block_size': v[2],
            'file_size': v[4],
            'offset': v[8],
        }
    return ft

def extract_file(raw_m2d, entry, keys, ivs):
    offset = entry['offset']
    block_size = entry['block_size']
    file_size = entry['file_size']
    
    if offset + block_size > len(raw_m2d):
        return None
    
    chunk = raw_m2d[offset:offset + block_size]
    
    clean = chunk.replace(b'=', b'')
    pad = (4 - len(clean) % 4) % 4
    try:
        decoded = base64.b64decode(clean + b'=' * pad)
    except Exception:
        return None
    
    ki = file_size & 0x7F
    try:
        dec = aes_ctr(ki, decoded, keys, ivs)
    except Exception:
        return None
    
    if len(dec) >= 2 and dec[0] == 0x78 and dec[1] in (0x01, 0x5E, 0x9C, 0xDA):
        try:
            dec = zlib.decompress(dec)
        except zlib.error:
            pass
    
    if len(dec) > file_size:
        dec = dec[:file_size]
    
    return dec

def main():
    p = argparse.ArgumentParser(description='MapleStory2 Exported Resource Extractor')
    p.add_argument('--m2d', required=True, help='Directory with Exported_*.m2d files')
    p.add_argument('--csv', default='Exported.m2h.header', help='Decrypted CSV file list')
    p.add_argument('--ft', default='Exported.filetable.decrypted.bin', help='Decrypted FileTable')
    p.add_argument('--keys', default='orion2_keys.json', help='AES key table JSON')
    p.add_argument('--out', default='extracted', help='Output directory')
    p.add_argument('--dry-run', action='store_true', help='Validate only')
    p.add_argument('--limit', type=int, default=0, help='Limit files (0=all)')
    args = p.parse_args()

    print("Loading...")
    keys, ivs = load_keys(args.keys)
    csv = parse_csv(args.csv)
    ft = parse_filetable(args.ft)
    print(f"  Keys: {len(keys)}  CSV: {len(csv)}  FT: {len(ft)}")

    os.makedirs(args.out, exist_ok=True)
    total_ok, total_bad = 0, 0
    m2d_cache = {}

    by_m2d = defaultdict(list)
    for idx, (m2d_id, filepath) in csv.items():
        by_m2d[m2d_id].append((idx, filepath))

    for m2d_id, files in sorted(by_m2d.items(), key=lambda x: -len(x[1])):
        fname = f'Exported_{m2d_id}.m2d'
        fpath = os.path.join(args.m2d, fname)
        if not os.path.exists(fpath):
            print(f"  SKIP: {fname} not found")
            continue

        if fname not in m2d_cache:
            with open(fpath, 'rb') as f:
                m2d_cache[fname] = f.read()
        raw = m2d_cache[fname]

        ok, bad = 0, 0
        for idx, filepath in files:
            if args.limit and total_ok + total_bad >= args.limit:
                break
            entry = ft.get(idx)
            if not entry:
                bad += 1
                continue
            if args.dry_run:
                ok += 1
                continue

            data = extract_file(raw, entry, keys, ivs)
            if data is None:
                bad += 1
                continue

            out_path = os.path.join(args.out, filepath.replace('/', os.sep))
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, 'wb') as f:
                f.write(data)
            ok += 1

        total_ok += ok
        total_bad += bad
        pct = ok * 100 // len(files) if files else 0
        flag = " [WARN]" if bad else ""
        print(f"  {fname}: {ok}/{len(files)} ({pct}%){flag}")

    print(f"\nDone: {total_ok} ok, {total_bad} bad (total {total_ok + total_bad})")
    if not args.dry_run:
        print(f"Output: {os.path.abspath(args.out)}")

if __name__ == '__main__':
    main()
