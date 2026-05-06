# -*- coding: utf-8 -*-
"""
MapleStory2 M2D/M2H Repacker
=============================
Packs a directory of extracted files back into M2D + M2H archives.

Supports: Image / Exported / Map / Effect / Item / Npc / Textures (OS2F)
          Movie (PS2F)

Usage:
  python ms2_pack.py --input ./modified_files --resource Item -o ./output
  python ms2_pack.py --input ./movie_files --resource Movie -o ./output --m2d-prefix CustomMovie

M2H structure:  base64( zlib(CSV) || zlib(FT) )
OS2F M2D:       base64( AES-CTR( zlib(file) ) )
PS2F M2D:       XOR(file, PS2F_XOR_KEY)
"""

import struct, base64, zlib, json, os, sys, argparse, hashlib
from collections import defaultdict

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    def tqdm(iterable, **kw):
        return iterable

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_FILE = os.path.join(SCRIPT_DIR, 'orion2_keys.json')

# ── Crypto ──────────────────────────────────────────────────

def aes_ctr_ecb_encrypt(key, iv, data):
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_ECB)
    result = bytearray()
    counter = bytearray(iv)
    for i in range(0, len(data), 16):
        xor_block = cipher.encrypt(bytes(counter))
        for j in range(16):
            if i + j >= len(data): break
            result.append(data[i + j] ^ xor_block[j])
        for j in range(15, -1, -1):
            counter[j] = (counter[j] + 1) & 0xFF
            if counter[j] != 0: break
    return bytes(result)

def xor_encrypt(data, xor_key):
    """PS2F XOR: 32-bit words with & 0x1FF key rotation (symmetric with decrypt)"""
    result = bytearray(data)
    n_blocks = len(data) >> 2
    for i in range(n_blocks):
        ko = i & 0x1FF
        kw = struct.unpack_from('<I', xor_key, ko * 4)[0]
        dw = struct.unpack_from('<I', result, i * 4)[0]
        struct.pack_into('<I', result, i * 4, dw ^ kw)
    rem_start = n_blocks * 4
    for i in range(len(data) - rem_start):
        result[rem_start + i] ^= xor_key[i & 0x7FF]
    return bytes(result)

# ── Resource Config ─────────────────────────────────────────

OS2F_RESOURCES = {
    'Image':    {'prefix': 'Image_',    'csv_name': 'Image.m2h'},
    'Exported': {'prefix': 'Exported_', 'csv_name': 'Exported.m2h'},
    'Map':      {'prefix': 'Map_',      'csv_name': 'Map.m2h'},
    'Effect':   {'prefix': 'Effect_',   'csv_name': 'Effect.m2h'},
    'Item':     {'prefix': 'Item_',     'csv_name': 'Item.m2h'},
    'Npc':      {'prefix': 'Npc_',      'csv_name': 'Npc_02.m2h'},
    'Textures': {'prefix': 'Textures_', 'csv_name': 'Textures.m2h'},
}

PS2F_RESOURCES = {
    'Movie':    {'prefix': 'Movie_',    'csv_name': 'Movie.m2h'},
}

# ── OS2F Packing ────────────────────────────────────────────

def build_m2d_id(prefix, volume_index):
    """Generate M2D filename ID (sequential, deterministic)"""
    h = hashlib.md5(f'{prefix}{volume_index}'.encode()).hexdigest()[:32]
    # Encode as the game's obfuscated digit-string format
    return h

def pack_os2f(input_dir, resource_name, cfg, output_dir, osk, oiv, m2d_prefix, max_m2d_mb):
    """Pack a directory into OS2F M2D + M2H archives."""

    # 1. Collect all files
    file_list = []
    for root, dirs, files in os.walk(input_dir):
        for f in files:
            full = os.path.join(root, f)
            rel = os.path.relpath(full, input_dir).replace('\\', '/')
            file_list.append((rel, full))

    if not file_list:
        print('Error: No files found in input directory')
        return

    print(f'\n{"="*60}')
    print(f'Packing {resource_name} (OS2F): {len(file_list)} files')
    print(f'{"="*60}')

    # 2. Process each file: compress → encrypt → base64
    processed = []
    total_raw = 0
    total_enc = 0

    for rel, full in tqdm(file_list, desc='  Encoding', unit='file') if HAS_TQDM else file_list:
        with open(full, 'rb') as f:
            raw = f.read()

        raw_size = len(raw)
        total_raw += raw_size

        # zlib compress
        compressed = zlib.compress(raw)

        # AES-CTR encrypt (key = raw_size & 0x7F)
        ki = raw_size & 0x7F
        encrypted = aes_ctr_ecb_encrypt(osk[ki], oiv[ki], compressed)

        # base64 encode
        encoded = base64.b64encode(encrypted)
        total_enc += len(encoded)

        processed.append({
            'path': rel,
            'raw_size': raw_size,
            'compressed_size': len(compressed),
            'block_size': len(encoded),
            'data': encoded,
        })

    # 3. Group into M2D volumes
    max_bytes = max_m2d_mb * 1024 * 1024
    volumes = []  # list of (m2d_id, [file_indices])
    current_vol = []
    current_size = 0
    vol_idx = 0

    for i, p in enumerate(processed):
        if current_size + p['block_size'] > max_bytes and current_vol:
            volumes.append(current_vol)
            current_vol = []
            current_size = 0
        current_vol.append(i)
        current_size += p['block_size']

    if current_vol:
        volumes.append(current_vol)

    m2d_prefix_str = m2d_prefix if m2d_prefix else cfg['prefix']

    # 4. Write M2D files and build FT/CSV
    ft_entries = []
    csv_lines = []
    file_index = 0

    for vol_idx, vol_files in enumerate(tqdm(volumes, desc='  Writing M2D', unit='m2d') if HAS_TQDM else volumes):
        m2d_id = build_m2d_id(m2d_prefix_str, vol_idx)
        m2d_path = os.path.join(output_dir, f'{m2d_prefix_str}{m2d_id}.m2d')

        m2d_data = bytearray()
        offset = 0

        for fi in vol_files:
            p = processed[fi]
            block = p['data']

            m2d_data.extend(block)

            # FT entry (40 bytes)
            ft_entries.append({
                'flag': 0xEE000009,
                'index': file_index,
                'block_size': len(block),
                'file_size': p['raw_size'],
                'raw_size': p['raw_size'],
                'offset': offset,
            })

            # CSV entry: file_index,m2d_id,path
            csv_lines.append(f'{file_index},{m2d_id},{p["path"]}')

            offset += len(block)
            file_index += 1

        os.makedirs(os.path.dirname(m2d_path) if os.path.dirname(m2d_path) else output_dir, exist_ok=True)
        with open(m2d_path, 'wb') as f:
            f.write(bytes(m2d_data))

    # 5. Build M2H
    csv_raw = '\n'.join(csv_lines).encode('utf-8')
    csv_zlib = zlib.compress(csv_raw)

    ft_raw = bytearray()
    for e in ft_entries:
        # 10 x uint32 = 40 bytes
        ft_raw.extend(struct.pack('<10I',
            e['flag'], e['index'], e['block_size'], 0,
            e['file_size'], 0, e['raw_size'], 0,
            e['offset'], 0))
    ft_zlib = zlib.compress(bytes(ft_raw))

    m2h_data = base64.b64encode(csv_zlib + ft_zlib)
    m2h_path = os.path.join(output_dir, cfg['csv_name'])
    with open(m2h_path, 'wb') as f:
        f.write(m2h_data)

    # 6. Summary
    total_m2d_size = sum(
        os.path.getsize(os.path.join(output_dir, f'{m2d_prefix_str}{build_m2d_id(m2d_prefix_str, vi)}.m2d'))
        for vi in range(len(volumes))
    )
    m2h_size = os.path.getsize(m2h_path)

    print(f'\n{"="*60}')
    print(f'Packed {resource_name}:')
    print(f'  Files: {len(file_list)}')
    print(f'  M2D archives: {len(volumes)}')
    print(f'  M2D total: {total_m2d_size / (1024*1024):.1f} MB')
    print(f'  M2H: {m2h_size / 1024:.1f} KB ({m2h_size} bytes)')
    print(f'  Output: {output_dir}')
    print(f'{"="*60}')

# ── PS2F Packing (Movie) ────────────────────────────────────

def pack_ps2f(input_dir, resource_name, cfg, output_dir, psk_xor, m2d_prefix):
    """Pack directory into PS2F M2D + M2H (Movie format)."""

    file_list = []
    for root, dirs, files in os.walk(input_dir):
        for f in files:
            full = os.path.join(root, f)
            rel = os.path.relpath(full, input_dir).replace('\\', '/')
            file_list.append((rel, full))

    if not file_list:
        print('Error: No files found')
        return

    print(f'\n{"="*60}')
    print(f'Packing {resource_name} (PS2F XOR): {len(file_list)} files')
    print(f'  XOR key: {len(psk_xor)} bytes')
    print(f'{"="*60}')

    m2d_prefix_str = m2d_prefix if m2d_prefix else cfg['prefix']
    ft_entries = []
    csv_lines = []

    for idx, (rel, full) in enumerate(tqdm(file_list, desc='  Encoding', unit='file') if HAS_TQDM else file_list):
        with open(full, 'rb') as f:
            raw = f.read()

        file_size = len(raw)

        # XOR encrypt
        encrypted = xor_encrypt(raw, psk_xor)

        # Each file = 1 M2D
        m2d_id = build_m2d_id(m2d_prefix_str, idx)
        m2d_path = os.path.join(output_dir, f'{m2d_prefix_str}{m2d_id}.m2d')
        with open(m2d_path, 'wb') as f:
            f.write(encrypted)

        ft_entries.append({
            'flag': 0xFF000000,
            'index': idx,
            'block_size': file_size,
            'file_size': file_size,
            'raw_size': file_size,
            'offset': 0,
        })
        csv_lines.append(f'{idx},{m2d_id},{rel}')

    # Build M2H
    csv_raw = '\n'.join(csv_lines).encode('utf-8')
    csv_zlib = zlib.compress(csv_raw)

    ft_raw = bytearray()
    for e in ft_entries:
        ft_raw.extend(struct.pack('<10I',
            e['flag'], e['index'], e['block_size'], 0,
            e['file_size'], 0, e['raw_size'], 0,
            e['offset'], 0))
    ft_zlib = zlib.compress(bytes(ft_raw))

    m2h_data = base64.b64encode(csv_zlib + ft_zlib)
    m2h_path = os.path.join(output_dir, cfg['csv_name'])
    with open(m2h_path, 'wb') as f:
        f.write(m2h_data)

    total_m2d = sum(
        os.path.getsize(os.path.join(output_dir, f'{m2d_prefix_str}{build_m2d_id(m2d_prefix_str, i)}.m2d'))
        for i in range(len(file_list))
    )

    print(f'\n{"="*60}')
    print(f'Packed {resource_name}:')
    print(f'  Files: {len(file_list)}')
    print(f'  M2D archives: {len(file_list)} (1 per file)')
    print(f'  M2D total: {total_m2d / (1024*1024):.1f} MB')
    print(f'  M2H: {os.path.getsize(m2h_path) / 1024:.1f} KB')
    print(f'  Output: {output_dir}')
    print(f'{"="*60)}')

# ── Main ────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='MapleStory2 M2D/M2H Repacker')
    parser.add_argument('--input', '-i', required=True, help='Input directory with files to pack')
    parser.add_argument('--resource', '-r', required=True,
                        choices=['Image','Exported','Map','Effect','Item','Npc','Textures','Movie'],
                        help='Resource type')
    parser.add_argument('--output', '-o', default='./packed', help='Output directory')
    parser.add_argument('--max-m2d-size', type=int, default=500,
                        help='Max M2D file size in MB (OS2F only, default 500)')
    parser.add_argument('--m2d-prefix', default=None,
                        help='Custom M2D filename prefix (default: auto from resource)')
    args = parser.parse_args()

    if not os.path.isdir(args.input):
        print(f'Error: Input directory not found: {args.input}'); sys.exit(1)
    os.makedirs(args.output, exist_ok=True)

    if not os.path.exists(KEYS_FILE):
        print(f'Error: Keys file not found: {KEYS_FILE}'); sys.exit(1)

    with open(KEYS_FILE) as f:
        k = json.load(f)
    osk = [bytes(kk) for kk in k['OS2F_USER_KEY']]
    oiv = [bytes(iv) for iv in k['OS2F_IV_CHAIN']]
    psk_list = k.get('PS2F_XOR_KEY', [])
    psk_xor = bytes(psk_list) * 4 if psk_list else b''

    print(f'Input: {args.input}')
    print(f'Output: {args.output}')
    print(f'Resource: {args.resource}')

    if args.resource in OS2F_RESOURCES:
        pack_os2f(args.input, args.resource, OS2F_RESOURCES[args.resource],
                  args.output, osk, oiv, args.m2d_prefix, args.max_m2d_size)
    elif args.resource in PS2F_RESOURCES:
        if not psk_xor:
            print('Error: PS2F_XOR_KEY not found in keys file'); sys.exit(1)
        pack_ps2f(args.input, args.resource, PS2F_RESOURCES[args.resource],
                  args.output, psk_xor, args.m2d_prefix)

if __name__ == '__main__':
    main()
