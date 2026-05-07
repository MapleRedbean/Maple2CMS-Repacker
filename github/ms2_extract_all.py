# -*- coding: utf-8 -*-
"""
MapleStory2 M2D Universal Extractor v7 (Orion2-Compliant)
==========================================================
Based on Orion2-Repacker2026 source code analysis.
Full PackStreamVer1/2/3 parsing — no pre-decrypted FT/CSV needed.

Universal key formula: key_index = compressed_size & 0x7F
  - For OS2F: compressed_size = len(base64_decode(block))
  - For MS2F: compressed_size = CompressedHeaderSize from M2H
  - For NS2F: compressed_size = CompressedHeaderSize from M2H

Usage:
  pip install pycryptodome tqdm
  python ms2_extract_all.py -r all -d "D:\WeGameApps\冒险岛2\Client\Data" -o ./output
"""

import struct, base64, zlib, json, os, sys, argparse
from collections import defaultdict
from io import BytesIO

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    def tqdm(iterable, **kw): return iterable

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_FILE = os.path.join(SCRIPT_DIR, 'orion2_keys.json')


# ══════════════════════════════════════════════════════════════════════════
# Crypto primitives
# ══════════════════════════════════════════════════════════════════════════

def aes_ctr_ecb(key, iv, data):
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

def xor_decrypt(data, xor_key):
    result = bytearray(data)
    n_blocks = len(data) >> 2
    for i in range(n_blocks):
        kw = struct.unpack_from('<I', xor_key, (i & 0x1FF) * 4)[0]
        dw = struct.unpack_from('<I', result, i * 4)[0]
        struct.pack_into('<I', result, i * 4, dw ^ kw)
    rem_start = n_blocks * 4
    for i in range(len(data) - rem_start):
        result[rem_start + i] ^= xor_key[i & 0x7FF]
    return bytes(result)


# ══════════════════════════════════════════════════════════════════════════
# Orion2 PackVer magic numbers
# ══════════════════════════════════════════════════════════════════════════

MS2F_MAGIC = 0x4632534D  # 'MS2F' -> Ver1
NS2F_MAGIC = 0x4632534E  # 'NS2F' -> Ver2
OS2F_MAGIC = 0x4632534F  # 'OS2F' -> Ver3
PS2F_MAGIC = 0x46325350  # 'PS2F' -> Ver3

# Buffer flags (CryptoMan.BufferManipulation)
AES_ZLIB = 0xEE000009  # Standard: base64 + AES + zlib
XOR     = 0xFF000000   # Alternative: XOR only (Movie)
XOR_ZLIB= 0xFF000009   # XOR + zlib (Movie with compression)


# ══════════════════════════════════════════════════════════════════════════
# PackStream header parsers
# ══════════════════════════════════════════════════════════════════════════

def parse_stream_v1(data, offset):
    """Parse PackStreamVer1 header (MS2F)."""
    r = {}
    r['uReserved'] = struct.unpack_from('<I', data, offset)[0]; offset += 4
    r['CompressedDataSize'] = struct.unpack_from('<Q', data, offset)[0]; offset += 8
    r['EncodedDataSize'] = struct.unpack_from('<Q', data, offset)[0]; offset += 8
    r['HeaderSize'] = struct.unpack_from('<Q', data, offset)[0]; offset += 8
    r['CompressedHeaderSize'] = struct.unpack_from('<Q', data, offset)[0]; offset += 8
    r['EncodedHeaderSize'] = struct.unpack_from('<Q', data, offset)[0]; offset += 8
    r['FileListCount'] = struct.unpack_from('<Q', data, offset)[0]; offset += 8
    r['DataSize'] = struct.unpack_from('<Q', data, offset)[0]; offset += 8
    r['_next'] = offset
    return r

def parse_stream_v2(data, offset):
    """Parse PackStreamVer2 header (NS2F)."""
    r = {}
    r['FileListCount'] = struct.unpack_from('<I', data, offset)[0]; offset += 4
    r['CompressedDataSize'] = struct.unpack_from('<Q', data, offset)[0]; offset += 8
    r['EncodedDataSize'] = struct.unpack_from('<Q', data, offset)[0]; offset += 8
    r['HeaderSize'] = struct.unpack_from('<Q', data, offset)[0]; offset += 8
    r['CompressedHeaderSize'] = struct.unpack_from('<Q', data, offset)[0]; offset += 8
    r['EncodedHeaderSize'] = struct.unpack_from('<Q', data, offset)[0]; offset += 8
    r['DataSize'] = struct.unpack_from('<Q', data, offset)[0]; offset += 8
    r['_next'] = offset
    return r

def parse_filetable_ver1(data, count):
    """Parse PackFileHeaderVer1 entries (48 bytes each, MS2F)."""
    entries = []
    offset = 0
    for _ in range(count):
        e = {}
        e['aPackingDef'] = data[offset:offset+4]; offset += 4
        e['FileIndex'] = struct.unpack_from('<i', data, offset)[0]; offset += 4
        e['BufferFlag'] = struct.unpack_from('<I', data, offset)[0]; offset += 4
        e['Reserved0']  = struct.unpack_from('<i', data, offset)[0]; offset += 4
        e['Offset'] = struct.unpack_from('<Q', data, offset)[0]; offset += 8
        e['EncodedFileSize'] = struct.unpack_from('<I', data, offset)[0]; offset += 4
        e['Reserved1'] = struct.unpack_from('<i', data, offset)[0]; offset += 4
        e['CompressedFileSize'] = struct.unpack_from('<Q', data, offset)[0]; offset += 8
        e['FileSize'] = struct.unpack_from('<Q', data, offset)[0]; offset += 8
        entries.append(e)
    return entries

def parse_filetable_ver2(data, count):
    """Parse PackFileHeaderVer2 entries (44 bytes each, NS2F)."""
    entries = []
    offset = 0
    for _ in range(count):
        e = {}
        e['BufferFlag'] = struct.unpack_from('<I', data, offset)[0]; offset += 4
        e['FileIndex'] = struct.unpack_from('<i', data, offset)[0]; offset += 4
        e['EncodedFileSize'] = struct.unpack_from('<I', data, offset)[0]; offset += 4
        e['CompressedFileSize'] = struct.unpack_from('<Q', data, offset)[0]; offset += 8
        e['FileSize'] = struct.unpack_from('<Q', data, offset)[0]; offset += 8
        e['Offset'] = struct.unpack_from('<Q', data, offset)[0]; offset += 8
        entries.append(e)
    return entries

def parse_filetable_ver3(data, count):
    """Parse PackFileHeaderVer3 entries (40 bytes each, OS2F)."""
    entries = []
    offset = 0
    for _ in range(count):
        vals = struct.unpack_from('<10I', data, offset)
        e = {
            'BufferFlag': vals[0], 'FileIndex': vals[1],
            'EncodedFileSize': vals[2], 'Reserved': vals[3],
            'FileSize': vals[4], 'OffsetHi': vals[5],
            'OffsetLo': vals[6], 'CompressedFileSizeLo': vals[7],
            'CompressedFileSizeHi': vals[8],
        }
        offset += 40
        entries.append(e)
    return entries


# ══════════════════════════════════════════════════════════════════════════
# Orion2 decrypt: base64 → AES → zlib
# ══════════════════════════════════════════════════════════════════════════

def decrypt_orion2_block(uVer, compressed_size, dwBufferFlag, pSrc, key_table, iv_table):
    """Orion2 Decrypt routine: base64 → AES → zlib."""
    bits = struct.pack('<I', dwBufferFlag)
    if (bits[3] & 1) == 0:
        # AES path
        ki = compressed_size & 0x7F
        key = key_table[ki]
        iv = iv_table[ki]
        decoded = base64.b64decode(pSrc)
        decrypted = aes_ctr_ecb(key, iv, decoded)
    else:
        # XOR path
        decoded = pSrc  # No base64
        # XOR key handling
        decrypted = decoded  # placeholder, handle XOR separately

    # zlib decompress if flag byte[0] != 0
    if bits[0] != 0:
        return zlib.decompress(decrypted)
    return decrypted


# ══════════════════════════════════════════════════════════════════════════
# OS2F extraction (Ver3) — multi M2D files
# ══════════════════════════════════════════════════════════════════════════

OS2F_RESOURCES = {
    'Image':    {'csv':'Image.m2h.header','ft':'filetable_decrypted.bin','prefix':'Image_','subdir':''},
    'Exported': {'csv':'Exported.m2h.header','ft':'Exported.filetable.decrypted.bin','prefix':'Exported_','subdir':''},
    'Map':      {'csv':'Map.m2h.header','ft':'Map.filetable.decrypted_v2.bin','prefix':'Map_','subdir':'Model'},
    'Effect':   {'csv':'Effect.m2h.header','ft':'Effect.filetable.decrypted_v2.bin','prefix':'Effect_','subdir':'Model'},
    'Item':     {'csv':'Item.m2h.header','ft':'Item.filetable.decrypted_v2.bin','prefix':'Item_','subdir':'Model'},
    'Npc':      {'csv':'Npc_02.header','ft':'Npc_02.filetable.decrypted_v2.bin','prefix':'Npc_','subdir':'Model'},
    'Textures': {'csv':'Textures.m2h.header','ft':'Textures.filetable.decrypted_v2.bin','prefix':'Textures_','subdir':'Model'},
}

def load_predecrypted_ft(path):
    with open(os.path.join(SCRIPT_DIR, path), 'rb') as f:
        data = f.read()
    entries = []
    for i in range(0, len(data), 40):
        v = struct.unpack_from('<10I', data, i)
        entries.append({'flag':v[0],'index':v[1],'block_size':v[2],'file_size':v[4],'raw_size':v[6],'offset':v[8]})
    return entries

def load_predecrypted_csv(path):
    with open(os.path.join(SCRIPT_DIR, path), 'rb') as f:
        data = f.read()
    entries = []
    for line in data.split(b'\n'):
        line = line.strip()
        if not line: continue
        parts = line.split(b',')
        if len(parts) >= 3:
            entries.append((int(parts[0]), parts[1].decode(), parts[2].decode('utf-8', errors='replace')))
    return entries

def extract_os2f(name, cfg, data_dir, output_dir, osk, oiv):
    csv_path = os.path.join(SCRIPT_DIR, cfg['csv'])
    ft_path = os.path.join(SCRIPT_DIR, cfg['ft'])
    sub = cfg['subdir']
    res_dir = os.path.join(data_dir, 'Resource', sub) if sub else os.path.join(data_dir, 'Resource')
    if not os.path.exists(csv_path) or not os.path.exists(ft_path):
        print(f'  [!] Missing: {cfg["csv"]} / {cfg["ft"]}')
        return 0, 0

    csv_entries = load_predecrypted_csv(cfg['csv'])
    ft_entries = load_predecrypted_ft(cfg['ft'])
    files_by_m2d = defaultdict(list)
    for i, e in enumerate(ft_entries):
        if i >= len(csv_entries): break
        idx, m2d_id, path = csv_entries[i]
        files_by_m2d[m2d_id].append((idx, path, e))

    out_dir = os.path.join(output_dir, 'Resource', sub, name) if sub else os.path.join(output_dir, 'Resource', name)
    os.makedirs(out_dir, exist_ok=True)
    print(f'\n{"="*60}')
    print(f'{name} (OS2F): {len(ft_entries)} files, {len(files_by_m2d)} M2Ds -> {out_dir}')
    print(f'{"="*60}')

    ok_total = bad_total = 0
    m2d_list = sorted(files_by_m2d.keys())
    it = tqdm(m2d_list, desc=f'  {name}', unit='m2d') if HAS_TQDM else m2d_list

    for m2d_id in it:
        files = files_by_m2d[m2d_id]
        fpath = os.path.join(res_dir, f'{cfg["prefix"]}{m2d_id}.m2d')
        if not os.path.exists(fpath): bad_total += len(files); continue
        with open(fpath, 'rb') as f: m2d = f.read()
        ok = 0
        for idx, rel_path, entry in files:
            off, size = entry['offset'], entry['block_size']
            if off + size > len(m2d): bad_total += 1; continue
            block = m2d[off:off+size]
            clean = block.replace(b'=', b'')
            pad = (4 - len(clean) % 4) % 4
            if pad == 3: bad_total += 1; continue
            try: decoded = base64.b64decode(clean + b'=' * pad)
            except: bad_total += 1; continue
            ki = len(decoded) & 0x7F
            try: dec = aes_ctr_ecb(osk[ki], oiv[ki], decoded)
            except: bad_total += 1; continue
            if dec[0] == 0x78 and dec[1] in (0x01, 0x5E, 0x9C, 0xDA):
                try: dec = zlib.decompress(dec)
                except: bad_total += 1; continue
            op = os.path.join(out_dir, rel_path.replace('/', os.sep))
            os.makedirs(os.path.dirname(op), exist_ok=True)
            with open(op, 'wb') as f: f.write(dec)
            ok += 1
        ok_total += ok; bad_total += len(files) - ok

    total = ok_total + bad_total
    pc = ok_total * 100 // total if total else 0
    print(f'  {name} done: {ok_total}/{total} ({pc}%)')
    return ok_total, bad_total


# ══════════════════════════════════════════════════════════════════════════
# PS2F extraction (Ver3) — XOR keys
# ══════════════════════════════════════════════════════════════════════════

PS2F_RESOURCES = {
    'Movie': {'csv':'Movie.m2h.header','ft':'Movie.filetable.decrypted_v2.bin','prefix':'Movie_','subdir':''},
}

def extract_ps2f(name, cfg, data_dir, output_dir, psk_xor):
    csv_path = os.path.join(SCRIPT_DIR, cfg['csv'])
    ft_path = os.path.join(SCRIPT_DIR, cfg['ft'])
    sub = cfg['subdir']
    res_dir = os.path.join(data_dir, 'Resource', sub) if sub else os.path.join(data_dir, 'Resource')

    csv_entries = load_predecrypted_csv(cfg['csv'])
    ft_entries = load_predecrypted_ft(cfg['ft'])
    csv_m2d_set = {m2d_id for (_, m2d_id, _) in csv_entries}
    size_to_m2d = {}
    if os.path.isdir(res_dir):
        for fname in os.listdir(res_dir):
            if fname.startswith(cfg['prefix']) and fname.endswith('.m2d'):
                mid = fname[len(cfg['prefix']):-4]
                if mid not in csv_m2d_set:
                    fsz = os.path.getsize(os.path.join(res_dir, fname))
                    if fsz not in size_to_m2d: size_to_m2d[fsz] = mid

    extra_from_size = 0
    files_by_m2d = defaultdict(list)
    for i, e in enumerate(ft_entries):
        if i >= len(csv_entries):
            sz = e['block_size']
            if sz in size_to_m2d:
                m2d_id = size_to_m2d[sz]; del size_to_m2d[sz]
                path = f'unknown/unnamed_{i:04d}.usm'; extra_from_size += 1
            else: m2d_id = f'unnamed_{i}'; path = f'unnamed_{i}'
        else: _, m2d_id, path = csv_entries[i]
        files_by_m2d[m2d_id].append((i, path, e))

    out_dir = os.path.join(output_dir, 'Resource', sub, name) if sub else os.path.join(output_dir, 'Resource', name)
    os.makedirs(out_dir, exist_ok=True)
    print(f'\n{"="*60}')
    print(f'{name} (PS2F XOR): {len(ft_entries)} files, {len(files_by_m2d)} M2Ds -> {out_dir}')
    if extra_from_size: print(f'  Size-matched extras: {extra_from_size}')
    print(f'{"="*60}')

    ok_total = bad_total = 0
    m2d_list = sorted(files_by_m2d.keys())
    it = tqdm(m2d_list, desc=f'  {name}', unit='m2d') if HAS_TQDM else m2d_list

    for m2d_id in it:
        files = files_by_m2d[m2d_id]
        fpath = os.path.join(res_dir, f'{cfg["prefix"]}{m2d_id}.m2d')
        if not os.path.exists(fpath): bad_total += len(files); continue
        ok = 0
        for idx, rel_path, entry in files:
            off, size, flag = entry['offset'], entry['block_size'], entry['flag']
            if flag not in (0xFF000000, 0xFF000009): bad_total += 1; continue
            with open(fpath, 'rb') as f: f.seek(off); block = f.read(size)
            dec = xor_decrypt(block, psk_xor)
            if flag == 0xFF000009:
                if dec[0] == 0x78 and dec[1] in (0x01, 0x5E, 0x9C, 0xDA):
                    try: dec = zlib.decompress(dec)
                    except: bad_total += 1; continue
                else: bad_total += 1; continue
            op = os.path.join(out_dir, rel_path.replace('/', os.sep))
            os.makedirs(os.path.dirname(op), exist_ok=True)
            with open(op, 'wb') as f: f.write(dec)
            ok += 1
        ok_total += ok; bad_total += len(files) - ok

    total = ok_total + bad_total
    pc = ok_total * 100 // total if total else 0
    print(f'  {name} done: {ok_total}/{total} ({pc}%)')
    return ok_total, bad_total


# ══════════════════════════════════════════════════════════════════════════
# MS2F/NS2F extraction (Ver1/Ver2) — single M2D+M2H pair, multi-file
# ══════════════════════════════════════════════════════════════════════════

PACKSTREAM_RESOURCES = {
    'Gfx': {'magic': MS2F_MAGIC, 'subdir': '', 'ver': 1},
    'Xml': {'magic': NS2F_MAGIC, 'subdir': '', 'ver': 2, 'data_root': True},
    # Previously misclassified as single-file; all are multi-file PackStreamVer1
    'Shaders': {'magic': MS2F_MAGIC, 'subdir': '', 'ver': 1},
    'asset-web-config': {'magic': MS2F_MAGIC, 'subdir': '', 'ver': 1},
    'asset-web-metadata': {'magic': MS2F_MAGIC, 'subdir': '', 'ver': 1},
    'Library': {'magic': MS2F_MAGIC, 'subdir': '', 'ver': 1},
    'PrecomputedTerrain': {'magic': MS2F_MAGIC, 'subdir': '', 'ver': 1},
}

def extract_packstream(name, cfg, data_dir, output_dir, osk, oiv, msk, miv, nsk, niv):
    """Extract Orion2 PackStreamVer1/2 resources with full M2H → M2D pipeline."""
    if cfg.get('data_root'):
        res_dir = data_dir
    else:
        sub = cfg['subdir']
        res_dir = os.path.join(data_dir, 'Resource', sub) if sub else os.path.join(data_dir, 'Resource')
    ver = cfg['ver']

    m2h_path = os.path.join(res_dir, f'{name}.m2h')
    m2d_path = os.path.join(res_dir, f'{name}.m2d')

    if not os.path.exists(m2h_path) or not os.path.exists(m2d_path):
        print(f'  [!] {name}: M2H/M2D not found')
        return 0, 0

    with open(m2h_path, 'rb') as f: m2h_data = f.read()
    magic = struct.unpack_from('<I', m2h_data, 0)[0]
    if magic != cfg['magic']:
        print(f'  [!] {name}: Expected 0x{cfg["magic"]:08X}, got 0x{magic:08X}')
        return 0, 1

    # Parse stream header
    off = 4
    if ver == 1:
        hdr = parse_stream_v1(m2h_data, off)
        ft_parser = parse_filetable_ver1
    else:
        hdr = parse_stream_v2(m2h_data, off)
        ft_parser = parse_filetable_ver2

    off = hdr['_next']

    # Select key tables
    if ver == 1:
        key_tab = msk; iv_tab = miv
    elif ver == 2:
        key_tab = nsk; iv_tab = niv
    else:
        key_tab = osk; iv_tab = oiv

    # Decrypt file string (CSV)
    enc_csv_data = m2h_data[off:off + hdr['EncodedHeaderSize']]
    off += hdr['EncodedHeaderSize']
    csv_ki = hdr['CompressedHeaderSize'] & 0x7F
    csv_decoded = base64.b64decode(enc_csv_data)
    csv_decrypted = aes_ctr_ecb(key_tab[csv_ki], iv_tab[csv_ki], csv_decoded)
    csv_text = zlib.decompress(csv_decrypted).decode('utf-8', errors='replace')
    print(f'  CSV: compressed={hdr["CompressedHeaderSize"]} key={csv_ki} uncompressed={len(csv_text)}B {hdr["FileListCount"]} files')

    # Parse CSV
    file_names = {}
    for line in csv_text.split('\r\n'):
        line = line.strip()
        if not line: continue
        parts = line.split(',')
        if len(parts) >= 2:
            idx = int(parts[0])
            nm = parts[-1] if len(parts) <= 2 else parts[2]
            file_names[idx] = nm

    # Decrypt file table
    enc_ft_data = m2h_data[off:off + hdr['EncodedDataSize']]
    ft_ki = hdr['CompressedDataSize'] & 0x7F
    ft_decoded = base64.b64decode(enc_ft_data)
    ft_decrypted = aes_ctr_ecb(key_tab[ft_ki], iv_tab[ft_ki], ft_decoded)
    ft_raw = zlib.decompress(ft_decrypted)
    ft_entries = ft_parser(ft_raw, hdr['FileListCount'])
    print(f'  FT: compressed={hdr["CompressedDataSize"]} key={ft_ki} raw={len(ft_raw)}B {len(ft_entries)} entries')

    # Memory-map M2D
    m2d_size = os.path.getsize(m2d_path)
    if cfg.get('data_root'):
        out_dir = os.path.join(output_dir, 'Data', name)
    else:
        out_dir = os.path.join(output_dir, 'Resource', cfg['subdir'], name) if cfg['subdir'] else os.path.join(output_dir, 'Resource', name)
    os.makedirs(out_dir, exist_ok=True)

    print(f'  M2D: {m2d_size//1024} KB, extracting to {out_dir}')

    # Open M2D once, seek for each file
    ok = bad = 0
    with open(m2d_path, 'rb') as m2d_f:
        it = tqdm(ft_entries, desc=f'  {name}', unit='file') if HAS_TQDM else ft_entries
        for entry in it:
            idx = entry['FileIndex']
            encoded_sz = entry['EncodedFileSize']
            comp_sz = entry['CompressedFileSize']
            file_sz = entry['FileSize']
            buf_flag = entry['BufferFlag']
            off_m2d = entry['Offset']

            if encoded_sz == 0 or comp_sz == 0:
                bad += 1; continue

            m2d_f.seek(off_m2d)
            block = m2d_f.read(encoded_sz)

            if len(block) != encoded_sz:
                bad += 1; continue

            try:
                # Decrypt: base64 → AES → zlib
                bits = struct.pack('<I', buf_flag)
                if (bits[3] & 1) == 0:
                    ki = (comp_sz & 0x7F)
                    decoded = base64.b64decode(block)
                    data = aes_ctr_ecb(key_tab[ki], iv_tab[ki], decoded)
                else:
                    data = block  # XOR path (shouldn't happen for MS2F/NS2F)

                if bits[0] != 0:
                    data = zlib.decompress(data)
            except Exception:
                bad += 1; continue

            path = file_names.get(idx, f'unnamed_{idx}')
            op = os.path.join(out_dir, path.replace('/', os.sep))
            os.makedirs(os.path.dirname(op), exist_ok=True)
            with open(op, 'wb') as f: f.write(data)
            ok += 1

    total = ok + bad
    pc = ok * 100 // total if total else 0
    print(f'  {name} done: {ok}/{total} ({pc}%)')
    return ok, bad


# ══════════════════════════════════════════════════════════════════════════
# MS2F single-file (trivial — entire M2D is one file)
# ══════════════════════════════════════════════════════════════════════════

MS2F_SINGLE = {
    # All moved to PACKSTREAM_RESOURCES (multi-file PackStreamVer1)
}

def extract_ms2f_single(name, cfg, data_dir, output_dir, msk, miv):
    """Extract single-file MS2F resource (entire M2D = one base64 block)."""
    base = os.path.join(data_dir, 'Resource')
    res_dir = os.path.join(base, cfg['subdir']) if cfg['subdir'] else base
    m2d_path = os.path.join(res_dir, f'{name}.m2d')

    if not os.path.exists(m2d_path):
        print(f'  [!] {name}.m2d not found')
        return 0, 1

    with open(m2d_path, 'rb') as f: raw = f.read()
    out_dir = os.path.join(output_dir, 'Resource', name)
    os.makedirs(out_dir, exist_ok=True)

    try:
        decoded = base64.b64decode(raw)
        ki = len(decoded) & 0x7F
        dec = aes_ctr_ecb(msk[ki], miv[ki], decoded)
        if dec[0] == 0x78 and dec[1] in (0x01, 0x5E, 0x9C, 0xDA):
            dec = zlib.decompress(dec)
    except Exception as e:
        print(f'  [!] {name}: {e}')
        return 0, 1

    out_path = os.path.join(out_dir, f'{name}{cfg["ext"]}')
    with open(out_path, 'wb') as f: f.write(dec)
    print(f'  {name} (MS2F key {ki}): {len(raw)//1024} KB -> {len(dec)//1024} KB')
    return 1, 0


# ══════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description='MapleStory2 M2D Universal Extractor v7 (Orion2-compliant)')
    choices = ['all','Image','Exported','Map','Effect','Item','Npc','Textures','Movie',
               'asset-web-config','asset-web-metadata','Gfx','Library','Shaders',
               'PrecomputedTerrain','Xml']
    parser.add_argument('--resource','-r', choices=choices, default='all')
    parser.add_argument('--data-dir','-d', default=r'D:\WeGameApps\冒险岛2\Client\Data')
    parser.add_argument('--output-dir','-o', default=None)
    args = parser.parse_args()

    if not os.path.isdir(args.data_dir):
        print(f'Error: Data directory not found'); sys.exit(1)
    if args.output_dir is None:
        args.output_dir = os.path.join(SCRIPT_DIR, 'extracted')
    if not os.path.exists(KEYS_FILE):
        print(f'Error: {KEYS_FILE} not found'); sys.exit(1)

    with open(KEYS_FILE) as f: k = json.load(f)
    osk = [bytes(kk) for kk in k['OS2F_USER_KEY']]
    oiv = [bytes(iv) for iv in k['OS2F_IV_CHAIN']]
    psk_xor = bytes(k.get('PS2F_XOR_KEY', [])) * 4
    msk = [bytes(kk) for kk in k['MS2F_USER_KEY']]
    miv = [bytes(iv) for iv in k['MS2F_IV_CHAIN']]
    nsk = [bytes(kk) for kk in k['NS2F_USER_KEY']]
    niv = [bytes(iv) for iv in k['NS2F_IV_CHAIN']]

    r = args.resource
    is_all = r == 'all'

    if is_all:
        print(f'Data: {args.data_dir}')
        print(f'Output: {args.output_dir}')
        print(f'Engine: Orion2 PackStreamVer 1/2/3, key = compressed_size & 0x7F')
        if not HAS_TQDM: print('(pip install tqdm for progress bars)')

    grand_ok = grand_bad = 0

    # OS2F
    for name in OS2F_RESOURCES:
        if not (is_all or r == name): continue
        ok, bad = extract_os2f(name, OS2F_RESOURCES[name], args.data_dir, args.output_dir, osk, oiv)
        grand_ok += ok; grand_bad += bad

    # PS2F
    for name in PS2F_RESOURCES:
        if not (is_all or r == name): continue
        if not psk_xor: print(f'  [!] PS2F_XOR_KEY missing, skip {name}'); continue
        ok, bad = extract_ps2f(name, PS2F_RESOURCES[name], args.data_dir, args.output_dir, psk_xor)
        grand_ok += ok; grand_bad += bad

    # MS2F single-file
    for name, cfg in MS2F_SINGLE.items():
        if not (is_all or r == name): continue
        ok, bad = extract_ms2f_single(name, cfg, args.data_dir, args.output_dir, msk, miv)
        grand_ok += ok; grand_bad += bad

    # PackStream (Gfx, Xml)
    for name, cfg in PACKSTREAM_RESOURCES.items():
        if not (is_all or r == name): continue
        ok, bad = extract_packstream(name, cfg, args.data_dir, args.output_dir, osk, oiv, msk, miv, nsk, niv)
        grand_ok += ok; grand_bad += bad

    total = grand_ok + grand_bad
    print(f'\n{"="*60}')
    print(f'ALL DONE: {grand_ok}/{total} files extracted')
    if grand_bad: print(f'  Failed: {grand_bad}')
    print(f'{"="*60}')

if __name__ == '__main__':
    main()
