#!/usr/bin/env python3
"""
MapleStory2 Interactive Repacker
=================================
Interactive tool to repack extracted/modified files back into M2D/M2H archives.
Supports: OS2F, PS2F, MS2F PackStreamVer1, NS2F PackStreamVer2.

Usage: python ms2_interactive_pack.py
"""

import os, sys, struct, json, base64, zlib, hashlib

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
try:
    from tqdm import tqdm as _tqdm
    HAS_TQDM = True
except ImportError:
    _tqdm = lambda it, **kw: it
    HAS_TQDM = False

KEYS_FILE = os.path.join(SCRIPT_DIR, 'orion2_keys.json')

# ── Colors ───────────────────────────────────────────────────────────
class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
    M = '\033[95m'; C = '\033[96m'; W = '\033[1m'; X = '\033[0m'

def ok(t):    print(f"  {C.G}[OK]{C.X} {t}")
def warn(t):  print(f"  {C.Y}[!]{C.X} {t}")
def info(t):  print(f"  {C.B}[i]{C.X} {t}")
def err(t):   print(f"  {C.R}[X]{C.X} {t}")
def header(t): print(f"\n{C.W}{'='*60}{C.X}\n{C.W}  {t}{C.X}\n{C.W}{'='*60}{C.X}\n")

# ── Crypto ────────────────────────────────────────────────────────────
def aes_ctr_ecb_encrypt(key, iv, data):
    """AES-CTR using ECB mode (matches Orion2's AESCipher)."""
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_ECB)
    result = bytearray()
    counter = bytearray(iv)  # IV is the initial counter
    for i in range(0, len(data), 16):
        xor_block = cipher.encrypt(bytes(counter))
        for j in range(16):
            if i + j >= len(data):
                break
            result.append(data[i + j] ^ xor_block[j])
        # Big-endian 128-bit counter increment (matches Orion2)
        for j in range(15, -1, -1):
            counter[j] = (counter[j] + 1) & 0xFF
            if counter[j] != 0:
                break
    return bytes(result)

def xor_encrypt(data, xor_key):
    return bytes(d ^ xor_key[i % len(xor_key)] for i, d in enumerate(data))

MS2F_MAGIC = 0x4632534D
NS2F_MAGIC = 0x4632534E
AES_ZLIB = 0xEE000009

# ── Resource Config ───────────────────────────────────────────────────

# Resources that can be packed as either OS2F (multi-M2D) or MS2F (single M2D)
CONVERTIBLE_TO_MS2F = {'Image', 'Exported', 'Map', 'Effect', 'Item', 'Npc', 'Textures', 'Movie', 'Xml'}

OS2F_RESOURCES = {
    'Image':    {'prefix': 'Image_',    'csv_name': 'Image.m2h',    'target': 'Resource'},
    'Exported': {'prefix': 'Exported_', 'csv_name': 'Exported.m2h', 'target': 'Resource'},
    'Map':      {'prefix': 'Map_',      'csv_name': 'Map.m2h',      'target': 'Resource/Model'},
    'Effect':   {'prefix': 'Effect_',   'csv_name': 'Effect.m2h',   'target': 'Resource/Model'},
    'Item':     {'prefix': 'Item_',     'csv_name': 'Item.m2h',     'target': 'Resource/Model'},
    'Npc':      {'prefix': 'Npc_',      'csv_name': 'Npc_02.m2h',   'target': 'Resource/Model'},
    'Textures': {'prefix': 'Textures_', 'csv_name': 'Textures.m2h', 'target': 'Resource/Model'},
}

PS2F_RESOURCES = {
    'Movie': {'prefix': 'Movie_', 'csv_name': 'Movie.m2h', 'target': 'Resource'},
}

MS2F_STREAM_RESOURCES = {
    'Gfx':      {'prefix': 'Gfx',       'magic': MS2F_MAGIC, 'target': 'Resource'},
    'Shaders':  {'prefix': 'Shaders',   'magic': MS2F_MAGIC, 'target': 'Resource'},
    'Library':  {'prefix': 'Library',   'magic': MS2F_MAGIC, 'target': 'Resource'},
    'PrecomputedTerrain': {'prefix': 'PrecomputedTerrain', 'magic': MS2F_MAGIC, 'target': 'Resource'},
    'asset-web-config':   {'prefix': 'asset-web-config',   'magic': MS2F_MAGIC, 'target': 'Resource'},
    'asset-web-metadata': {'prefix': 'asset-web-metadata', 'magic': MS2F_MAGIC, 'target': 'Resource'},
    'Camera':   {'prefix': 'Camera',    'magic': MS2F_MAGIC, 'target': 'Resource'},
    'Character':{'prefix': 'Character', 'magic': MS2F_MAGIC, 'target': 'Resource'},
    'Common':   {'prefix': 'Common',    'magic': MS2F_MAGIC, 'target': 'Resource'},
    'Emotion':  {'prefix': 'Emotion',   'magic': MS2F_MAGIC, 'target': 'Resource'},
    'Path':     {'prefix': 'Path',      'magic': MS2F_MAGIC, 'target': 'Resource/Model'},
    'Precompiled':{'prefix': 'Precompiled','magic': MS2F_MAGIC, 'target': 'lua'},
    'Tool':     {'prefix': 'Tool',      'magic': MS2F_MAGIC, 'target': 'Resource/Model'},
    'Npc':      {'prefix': 'Npc',       'magic': MS2F_MAGIC, 'target': 'Resource/Model'},
    'Image':    {'prefix': 'Image',     'magic': MS2F_MAGIC, 'target': 'Resource'},
    'Exported': {'prefix': 'Exported',  'magic': MS2F_MAGIC, 'target': 'Resource'},
    'Map':      {'prefix': 'Map',       'magic': MS2F_MAGIC, 'target': 'Resource/Model'},
    'Effect':   {'prefix': 'Effect',    'magic': MS2F_MAGIC, 'target': 'Resource/Model'},
    'Item':     {'prefix': 'Item',      'magic': MS2F_MAGIC, 'target': 'Resource/Model'},
    'Textures': {'prefix': 'Textures',  'magic': MS2F_MAGIC, 'target': 'Resource/Model'},
    'Movie':    {'prefix': 'Movie',     'magic': MS2F_MAGIC, 'target': 'Resource'},
    'common':   {'prefix': 'common',    'magic': MS2F_MAGIC, 'target': 'Resource'},
    'emotion':  {'prefix': 'emotion',   'magic': MS2F_MAGIC, 'target': 'Resource'},
    'item':     {'prefix': 'item',      'magic': MS2F_MAGIC, 'target': 'Resource'},
    'Xml':      {'prefix': 'Xml',       'magic': MS2F_MAGIC, 'target': ''},
}

NS2F_RESOURCES = {
    'Xml': {'prefix': 'Xml', 'magic': NS2F_MAGIC, 'target': ''},
}

# ── Helpers ───────────────────────────────────────────────────────────
def fmt_size(b):
    if b >= 1024*1024*1024: return f'{b/(1024**3):.1f} GB'
    if b >= 1024*1024: return f'{b/(1024**2):.1f} MB'
    if b >= 1024: return f'{b/1024:.0f} KB'
    return f'{b} B'

def collect_files(input_dir):
    file_list = []
    for root, dirs, files in os.walk(input_dir):
        for f in files:
            full = os.path.join(root, f)
            rel = os.path.relpath(full, input_dir).replace('\\', '/')
            file_list.append((rel, full))
    file_list.sort(key=lambda x: x[0])
    return file_list

def load_keys():
    if not os.path.exists(KEYS_FILE):
        err(f"Key file not found: {KEYS_FILE}")
        sys.exit(1)
    with open(KEYS_FILE) as f: k = json.load(f)
    return {
        'osk': [bytes(kk) for kk in k['OS2F_USER_KEY']],
        'oiv': [bytes(iv) for iv in k['OS2F_IV_CHAIN']],
        'msk': [bytes(kk) for kk in k['MS2F_USER_KEY']],
        'miv': [bytes(iv) for iv in k['MS2F_IV_CHAIN']],
        'nsk': [bytes(kk) for kk in k['NS2F_USER_KEY']],
        'niv': [bytes(iv) for iv in k['NS2F_IV_CHAIN']],
        'psk': bytes(k.get('PS2F_XOR_KEY', [])) * 4,
    }

# ── Pack: OS2F ────────────────────────────────────────────────────────
def pack_os2f_resource(r, keys, output_dir, max_m2d_mb=200):
    """Pack an OS2F resource (multi-M2D volumes)."""
    name = r['name']
    cfg = r['cfg']
    prefix = cfg['prefix']
    input_dir = r['input_dir']
    osk = keys['osk']
    oiv = keys['oiv']

    files = collect_files(input_dir)
    info(f"Collected {len(files)} files")

    # Assign files to volumes
    m2d_index = 0
    m2d_blocks = []  # (rel_path, block_bytes)
    m2d_size = 0
    all_m2d = []
    max_bytes = max_m2d_mb * 1024 * 1024

    for rel_path, full_path in _tqdm(files, desc=f"{name}", unit="file"):
        with open(full_path, 'rb') as f:
            data = f.read()
        compressed = zlib.compress(data)
        ki = len(compressed) & 0x7F
        encrypted = aes_ctr_ecb_encrypt(osk[ki], oiv[ki], compressed)
        encoded = base64.b64encode(encrypted).decode('ascii') + '='
        block = encoded.encode('ascii')

        if m2d_blocks and m2d_size + len(block) > max_bytes:
            all_m2d.append((m2d_index, m2d_blocks))
            m2d_index += 1
            m2d_blocks = []
            m2d_size = 0
        m2d_blocks.append((rel_path, block))
        m2d_size += len(block)

    if m2d_blocks:
        all_m2d.append((m2d_index, m2d_blocks))

    # Load original CSV
    csv_path = os.path.join(SCRIPT_DIR, f'{cfg["csv_name"]}.header')
    orig_ids = {}
    if os.path.exists(csv_path):
        with open(csv_path, 'r', encoding='utf-8') as f:
            for line in f.read().strip().split('\r\n'):
                parts = line.split(',')
                if len(parts) >= 3:
                    orig_ids[parts[2]] = parts[0], parts[1]

    csv_lines = []
    for i, (rel, _) in enumerate(files, 1):
        if rel in orig_ids:
            fid, key = orig_ids[rel]
        else:
            key = hashlib.md5(rel.encode()).hexdigest()[:8]
            fid = i
        csv_lines.append(f'{fid},{key},{rel}')

    csv_text = '\r\n'.join(csv_lines)
    csv_bytes = csv_text.encode('utf-8')
    csv_comp = zlib.compress(csv_bytes)
    csv_ki = len(csv_comp) & 0x7F
    csv_enc = aes_ctr_ecb_encrypt(osk[csv_ki], oiv[csv_ki], csv_comp)
    csv_b64 = base64.b64encode(csv_enc)

    # Build FileTable (OS2F Ver3: 40B entries, PackFileHeaderVer3)
    ft_entries = bytearray()
    file_idx = 0
    for _m2d_idx, m2d_blocks_list in all_m2d:
        offset = 0
        for rel_path, block in m2d_blocks_list:
            file_idx += 1
            full = os.path.join(input_dir, rel_path)
            with open(full, 'rb') as f:
                file_data = f.read()
            compressed = zlib.compress(file_data)
            entry = bytearray(40)
            struct.pack_into('<I', entry, 0, AES_ZLIB)           # dwBufferFlag
            struct.pack_into('<I', entry, 4, file_idx)           # nFileIndex
            struct.pack_into('<I', entry, 8, len(block))         # uEncodedFileSize
            struct.pack_into('<I', entry, 12, 0)                 # Reserved
            struct.pack_into('<Q', entry, 16, len(compressed))   # uCompressedFileSize
            struct.pack_into('<Q', entry, 24, len(file_data))    # uFileSize
            struct.pack_into('<Q', entry, 32, offset)            # uOffset
            ft_entries.extend(entry)
            offset += len(block)

    ft_comp = zlib.compress(bytes(ft_entries))
    ft_ki = len(ft_comp) & 0x7F
    ft_enc = aes_ctr_ecb_encrypt(osk[ft_ki], oiv[ft_ki], ft_comp)
    ft_b64 = base64.b64encode(ft_enc)

    # Write M2H
    os.makedirs(output_dir, exist_ok=True)
    m2h_data = bytearray()
    m2h_data.extend(struct.pack('<I', 0x4632534F))
    m2h_data.extend(struct.pack('<I', len(files)))
    m2h_data.extend(struct.pack('<I', 0))
    m2h_data.extend(struct.pack('<Q', len(ft_comp)))
    m2h_data.extend(struct.pack('<Q', len(ft_b64)))
    m2h_data.extend(struct.pack('<Q', len(csv_comp)))
    m2h_data.extend(struct.pack('<Q', len(csv_b64)))
    m2h_data.extend(struct.pack('<Q', len(ft_entries)))
    m2h_data.extend(struct.pack('<Q', len(csv_bytes)))
    m2h_data.extend(csv_b64)
    m2h_data.extend(ft_b64)

    with open(os.path.join(output_dir, f'{name}.m2h'), 'wb') as f:
        f.write(m2h_data)

    # Write M2Ds
    for m2d_idx, m2d_blocks_list in all_m2d:
        m2d_data = b''.join(b for _, b in m2d_blocks_list)
        m2d_name = f'{prefix}{m2d_idx:04d}.m2d' if not name.startswith('Npc') else f'{prefix}{m2d_idx:02d}.m2d'
        with open(os.path.join(output_dir, m2d_name), 'wb') as f:
            f.write(m2d_data)

    total_m2d = len(all_m2d)
    ok(f"{name}: {len(files)} files -> {total_m2d} M2D volume(s) ({fmt_size(sum(len(b) for _, blocks in all_m2d for _, b in blocks))})")
    return len(files), 0

# ── Pack: PS2F ────────────────────────────────────────────────────────
def pack_ps2f_resource(r, keys, output_dir):
    name = r['name']
    cfg = r['cfg']
    prefix = cfg['prefix']
    input_dir = r['input_dir']
    psk = keys['psk']
    if not psk:
        err(f"{name}: PS2F_XOR_KEY missing")
        return 0, 1

    files = collect_files(input_dir)
    info(f"Collected {len(files)} files")

    max_bytes = 200 * 1024 * 1024
    m2d_index = 0
    m2d_blocks = []
    m2d_size = 0
    all_m2d = []

    for rel_path, full_path in _tqdm(files, desc=f"{name}", unit="file"):
        with open(full_path, 'rb') as f:
            data = f.read()
        compressed = zlib.compress(data)
        encrypted = xor_encrypt(compressed, psk)
        encoded = base64.b64encode(encrypted).decode('ascii') + '='
        block = encoded.encode('ascii')
        if m2d_blocks and m2d_size + len(block) > max_bytes:
            all_m2d.append((m2d_index, b''.join(m2d_blocks)))
            m2d_index += 1
            m2d_blocks = []
            m2d_size = 0
        m2d_blocks.append(block)
        m2d_size += len(block)
    if m2d_blocks:
        all_m2d.append((m2d_index, b''.join(m2d_blocks)))

    os.makedirs(output_dir, exist_ok=True)
    # Build encrypted CSV
    csv_lines = [f'{i+1},0,{f[0]}' for i, f in enumerate(files)]
    csv_raw = '\r\n'.join(csv_lines).encode('utf-8')
    csv_comp = zlib.compress(csv_raw)
    csv_ki = len(csv_comp) & 0x7F
    csv_enc = aes_ctr_ecb_encrypt(keys['osk'][csv_ki], keys['oiv'][csv_ki], csv_comp)
    csv_b64 = base64.b64encode(csv_enc)

    # Build FileTable (OS2F Ver3: 40B entries)
    ft_entries = bytearray()
    m2d_offset = 0
    # Pre-compute all blocks to get accurate sizes
    all_blocks = []
    for rel_path, full_path in files:
        with open(full_path, 'rb') as fh:
            fd = fh.read()
        comp = zlib.compress(fd)
        enc = xor_encrypt(comp, psk)
        b64e = base64.b64encode(enc) + b'='
        all_blocks.append((rel_path, full_path, fd, comp, b64e))
    file_idx = 0
    for rel_path, full_path, fd, comp, b64e in all_blocks:
        file_idx += 1
        entry = bytearray(40)
        # PackFileHeaderVer3 layout:
        struct.pack_into('<I', entry, 0, 0xFF000009)          # dwBufferFlag (XOR_ZLIB)
        struct.pack_into('<I', entry, 4, file_idx)             # nFileIndex
        struct.pack_into('<I', entry, 8, len(b64e))            # uEncodedFileSize
        struct.pack_into('<I', entry, 12, 0)                   # Reserved
        struct.pack_into('<Q', entry, 16, len(comp))           # uCompressedFileSize
        struct.pack_into('<Q', entry, 24, len(fd))             # uFileSize
        struct.pack_into('<Q', entry, 32, m2d_offset)          # uOffset
        ft_entries.extend(entry)
        m2d_offset += len(b64e)

    ft_comp = zlib.compress(bytes(ft_entries))
    ft_ki = len(ft_comp) & 0x7F
    ft_enc = aes_ctr_ecb_encrypt(keys['osk'][ft_ki], keys['oiv'][ft_ki], ft_comp)
    ft_b64 = base64.b64encode(ft_enc)

    m2h_data = bytearray()
    m2h_data.extend(struct.pack('<I', 0x46325350))
    m2h_data.extend(struct.pack('<I', len(files)))
    m2h_data.extend(struct.pack('<I', 0))
    m2h_data.extend(struct.pack('<Q', len(ft_comp)))
    m2h_data.extend(struct.pack('<Q', len(ft_b64)))
    m2h_data.extend(struct.pack('<Q', len(csv_comp)))
    m2h_data.extend(struct.pack('<Q', len(csv_b64)))
    m2h_data.extend(struct.pack('<Q', len(ft_entries)))
    m2h_data.extend(struct.pack('<Q', len(csv_raw)))
    m2h_data.extend(csv_b64)
    m2h_data.extend(ft_b64)
    with open(os.path.join(output_dir, f'{name}.m2h'), 'wb') as f:
        f.write(m2h_data)
    for m2d_idx, m2d_data in all_m2d:
        with open(os.path.join(output_dir, f'{prefix}{m2d_idx:04d}.m2d'), 'wb') as f:
            f.write(m2d_data)
    ok(f"{name}: {len(files)} files -> {len(all_m2d)} M2D volume(s)")
    return len(files), 0

# ── Pack: MS2F PackStreamVer1 ─────────────────────────────────────────
def pack_ms2f_resource(r, keys, output_dir):
    name = r['name']
    cfg = r['cfg']
    prefix = cfg['prefix']
    input_dir = r['input_dir']
    msk = keys['msk']
    miv = keys['miv']

    files = collect_files(input_dir)
    info(f"Collected {len(files)} files")

    csv_lines = []
    for i, (rel_path, _) in enumerate(files, 1):
        key = hashlib.md5(rel_path.encode()).hexdigest()[:8]
        csv_lines.append(f'{i},{key},{rel_path}')
    csv_raw = '\r\n'.join(csv_lines).encode('utf-8')
    csv_comp = zlib.compress(csv_raw)
    csv_ki = len(csv_comp) & 0x7F
    csv_enc = aes_ctr_ecb_encrypt(msk[csv_ki], miv[csv_ki], csv_comp)
    csv_b64 = base64.b64encode(csv_enc)

    ft_entries = bytearray()
    m2d_blocks = []
    m2d_offset = 0

    for rel_path, full_path in _tqdm(files, desc=f"{name}", unit="file"):
        with open(full_path, 'rb') as f:
            file_data = f.read()
        compressed = zlib.compress(file_data)
        file_ki = len(compressed) & 0x7F
        encrypted = aes_ctr_ecb_encrypt(msk[file_ki], miv[file_ki], compressed)
        encoded = base64.b64encode(encrypted)
        m2d_blocks.append(encoded)
        entry = bytearray(48)  # PackFileHeaderVer1 (MS2F uses Ver1, not Ver3)
        struct.pack_into('<I', entry, 0, 0)                   # aPackingDef (unused)
        struct.pack_into('<i', entry, 4, len(m2d_blocks))     # nFileIndex
        struct.pack_into('<I', entry, 8, AES_ZLIB)            # dwBufferFlag
        struct.pack_into('<i', entry, 12, 0)                  # Reserved[0]
        struct.pack_into('<Q', entry, 16, m2d_offset)         # uOffset
        struct.pack_into('<I', entry, 24, len(encoded))       # uEncodedFileSize
        struct.pack_into('<i', entry, 28, 0)                  # Reserved[1]
        struct.pack_into('<Q', entry, 32, len(compressed))    # uCompressedFileSize
        struct.pack_into('<Q', entry, 40, len(file_data))     # uFileSize
        ft_entries.extend(entry)
        m2d_offset += len(encoded)

    ft_comp = zlib.compress(bytes(ft_entries))
    ft_ki = len(ft_comp) & 0x7F
    ft_enc = aes_ctr_ecb_encrypt(msk[ft_ki], miv[ft_ki], ft_comp)
    ft_b64 = base64.b64encode(ft_enc)

    os.makedirs(output_dir, exist_ok=True)
    m2h_data = bytearray()
    m2h_data.extend(struct.pack('<I', MS2F_MAGIC))
    m2h_data.extend(struct.pack('<I', 0))
    m2h_data.extend(struct.pack('<Q', len(ft_comp)))
    m2h_data.extend(struct.pack('<Q', len(ft_b64)))
    m2h_data.extend(struct.pack('<Q', len(csv_raw)))
    m2h_data.extend(struct.pack('<Q', len(csv_comp)))
    m2h_data.extend(struct.pack('<Q', len(csv_b64)))
    m2h_data.extend(struct.pack('<Q', len(files)))
    m2h_data.extend(struct.pack('<Q', len(ft_entries)))
    m2h_data.extend(csv_b64)
    m2h_data.extend(ft_b64)
    with open(os.path.join(output_dir, f'{name}.m2h'), 'wb') as f:
        f.write(m2h_data)

    m2d_data = b''.join(m2d_blocks)
    with open(os.path.join(output_dir, f'{name}.m2d'), 'wb') as f:
        f.write(m2d_data)
    ok(f"{name}: {len(files)} files -> {fmt_size(len(m2d_data))} M2D")
    return len(files), 0

# ── Pack: NS2F PackStreamVer2 ─────────────────────────────────────────
def pack_ns2f_resource(r, keys, output_dir):
    name = r['name']
    cfg = r['cfg']
    input_dir = r['input_dir']
    nsk = keys['nsk']
    niv = keys['niv']

    files = collect_files(input_dir)
    info(f"Collected {len(files)} files")

    csv_lines = []
    for i, (rel_path, _) in enumerate(files, 1):
        key = hashlib.md5(rel_path.encode()).hexdigest()[:8]
        csv_lines.append(f'{i},{key},{rel_path}')
    csv_raw = '\r\n'.join(csv_lines).encode('utf-8')
    csv_comp = zlib.compress(csv_raw)
    csv_ki = len(csv_comp) & 0x7F
    csv_enc = aes_ctr_ecb_encrypt(nsk[csv_ki], niv[csv_ki], csv_comp)
    csv_b64 = base64.b64encode(csv_enc)

    ft_entries = bytearray()
    m2d_blocks = []
    m2d_offset = 0
    for rel_path, full_path in _tqdm(files, desc=f"{name}", unit="file"):
        with open(full_path, 'rb') as f:
            file_data = f.read()
        compressed = zlib.compress(file_data)
        file_ki = len(compressed) & 0x7F
        encrypted = aes_ctr_ecb_encrypt(nsk[file_ki], niv[file_ki], compressed)
        encoded = base64.b64encode(encrypted)
        m2d_blocks.append(encoded)
        entry = bytearray(36)
        struct.pack_into('<I', entry, 0, AES_ZLIB)
        struct.pack_into('<I', entry, 4, len(m2d_blocks))
        struct.pack_into('<I', entry, 8, len(encoded))
        struct.pack_into('<Q', entry, 12, len(compressed))
        struct.pack_into('<Q', entry, 20, len(file_data))
        struct.pack_into('<Q', entry, 28, m2d_offset)
        ft_entries.extend(entry)
        m2d_offset += len(encoded)

    ft_comp = zlib.compress(bytes(ft_entries))
    ft_ki = len(ft_comp) & 0x7F
    ft_enc = aes_ctr_ecb_encrypt(nsk[ft_ki], niv[ft_ki], ft_comp)
    ft_b64 = base64.b64encode(ft_enc)

    os.makedirs(output_dir, exist_ok=True)
    m2h_data = bytearray()
    m2h_data.extend(struct.pack('<I', NS2F_MAGIC))
    m2h_data.extend(struct.pack('<I', len(files)))
    m2h_data.extend(struct.pack('<Q', len(ft_comp)))
    m2h_data.extend(struct.pack('<Q', len(ft_b64)))
    m2h_data.extend(struct.pack('<Q', len(csv_raw)))
    m2h_data.extend(struct.pack('<Q', len(csv_comp)))
    m2h_data.extend(struct.pack('<Q', len(csv_b64)))
    m2h_data.extend(struct.pack('<Q', len(ft_entries)))
    m2h_data.extend(csv_b64)
    m2h_data.extend(ft_b64)
    with open(os.path.join(output_dir, f'{name}.m2h'), 'wb') as f:
        f.write(m2h_data)

    m2d_data = b''.join(m2d_blocks)
    with open(os.path.join(output_dir, f'{name}.m2d'), 'wb') as f:
        f.write(m2d_data)
    ok(f"{name}: {len(files)} files -> {fmt_size(len(m2d_data))} M2D")
    return len(files), 0

# ── Resource Discovery ────────────────────────────────────────────────
# Folder name → config key aliases (e.g. Npc_02/ → Npc)
RESOURCE_ALIASES = {'Npc_02': 'Npc'}

def discover_resources(input_root):
    discovered = []
    # Walk full tree to find resource directories (e.g. lua/Precompiled, Resource/Image)
    for entry in os.scandir(input_root):
        if not entry.is_dir():
            continue
        entry_path = entry.path
        file_list = collect_files(entry_path)
        if not file_list:
            continue
        total_size = sum(os.path.getsize(fp) for _, fp in file_list)
        # Determine format (check alias first, then direct name)
        name = entry.name
        resolved = RESOURCE_ALIASES.get(name, name)
        fmt = cfg = None
        if resolved in OS2F_RESOURCES:
            fmt = 'OS2F'; cfg = OS2F_RESOURCES[resolved]
        elif name in PS2F_RESOURCES:
            fmt = 'PS2F'; cfg = PS2F_RESOURCES[name]
        elif name in MS2F_STREAM_RESOURCES:
            fmt = 'MS2F'; cfg = MS2F_STREAM_RESOURCES[name]
        elif name in NS2F_RESOURCES:
            fmt = 'NS2F'; cfg = NS2F_RESOURCES[name]
        else:
            continue
        discovered.append({
            'name': name, 'display_name': name, 'format': fmt, 'cfg': cfg,
            'input_dir': entry_path,
            'file_count': len(file_list), 'total_size': total_size,
        })
    return discovered

# ── UI ────────────────────────────────────────────────────────────────
def prompt(text, default=None):
    if default:
        result = input(f"  {text} [{default}]: ").strip()
        return result if result else default
    while True:
        result = input(f"  {text}: ").strip()
        if result: return result

def select_indices(items, title):
    print(f"\n{C.W}{title}{C.X}")
    for i, item in enumerate(items, 1):
        label = item.get('display_name', item['name'])
        print(f"  {C.B}{i:>3}{C.X}. {C.W}{item.get('display_name', item['name']):<40}{C.X} {item['format']:<6} {item['file_count']:>6} files  {fmt_size(item['total_size'])}")
    print(f"  {C.B}  0{C.X}. All of the above\n")
    while True:
        raw = prompt("Enter numbers (comma/space, 0=all)")
        try:
            nums = []
            for part in raw.replace(',', ' ').split():
                n = int(part)
                if n == 0: return list(range(len(items)))
                if 1 <= n <= len(items): nums.append(n - 1)
            if nums: return nums
            warn("No valid selections")
        except ValueError:
            warn("Invalid input")

# ── Main ──────────────────────────────────────────────────────────────
def main():
    n = chr(0x2550)
    print(f"\n{C.W}╔{n*58}╗{C.X}")
    print(f"{C.W}║{C.X}  {C.M}MapleStory2 Interactive Repacker v1{C.X}")
    print(f"{C.W}╚{n*58}╝{C.X}\n")

    print(f"{C.W}─ Step 1: Input Directory{C.X}")
    print(f"  Directory containing extracted resource subfolders.")
    print(f"  E.g. {C.B}C:\\extracted\\Resource{C.X} (contains {C.B}Image{C.X}, {C.B}Gfx{C.X}, etc.)\n")
    input_root = prompt("Input directory").strip('"')
    if not os.path.isdir(input_root):
        err(f"Not found: {input_root}"); sys.exit(1)

    print(f"\n{C.W}─ Step 2: Scanning...{C.X}")
    discovered = discover_resources(input_root)
    if not discovered:
        err("No packable resource folders found.")
        sys.exit(1)
    ok(f"Found {len(discovered)} resource(s)")
    for r in discovered:
        info(f"  {r['name']} ({r['format']}): {r['file_count']} files, {fmt_size(r['total_size'])}")

    indices = select_indices(discovered, "─ Step 3: Select Resources to Pack")
    selected = [discovered[i] for i in indices]
    header(f"Selected: {', '.join(r['name'] for r in selected)}")

    # Format selection: MS2F (single M2D) as default
    # Resources that support multiple formats
    convertible = []
    for r in selected:
        resolved = RESOURCE_ALIASES.get(r['name'], r['name'])
        if resolved in CONVERTIBLE_TO_MS2F:
            convertible.append((r, resolved))
    if convertible:
        names = ', '.join(r[0]['name'] for r in convertible)
        print(f"\n{C.W}─ Step 3.5: Pack Format{C.X}")
        print(f"  Applicable to: {C.Y}{names}{C.X}")
        print(f"  {C.B}[1] MS2F{C.X} (single M2D, compact — RECOMMENDED)")
        print(f"  {C.B}[2] OS2F{C.X} (multi-volume M2D, classic CMS)")
        print(f"  {C.B}[3] Per-resource auto{C.X} (keep original format)")
        choice = prompt("Format", "1")
        if choice == '2':
            for r, resolved in convertible:
                if r['format'] in ('MS2F', 'PS2F') and resolved in OS2F_RESOURCES:
                    r['format'] = 'OS2F'
                    r['cfg'] = OS2F_RESOURCES[resolved]
                    info(f"  {r['name']}: -> OS2F")
                elif r['format'] == 'MS2F' and resolved in NS2F_RESOURCES:
                    r['format'] = 'NS2F'
                    r['cfg'] = NS2F_RESOURCES[resolved]
                    info(f"  {r['name']}: -> NS2F")
        elif choice == '1':
            for r, resolved in convertible:
                r['format'] = 'MS2F'
                r['cfg'] = MS2F_STREAM_RESOURCES[resolved]
                info(f"  {r['name']}: -> MS2F")
        # choice 3 = keep auto-detected format

    print(f"\n{C.W}- Step 4: Output Base{C.X}")
    print(f"  Specify the game Data directory.")
    print(f"  M2H/M2D are placed in correct subdirs: Resource/, Resource/Model/, lua/, etc.")
    data_dir = prompt("Game Data directory")
    if not os.path.isdir(data_dir):
        warn(f"Directory not found: {data_dir}, will create as needed")
    for r in selected:
        target = r["cfg"].get("target", "")
        r["output_dir"] = os.path.join(data_dir, target) if target else data_dir
        os.makedirs(r["output_dir"], exist_ok=True)
    info(f"Base: {data_dir}")

    # Step 5: OS2F volume size (only if any remain OS2F)
    os2f_selected = [r for r in selected if r['format'] == 'OS2F']
    max_m2d = 200
    if os2f_selected:
        print(f"\n{C.W}─ Step 5: OS2F Max Volume Size{C.X}")
        try: max_m2d = int(prompt("Max M2D size (MB)", "200"))
        except ValueError: pass

    print(f"\n{C.W}─ Loading Keys...{C.X}")
    keys = load_keys()
    ok("Keys loaded")

    header("Packing...")
    grand_ok, grand_bad = 0, 0
    for r in selected:
        try:
            fmt = r['format']
            out = r['output_dir']
            if fmt == 'OS2F':
                ok_n, bad_n = pack_os2f_resource(r, keys, out, max_m2d)
            elif fmt == 'PS2F':
                ok_n, bad_n = pack_ps2f_resource(r, keys, out)
            elif fmt == 'MS2F':
                ok_n, bad_n = pack_ms2f_resource(r, keys, out)
            elif fmt == 'NS2F':
                ok_n, bad_n = pack_ns2f_resource(r, keys, out)
            else:
                warn(f"{r['name']}: unknown format, skipped"); continue
            grand_ok += ok_n; grand_bad += bad_n
        except Exception as e:
            err(f"{r['name']}: {e}")
            import traceback; traceback.print_exc()
            grand_bad += 1

    header(f"ALL DONE: {grand_ok} files packed" + (f", {grand_bad} failed" if grand_bad else ""))



if __name__ == '__main__':
    main()
