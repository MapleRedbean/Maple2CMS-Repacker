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

def ok(t):    print(f"  {C.G}✓{C.X} {t}")
def warn(t):  print(f"  {C.Y}⚠{C.X} {t}")
def info(t):  print(f"  {C.B}ℹ{C.X} {t}")
def err(t):   print(f"  {C.R}✗{C.X} {t}")
def header(t): print(f"\n{C.W}{'='*60}{C.X}\n{C.W}  {t}{C.X}\n{C.W}{'='*60}{C.X}\n")

# ── Crypto ────────────────────────────────────────────────────────────
def aes_ctr_ecb_encrypt(key, iv, data):
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_ECB)
    keystream = b''
    ctr = 0
    while len(keystream) < len(data):
        block = struct.pack('<QQ', ctr, 0) + iv
        keystream += cipher.encrypt(block)
        ctr += 1
    return bytes(a ^ k for a, k in zip(data, keystream[:len(data)]))

def xor_encrypt(data, xor_key):
    return bytes(d ^ xor_key[i % len(xor_key)] for i, d in enumerate(data))

MS2F_MAGIC = 0x4632534D
NS2F_MAGIC = 0x4632534E
AES_ZLIB = 0xEE000009

# ── Resource Config ───────────────────────────────────────────────────

# Resources that can be packed as either OS2F (multi-M2D) or MS2F (single M2D)
OS2F_TO_MS2F = {'Image', 'Exported', 'Map', 'Effect', 'Item', 'Npc', 'Textures', 'Movie'}

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
    'Movie': {'prefix': 'Movie_', 'csv_name': 'Movie.m2h'},
}

MS2F_STREAM_RESOURCES = {
    'Gfx':      {'prefix': 'Gfx',       'magic': MS2F_MAGIC},
    'Shaders':  {'prefix': 'Shaders',   'magic': MS2F_MAGIC},
    'Library':  {'prefix': 'Library',   'magic': MS2F_MAGIC},
    'PrecomputedTerrain': {'prefix': 'PrecomputedTerrain', 'magic': MS2F_MAGIC},
    'asset-web-config':   {'prefix': 'asset-web-config',   'magic': MS2F_MAGIC},
    'asset-web-metadata': {'prefix': 'asset-web-metadata', 'magic': MS2F_MAGIC},
    'Camera':   {'prefix': 'Camera',    'magic': MS2F_MAGIC},
    'Character':{'prefix': 'Character', 'magic': MS2F_MAGIC},
    'Common':   {'prefix': 'Common',    'magic': MS2F_MAGIC},
    'Emotion':  {'prefix': 'Emotion',   'magic': MS2F_MAGIC},
    'Path':     {'prefix': 'Path',      'magic': MS2F_MAGIC},
    'Precompiled':{'prefix': 'Precompiled','magic': MS2F_MAGIC},
    'Tool':     {'prefix': 'Tool',      'magic': MS2F_MAGIC},
    'Npc':      {'prefix': 'Npc',       'magic': MS2F_MAGIC},
}

NS2F_RESOURCES = {
    'Xml': {'prefix': 'Xml', 'magic': NS2F_MAGIC},
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

    for rel_path, full_path in files:
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

    # Build FileTable (OS2F Ver3: 40B entries)
    ft_entries = bytearray()
    for m2d_idx, m2d_blocks_list in all_m2d:
        offset = 0
        for rel_path, block in m2d_blocks_list:
            full = os.path.join(input_dir, rel_path)
            with open(full, 'rb') as f:
                file_data = f.read()
            compressed = zlib.compress(file_data)
            entry = bytearray(40)
            struct.pack_into('<I', entry, 0, m2d_idx)
            struct.pack_into('<I', entry, 4, 0)
            struct.pack_into('<I', entry, 8, AES_ZLIB)
            struct.pack_into('<I', entry, 12, 0)
            struct.pack_into('<Q', entry, 16, offset)
            struct.pack_into('<I', entry, 24, len(block))
            struct.pack_into('<I', entry, 28, 0)
            struct.pack_into('<Q', entry, 32, len(compressed))
            ft_entries.extend(entry)
            offset += len(block)
    for i in range(len(ft_entries) // 40):
        struct.pack_into('<I', ft_entries, i*40 + 4, i+1)

    ft_comp = zlib.compress(bytes(ft_entries))
    ft_ki = len(ft_comp) & 0x7F
    ft_enc = aes_ctr_ecb_encrypt(osk[ft_ki], oiv[ft_ki], ft_comp)
    ft_b64 = base64.b64encode(ft_enc)

    # Write M2H
    os.makedirs(output_dir, exist_ok=True)
    m2h_data = bytearray()
    m2h_data.extend(struct.pack('<I', 0x4632534F))
    m2h_data.extend(struct.pack('<I', 0))
    m2h_data.extend(struct.pack('<Q', len(ft_comp)))
    m2h_data.extend(struct.pack('<Q', len(ft_b64)))
    m2h_data.extend(struct.pack('<Q', len(ft_entries)))
    m2h_data.extend(struct.pack('<Q', len(csv_comp)))
    m2h_data.extend(struct.pack('<Q', len(csv_b64)))
    m2h_data.extend(struct.pack('<Q', len(files)))
    m2h_data.extend(struct.pack('<Q', len(all_m2d)))
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

    for rel_path, full_path in files:
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
    csv_lines = [f'{i+1},0,{f[0]}' for i, f in enumerate(files)]
    csv_text = '\r\n'.join(csv_lines)
    m2h_data = bytearray()
    m2h_data.extend(struct.pack('<I', 0x46325350))
    m2h_data.extend(struct.pack('<I', 0))
    m2h_data.extend(struct.pack('<Q', 0))
    m2h_data.extend(struct.pack('<Q', 0))
    m2h_data.extend(struct.pack('<Q', 40 * len(files)))
    m2h_data.extend(struct.pack('<Q', len(csv_text.encode('utf-8'))))
    m2h_data.extend(struct.pack('<Q', len(csv_text.encode('utf-8'))))
    m2h_data.extend(struct.pack('<Q', len(files)))
    m2h_data.extend(struct.pack('<Q', len(all_m2d)))
    m2h_data.extend(csv_text.encode('utf-8'))
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

    for rel_path, full_path in files:
        with open(full_path, 'rb') as f:
            file_data = f.read()
        compressed = zlib.compress(file_data)
        file_ki = len(compressed) & 0x7F
        encrypted = aes_ctr_ecb_encrypt(msk[file_ki], miv[file_ki], compressed)
        encoded = base64.b64encode(encrypted)
        m2d_blocks.append(encoded)
        entry = bytearray(48)
        struct.pack_into('<I', entry, 0, 0)
        struct.pack_into('<i', entry, 4, len(m2d_blocks))
        struct.pack_into('<I', entry, 8, AES_ZLIB)
        struct.pack_into('<I', entry, 12, 0)
        struct.pack_into('<Q', entry, 16, m2d_offset)
        struct.pack_into('<I', entry, 24, len(encoded))
        struct.pack_into('<I', entry, 28, 0)
        struct.pack_into('<Q', entry, 32, len(compressed))
        struct.pack_into('<Q', entry, 40, len(file_data))
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
    m2h_data.extend(struct.pack('<Q', 0))
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
    for rel_path, full_path in files:
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
    m2h_data.extend(struct.pack('<Q', 0))
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
    for root, dirs, files in os.walk(input_root):
        for entry in dirs:
            entry_path = os.path.join(root, entry)
            file_list = collect_files(entry_path)
            if not file_list:
                continue
            total_size = sum(os.path.getsize(fp) for _, fp in file_list)
            # Determine format (check alias first, then direct name)
            resolved = RESOURCE_ALIASES.get(entry, entry)
            fmt = cfg = None
            if resolved in OS2F_RESOURCES:
                fmt = 'OS2F'; cfg = OS2F_RESOURCES[resolved]
            elif entry in PS2F_RESOURCES:
                fmt = 'PS2F'; cfg = PS2F_RESOURCES[entry]
            elif entry in MS2F_STREAM_RESOURCES:
                fmt = 'MS2F'; cfg = MS2F_STREAM_RESOURCES[entry]
            elif entry in NS2F_RESOURCES:
                fmt = 'NS2F'; cfg = NS2F_RESOURCES[entry]
            else:
                continue
            # Show subdirectory context in display name
            rel_parent = os.path.relpath(root, input_root)
            display_name = f'{rel_parent}/{entry}' if rel_parent != '.' else entry
            discovered.append({
                'name': entry, 'display_name': display_name, 'format': fmt, 'cfg': cfg,
                'input_dir': entry_path,
                'file_count': len(file_list), 'total_size': total_size,
            })
        dirs[:] = []  # Don't recurse deeper than immediate subdirs of each root
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
    print(f"\n{C.W}╔{C._eq}58╗{C.X}")
    print(f"{C.W}║{C.X}  {C.M}MapleStory2 Interactive Repacker v1{C.X}")
    print(f"{C.W}║{C.X}  Pack extracted/modified files -> M2D/M2H")
    print(f"{C.W}╚{C._eq}58╝{C.X}\n")

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

    # Offer MS2F override for OS2F resources
    convertible = [r for r in selected if r['format'] == 'OS2F' and r['name'] in OS2F_TO_MS2F]
    if convertible:
        names = ', '.join(r['name'] for r in convertible)
        print(f"\n{C.W}─ Step 3.5: Format Override{C.X}")
        print(f"  {C.Y}{names}: can be MS2F (single M2D) instead of OS2F (multi-volume){C.X}")
        print(f"  {C.B}OS2F{C.X}: Image_0000.m2d + Image_0001.m2d + ...")
        print(f"  {C.B}MS2F{C.X}: Image.m2d (single archive)")
        choice = prompt("Pack as MS2F? (y/n)", "n").lower()
        if choice.startswith('y'):
            for r in convertible:
                r['format'] = 'MS2F'
                r['cfg'] = MS2F_STREAM_RESOURCES[r['name']]
                info(f"  {r['name']}: OS2F -> MS2F")

    print(f"\n{C.W}─ Step 4: Output Directory{C.X}")
    print(f"  [S] Same as input")
    print(f"  [D] Different directory")
    choice = prompt("Choice", "S").upper()
    output_dir = input_root if choice == 'S' else prompt("Output directory").strip('"')
    os.makedirs(output_dir, exist_ok=True)
    info(f"Output: {output_dir}")

    os2f = [r for r in selected if r['format'] == 'OS2F']
    max_m2d = 200
    if os2f:
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
            if fmt == 'OS2F':
                ok_n, bad_n = pack_os2f_resource(r, keys, output_dir, max_m2d)
            elif fmt == 'PS2F':
                ok_n, bad_n = pack_ps2f_resource(r, keys, output_dir)
            elif fmt == 'MS2F':
                ok_n, bad_n = pack_ms2f_resource(r, keys, output_dir)
            elif fmt == 'NS2F':
                ok_n, bad_n = pack_ns2f_resource(r, keys, output_dir)
            else:
                warn(f"{r['name']}: unknown format, skipped"); continue
            grand_ok += ok_n; grand_bad += bad_n
        except Exception as e:
            err(f"{r['name']}: {e}")
            import traceback; traceback.print_exc()
            grand_bad += 1

    header(f"ALL DONE: {grand_ok} files packed" + (f", {grand_bad} failed" if grand_bad else ""))

