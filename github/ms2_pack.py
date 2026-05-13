# -*- coding: utf-8 -*-
"""
MapleStory2 M2D/M2H Repacker v7
===============================
Packs a directory of extracted files back into M2D + M2H archives.

Supports ALL formats:
  OS2F: Image, Exported, Map, Effect, Item, Npc, Textures
  PS2F: Movie
  MS2F: Gfx, Camera, Character, Common, Library, Path, Precompiled,
        PrecomputedTerrain, Shaders, Tool, asset-web-config,
        asset-web-metadata, Emotion, NPC
  NS2F: Xml

Usage:
  python ms2_pack.py --input ./modified_files --resource Item -o ./output
  python ms2_pack.py --input ./gfx_files --resource Gfx -o ./output
  python ms2_pack.py --input ./xml_files --resource Xml -o ./output

M2H structure:
  OS2F/PS2F:  base64( zlib(CSV) || zlib(FT) )
  MS2F/NS2F:  PackStream header + base64(AES(zlib(CSV))) + base64(AES(zlib(FT)))
OS2F M2D:     base64( AES-CTR( zlib(file) ) )
PS2F M2D:     XOR(file, PS2F_XOR_KEY)
MS2F/NS2F M2D: base64( AES-CTR( zlib(file) ) ), single M2D
"""

import struct, base64, zlib, json, os, sys, argparse, hashlib
from collections import defaultdict

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    def tqdm(iterable, **kw): return iterable

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_FILE = os.path.join(SCRIPT_DIR, 'orion2_keys.json')

# Steam/CMS BlackCipher key source (overrides MS2F keys)
def _get_config_bc():
    for p in [os.path.join(SCRIPT_DIR, "config.bc"),
              os.path.join(SCRIPT_DIR, "BlackCipher", "config.bc")]:
        if os.path.exists(p): return p
    return None


# ── Crypto ───────────────────────────────────────────────────────────


def parse_config_bc_keys(path):
    """Parse BlackCipher config.bc hex keys into byte arrays."""
    with open(path, "r") as f:
        hex_data = f.read().strip()
    keys = []
    for i in range(0, len(hex_data), 64):
        chunk = hex_data[i:i+64]
        if len(chunk) == 64:
            keys.append(bytes(int(chunk[j:j+2], 16) for j in range(0, 64, 2)))
    return keys

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

# ── Magic & constants ────────────────────────────────────────────────

MS2F_MAGIC = 0x4632534D
NS2F_MAGIC = 0x4632534E
AES_ZLIB = 0xEE000009

# ── Resource Config ──────────────────────────────────────────────────

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

MS2F_STREAM_RESOURCES = {
    'Gfx':      {'prefix': 'Gfx',       'magic': MS2F_MAGIC},
    'Camera':   {'prefix': 'Camera',    'magic': MS2F_MAGIC},
    'Character':{'prefix': 'Character', 'magic': MS2F_MAGIC},
    'Common':   {'prefix': 'Common',    'magic': MS2F_MAGIC},
    'Emotion':  {'prefix': 'Emotion',   'magic': MS2F_MAGIC},
    'Library':  {'prefix': 'Library',   'magic': MS2F_MAGIC},
    'Path':     {'prefix': 'Path',      'magic': MS2F_MAGIC},
    'Precompiled':{'prefix': 'Precompiled','magic': MS2F_MAGIC},
    'PrecomputedTerrain':{'prefix':'PrecomputedTerrain','magic':MS2F_MAGIC,'subdir':'lua'},
    'Shaders':  {'prefix': 'Shaders',   'magic': MS2F_MAGIC},
    'Tool':     {'prefix': 'Tool',      'magic': MS2F_MAGIC},
    'NPC':      {'prefix': 'NPC',       'magic': MS2F_MAGIC},
    'Effect':   {'prefix': 'Effect',    'magic': MS2F_MAGIC},
    'Exported': {'prefix': 'Exported',  'magic': MS2F_MAGIC},
    'Image':    {'prefix': 'Image',     'magic': MS2F_MAGIC},
    'Item':     {'prefix': 'Item',      'magic': MS2F_MAGIC},
    'Map':      {'prefix': 'Map',       'magic': MS2F_MAGIC},
    'Textures': {'prefix': 'Textures',  'magic': MS2F_MAGIC},
    'Movie':    {'prefix': 'Movie',     'magic': MS2F_MAGIC},
    'asset-web-config':  {'prefix':'asset-web-config', 'magic':MS2F_MAGIC},
    'asset-web-metadata':{'prefix':'asset-web-metadata','magic':MS2F_MAGIC},
}

NS2F_RESOURCES = {
    'Xml':      {'prefix': 'Xml',       'magic': NS2F_MAGIC},
}

# ── Helpers ──────────────────────────────────────────────────────────

def build_m2d_id(prefix, volume_index):
    """Generate M2D filename ID (sequential, deterministic)."""
    h = hashlib.md5(f'{prefix}{volume_index}'.encode()).hexdigest()[:32]
    return h

def collect_files(input_dir):
    """Walk input_dir and return sorted list of (rel_path, full_path)."""
    file_list = []
    for root, dirs, files in os.walk(input_dir):
        for f in files:
            full = os.path.join(root, f)
            rel = os.path.relpath(full, input_dir).replace('\\', '/')
            file_list.append((rel, full))
    file_list.sort(key=lambda x: x[0])
    return file_list

# ── OS2F Packing ─────────────────────────────────────────────────────

def pack_os2f(input_dir, resource_name, cfg, output_dir, osk, oiv, m2d_prefix, max_m2d_mb):
    """Pack a directory into OS2F M2D + M2H archives."""

    file_list = collect_files(input_dir)
    if not file_list:
        print('Error: No files found in input directory')
        return

    print(f'\n{"="*60}')
    print(f'Packing {resource_name} (OS2F): {len(file_list)} files')
    print(f'{"="*60}')

    processed = []
    total_raw = 0
    for rel, full in tqdm(file_list, desc='  Encoding', unit='file') if HAS_TQDM else file_list:
        with open(full, 'rb') as f:
            raw = f.read()
        raw_size = len(raw)
        total_raw += raw_size
        compressed = zlib.compress(raw)
        ki = raw_size & 0x7F
        encrypted = aes_ctr_ecb_encrypt(osk[ki], oiv[ki], compressed)
        encoded = base64.b64encode(encrypted)
        processed.append({
            'path': rel, 'raw_size': raw_size,
            'compressed_size': len(compressed),
            'block_size': len(encoded), 'data': encoded,
        })

    max_bytes = max_m2d_mb * 1024 * 1024
    volumes = []
    current_vol = []
    current_size = 0
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
            ft_entries.append({
                'flag': AES_ZLIB, 'index': file_index,
                'block_size': len(block), 'file_size': p['raw_size'],
                'raw_size': p['raw_size'], 'offset': offset,
            })
            csv_lines.append(f'{file_index},{m2d_id},{p["path"]}')
            offset += len(block)
            file_index += 1
        os.makedirs(os.path.dirname(m2d_path) if os.path.dirname(m2d_path) else output_dir, exist_ok=True)
        with open(m2d_path, 'wb') as f:
            f.write(bytes(m2d_data))

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

    total_m2d_size = sum(
        os.path.getsize(os.path.join(output_dir, f'{m2d_prefix_str}{build_m2d_id(m2d_prefix_str, vi)}.m2d'))
        for vi in range(len(volumes))
    )
    print(f'\n{"="*60}')
    print(f'Packed {resource_name}:')
    print(f'  Files: {len(file_list)}')
    print(f'  M2D archives: {len(volumes)}')
    print(f'  M2D total: {total_m2d_size / (1024*1024):.1f} MB')
    print(f'  M2H: {os.path.getsize(m2h_path) / 1024:.1f} KB')
    print(f'  Output: {output_dir}')
    print(f'{"="*60}')

# ── PS2F Packing ─────────────────────────────────────────────────────

def pack_ps2f(input_dir, resource_name, cfg, output_dir, psk_xor, m2d_prefix):
    """Pack directory into PS2F M2D + M2H (Movie format)."""
    file_list = collect_files(input_dir)
    if not file_list:
        print('Error: No files found')
        return

    print(f'\n{"="*60}')
    print(f'Packing {resource_name} (PS2F XOR): {len(file_list)} files')
    print(f'{"="*60}')

    m2d_prefix_str = m2d_prefix if m2d_prefix else cfg['prefix']
    ft_entries = []
    csv_lines = []

    for idx, (rel, full) in enumerate(tqdm(file_list, desc='  Encoding', unit='file') if HAS_TQDM else file_list):
        with open(full, 'rb') as f:
            raw = f.read()
        file_size = len(raw)
        encrypted = xor_encrypt(raw, psk_xor)
        m2d_id = build_m2d_id(m2d_prefix_str, idx)
        m2d_path = os.path.join(output_dir, f'{m2d_prefix_str}{m2d_id}.m2d')
        with open(m2d_path, 'wb') as f:
            f.write(encrypted)
        ft_entries.append({
            'flag': 0xFF000000, 'index': idx,
            'block_size': file_size, 'file_size': file_size,
            'raw_size': file_size, 'offset': 0,
        })
        csv_lines.append(f'{idx},{m2d_id},{rel}')

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
    print(f'{"="*60}')

# ── MS2F PackStreamVer1 Packing ─────────────────────────────────────

def pack_ms2f_stream(input_dir, resource_name, cfg, output_dir, msk, miv):
    """
    Pack directory into MS2F PackStreamVer1 (single M2D + M2H).
    Used by: Gfx, Camera, Character, Common, Emotion, Library, Path,
             Precompiled, PrecomputedTerrain, Shaders, Tool, NPC,
             asset-web-config, asset-web-metadata,
             and all GMS resources (Effect, Exported, Image, Item, Map,
             Textures, Movie).
    """
    file_list = collect_files(input_dir)
    if not file_list:
        print('Error: No files found')
        return

    print(f'\n{"="*60}')
    print(f'Packing {resource_name} (MS2F PackStreamVer1): {len(file_list)} files')
    print(f'{"="*60}')

    prefix = cfg['prefix']

    # 1. Process each file: zlib → AES → base64
    processed = []
    for rel, full in tqdm(file_list, desc='  Encoding', unit='file') if HAS_TQDM else file_list:
        with open(full, 'rb') as f:
            raw = f.read()
        compressed = zlib.compress(raw)
        ki = len(compressed) & 0x7F
        encrypted = aes_ctr_ecb_encrypt(msk[ki], miv[ki], compressed)
        encoded = base64.b64encode(encrypted)
        processed.append({
            'path': rel, 'file_size': len(raw),
            'compressed_size': len(compressed),
            'encoded_size': len(encoded),
            'data': encoded,
        })

    # 2. Build CSV text
    # Ver1 CSV: index,hash,path  (hash = MD5 of path prefix)
    csv_lines = []
    for i, p in enumerate(processed):
        h = hashlib.md5(f'{prefix}{i}'.encode()).hexdigest()[:32]
        csv_lines.append(f'{i},{h},{p["path"]}')
    csv_text = '\r\n'.join(csv_lines)  # GMS uses \r\n line endings

    # 3. Build FileTable (Ver1, 48 bytes per entry)
    ft_entries = []
    m2d_offset = 0
    for i, p in enumerate(processed):
        ft_entry = bytearray()
        ft_entry.extend(b'\x00\x00\x00\x00')  # aPackingDef
        ft_entry.extend(struct.pack('<i', i))  # FileIndex
        ft_entry.extend(struct.pack('<I', AES_ZLIB))  # BufferFlag
        ft_entry.extend(struct.pack('<i', 0))  # Reserved0
        ft_entry.extend(struct.pack('<Q', m2d_offset))  # Offset
        ft_entry.extend(struct.pack('<I', p['encoded_size']))  # EncodedFileSize
        ft_entry.extend(struct.pack('<i', 0))  # Reserved1
        ft_entry.extend(struct.pack('<Q', p['compressed_size']))  # CompressedFileSize
        ft_entry.extend(struct.pack('<Q', p['file_size']))  # FileSize
        ft_entries.append(bytes(ft_entry))
        m2d_offset += p['encoded_size']

    # 4. Compress + encrypt CSV
    csv_zlib = zlib.compress(csv_text.encode('utf-8'))
    csv_ki = len(csv_zlib) & 0x7F
    csv_encrypted = aes_ctr_ecb_encrypt(msk[csv_ki], miv[csv_ki], csv_zlib)
    csv_encoded = base64.b64encode(csv_encrypted)

    # 5. Compress + encrypt FT
    ft_raw = b''.join(ft_entries)
    ft_zlib = zlib.compress(ft_raw)
    ft_ki = len(ft_zlib) & 0x7F
    ft_encrypted = aes_ctr_ecb_encrypt(msk[ft_ki], miv[ft_ki], ft_zlib)
    ft_encoded = base64.b64encode(ft_encrypted)

    # 6. Build PackStreamVer1 header
    header_size = 60  # bytes after uReserved
    m2h_hdr = bytearray()
    m2h_hdr.extend(struct.pack('<I', MS2F_MAGIC))       # magic
    m2h_hdr.extend(struct.pack('<I', 0))                # uReserved
    m2h_hdr.extend(struct.pack('<Q', len(ft_zlib)))     # CompressedDataSize
    m2h_hdr.extend(struct.pack('<Q', len(ft_encoded)))  # EncodedDataSize
    m2h_hdr.extend(struct.pack('<Q', header_size))      # HeaderSize
    m2h_hdr.extend(struct.pack('<Q', len(csv_zlib)))    # CompressedHeaderSize
    m2h_hdr.extend(struct.pack('<Q', len(csv_encoded))) # EncodedHeaderSize
    m2h_hdr.extend(struct.pack('<Q', len(file_list)))   # FileListCount
    m2h_hdr.extend(struct.pack('<Q', len(ft_raw)))      # DataSize

    # 7. Write M2H
    m2h_data = bytes(m2h_hdr) + csv_encoded + ft_encoded
    m2h_path = os.path.join(output_dir, f'{prefix}.m2h')
    os.makedirs(output_dir, exist_ok=True)
    with open(m2h_path, 'wb') as f:
        f.write(m2h_data)

    # 8. Write M2D (single file with all blocks concatenated)
    m2d_data = b''.join(p['data'] for p in processed)
    m2d_path = os.path.join(output_dir, f'{prefix}.m2d')
    with open(m2d_path, 'wb') as f:
        f.write(m2d_data)

    # 9. Summary
    print(f'\n{"="*60}')
    print(f'Packed {resource_name}:')
    print(f'  Files: {len(file_list)}')
    print(f'  M2D: {len(m2d_data) / (1024*1024):.1f} MB (single)')
    print(f'  M2H: {len(m2h_data) / 1024:.1f} KB')
    print(f'  CSV key: {csv_ki}, FT key: {ft_ki}')
    print(f'  Output: {output_dir}')
    print(f'{"="*60}')

# ── NS2F PackStreamVer2 Packing ─────────────────────────────────────

def pack_ns2f_stream(input_dir, resource_name, cfg, output_dir, nsk, niv):
    """
    Pack directory into NS2F PackStreamVer2 (single M2D + M2H).
    Used by: Xml.
    """
    file_list = collect_files(input_dir)
    if not file_list:
        print('Error: No files found')
        return

    print(f'\n{"="*60}')
    print(f'Packing {resource_name} (NS2F PackStreamVer2): {len(file_list)} files')
    print(f'{"="*60}')

    prefix = cfg['prefix']

    # 1. Process each file: zlib → AES → base64
    processed = []
    for rel, full in tqdm(file_list, desc='  Encoding', unit='file') if HAS_TQDM else file_list:
        with open(full, 'rb') as f:
            raw = f.read()
        compressed = zlib.compress(raw)
        ki = len(compressed) & 0x7F
        encrypted = aes_ctr_ecb_encrypt(nsk[ki], niv[ki], compressed)
        encoded = base64.b64encode(encrypted)
        processed.append({
            'path': rel, 'file_size': len(raw),
            'compressed_size': len(compressed),
            'encoded_size': len(encoded),
            'data': encoded,
        })

    # 2. Build CSV
    csv_lines = []
    for i, p in enumerate(processed):
        h = hashlib.md5(f'{prefix}{i}'.encode()).hexdigest()[:32]
        csv_lines.append(f'{i},{h},{p["path"]}')
    csv_text = '\r\n'.join(csv_lines)

    # 3. Build FileTable (Ver2, 36 bytes per entry)
    ft_entries = []
    m2d_offset = 0
    for i, p in enumerate(processed):
        ft_entry = bytearray()
        ft_entry.extend(struct.pack('<I', AES_ZLIB))     # BufferFlag
        ft_entry.extend(struct.pack('<i', i))            # FileIndex
        ft_entry.extend(struct.pack('<I', p['encoded_size']))  # EncodedFileSize
        ft_entry.extend(struct.pack('<Q', p['compressed_size'])) # CompressedFileSize
        ft_entry.extend(struct.pack('<Q', p['file_size']))      # FileSize
        ft_entry.extend(struct.pack('<Q', m2d_offset))          # Offset
        ft_entries.append(bytes(ft_entry))
        m2d_offset += p['encoded_size']

    # 4. Compress + encrypt CSV
    csv_zlib = zlib.compress(csv_text.encode('utf-8'))
    csv_ki = len(csv_zlib) & 0x7F
    csv_encrypted = aes_ctr_ecb_encrypt(nsk[csv_ki], niv[csv_ki], csv_zlib)
    csv_encoded = base64.b64encode(csv_encrypted)

    # 5. Compress + encrypt FT
    ft_raw = b''.join(ft_entries)
    ft_zlib = zlib.compress(ft_raw)
    ft_ki = len(ft_zlib) & 0x7F
    ft_encrypted = aes_ctr_ecb_encrypt(nsk[ft_ki], niv[ft_ki], ft_zlib)
    ft_encoded = base64.b64encode(ft_encrypted)

    # 6. Build PackStreamVer2 header
    m2h_hdr = bytearray()
    m2h_hdr.extend(struct.pack('<I', NS2F_MAGIC))       # magic
    m2h_hdr.extend(struct.pack('<I', len(file_list)))   # FileListCount
    m2h_hdr.extend(struct.pack('<Q', len(ft_zlib)))     # CompressedDataSize
    m2h_hdr.extend(struct.pack('<Q', len(ft_encoded)))  # EncodedDataSize
    m2h_hdr.extend(struct.pack('<Q', 56))               # HeaderSize
    m2h_hdr.extend(struct.pack('<Q', len(csv_zlib)))    # CompressedHeaderSize
    m2h_hdr.extend(struct.pack('<Q', len(csv_encoded))) # EncodedHeaderSize
    m2h_hdr.extend(struct.pack('<Q', len(ft_raw)))      # DataSize

    # 7. Write M2H
    m2h_data = bytes(m2h_hdr) + csv_encoded + ft_encoded
    m2h_path = os.path.join(output_dir, f'{prefix}.m2h')
    os.makedirs(output_dir, exist_ok=True)
    with open(m2h_path, 'wb') as f:
        f.write(m2h_data)

    # 8. Write M2D
    m2d_data = b''.join(p['data'] for p in processed)
    m2d_path = os.path.join(output_dir, f'{prefix}.m2d')
    with open(m2d_path, 'wb') as f:
        f.write(m2d_data)

    # 9. Summary
    print(f'\n{"="*60}')
    print(f'Packed {resource_name}:')
    print(f'  Files: {len(file_list)}')
    print(f'  M2D: {len(m2d_data) / (1024*1024):.1f} MB (single)')
    print(f'  M2H: {len(m2h_data) / 1024:.1f} KB')
    print(f'  CSV key: {csv_ki}, FT key: {ft_ki}')
    print(f'  Output: {output_dir}')
    print(f'{"="*60}')

# ── Main ─────────────────────────────────────────────────────────────

def main():
    all_choices = sorted(set(
        list(OS2F_RESOURCES.keys()) +
        list(PS2F_RESOURCES.keys()) +
        list(MS2F_STREAM_RESOURCES.keys()) +
        list(NS2F_RESOURCES.keys())
    ))

    parser = argparse.ArgumentParser(description='MapleStory2 M2D/M2H Repacker v7')
    parser.add_argument('--input', '-i', required=True,
                        help='Input directory with files to pack')
    parser.add_argument('--resource', '-r', required=True,
                        choices=all_choices,
                        help='Resource type')
    parser.add_argument('--output', '-o', default='./packed',
                        help='Output directory')
    parser.add_argument('--max-m2d-size', type=int, default=500,
                        help='Max M2D size in MB (OS2F only, default 500)')
    parser.add_argument('--m2d-prefix', default=None,
                        help='Custom M2D filename prefix (OS2F/PS2F only)')
    args = parser.parse_args()

    if not os.path.isdir(args.input):
        print(f'Error: Input directory not found: {args.input}')
        sys.exit(1)
    os.makedirs(args.output, exist_ok=True)

    if not os.path.exists(KEYS_FILE):
        print(f'Error: Keys file not found: {KEYS_FILE}')
        sys.exit(1)

    with open(KEYS_FILE) as f:
        k = json.load(f)
    osk = [bytes(kk) for kk in k['OS2F_USER_KEY']]
    oiv = [bytes(iv) for iv in k['OS2F_IV_CHAIN']]
    msk = [bytes(kk) for kk in k['MS2F_USER_KEY']]

    # Override MS2F keys with config.bc if available (Steam/CMS)
    config_bc = _get_config_bc()
    if config_bc:
        print(f'[key] Loading MS2F keys from BlackCipher: {config_bc}')
        bc_keys = parse_config_bc_keys(config_bc)
        msk = bc_keys[:128]  # First 128 keys for & 0x7F indexing
        if len(msk) < 128:
            print(f'  Warning: config.bc only has {len(msk)} keys, expected 128')
    else:
        print('[!] config.bc not found, using orion2 MS2F keys')
    miv = [bytes(iv) for iv in k['MS2F_IV_CHAIN']]
    nsk = [bytes(kk) for kk in k['NS2F_USER_KEY']]
    niv = [bytes(iv) for iv in k['NS2F_IV_CHAIN']]
    psk_list = k.get('PS2F_XOR_KEY', [])
    psk_xor = bytes(psk_list) * 4 if psk_list else b''

    print(f'Input:  {args.input}')
    print(f'Output: {args.output}')
    print(f'Resource: {args.resource}')

    r = args.resource

    if r in OS2F_RESOURCES:
        pack_os2f(args.input, r, OS2F_RESOURCES[r],
                  args.output, osk, oiv, args.m2d_prefix, args.max_m2d_size)
    elif r in PS2F_RESOURCES:
        if not psk_xor:
            print('Error: PS2F_XOR_KEY not found in keys file')
            sys.exit(1)
        pack_ps2f(args.input, r, PS2F_RESOURCES[r],
                  args.output, psk_xor, args.m2d_prefix)
    elif r in NS2F_RESOURCES:
        pack_ns2f_stream(args.input, r, NS2F_RESOURCES[r],
                         args.output, nsk, niv)
    elif r in MS2F_STREAM_RESOURCES:
        pack_ms2f_stream(args.input, r, MS2F_STREAM_RESOURCES[r],
                         args.output, msk, miv)

if __name__ == '__main__':
    main()
