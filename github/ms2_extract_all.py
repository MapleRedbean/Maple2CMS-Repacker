# -*- coding: utf-8 -*-
"""
MapleStory2 M2D Universal Extractor
====================================
Supports: Image / Exported / Map / Effect / Item / Npc / Textures / Movie
Total: ~152,055 files from ~574 M2D archives

Encryption schemes:
  OS2F: base64 -> AES-CTR(ECB) -> zlib  (key = file_size & 0x7F)
  PS2F (Movie): XOR only, no base64, no zlib  (PS2F_XOR_KEY, 2048B repeating)

Output directory mirrors source structure:
  {output}/Resource/{subdir}/{name}/{csv_path}

Examples:
  pip install pycryptodome tqdm
  python ms2_extract_all.py -r Movie -d D:\Game\Data -o ./output
  python ms2_extract_all.py -r all -d D:\Game\Data -o ./output
"""

import struct, base64, zlib, json, os, sys, argparse
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
    """PS2F XOR: 32-bit words with & 0x1FF key rotation"""
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

OS2F_RESOURCES = {
    'Image':    {'csv':'Image.m2h.header','ft':'filetable_decrypted.bin','prefix':'Image_','subdir':''},
    'Exported': {'csv':'Exported.m2h.header','ft':'Exported.filetable.decrypted.bin','prefix':'Exported_','subdir':''},
    'Map':      {'csv':'Map.m2h.header','ft':'Map.filetable.decrypted_v2.bin','prefix':'Map_','subdir':'Model'},
    'Effect':   {'csv':'Effect.m2h.header','ft':'Effect.filetable.decrypted_v2.bin','prefix':'Effect_','subdir':'Model'},
    'Item':     {'csv':'Item.m2h.header','ft':'Item.filetable.decrypted_v2.bin','prefix':'Item_','subdir':'Model'},
    'Npc':      {'csv':'Npc_02.header','ft':'Npc_02.filetable.decrypted_v2.bin','prefix':'Npc_','subdir':'Model'},
    'Textures': {'csv':'Textures.m2h.header','ft':'Textures.filetable.decrypted_v2.bin','prefix':'Textures_','subdir':'Model'},
}

PS2F_RESOURCES = {
    'Movie':    {'csv':'Movie.m2h.header','ft':'Movie.filetable.decrypted_v2.bin','prefix':'Movie_','subdir':''},
}

def load_ft(path):
    with open(os.path.join(SCRIPT_DIR, path), 'rb') as f:
        data = f.read()
    entries = []
    for i in range(0, len(data), 40):
        v = struct.unpack_from('<10I', data, i)
        entries.append({'flag':v[0],'index':v[1],'block_size':v[2],'file_size':v[4],'raw_size':v[6],'offset':v[8]})
    return entries

def load_csv(path):
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

    csv_entries = load_csv(cfg['csv'])
    ft_entries = load_ft(cfg['ft'])

    files_by_m2d = defaultdict(list)
    for i, e in enumerate(ft_entries):
        if i >= len(csv_entries): break
        idx, m2d_id, path = csv_entries[i]
        files_by_m2d[m2d_id].append((idx, path, e))

    # Mirror source: {output}/Resource/{subdir}/{name}/{csv_path}
    if sub:
        out_dir = os.path.join(output_dir, 'Resource', sub, name)
    else:
        out_dir = os.path.join(output_dir, 'Resource', name)
    os.makedirs(out_dir, exist_ok=True)

    n_m2d = len(files_by_m2d)
    print(f'\n{"="*60}')
    print(f'{name} (OS2F): {len(ft_entries)} files, {n_m2d} M2Ds -> {out_dir}')
    print(f'{"="*60}')

    ok_total = bad_total = 0
    m2d_list = sorted(files_by_m2d.keys())
    it = tqdm(m2d_list, desc=f'  {name}', unit='m2d') if HAS_TQDM else m2d_list

    for m2d_id in it:
        files = files_by_m2d[m2d_id]
        fpath = os.path.join(res_dir, f'{cfg["prefix"]}{m2d_id}.m2d')
        if not os.path.exists(fpath):
            bad_total += len(files)
            continue

        with open(fpath, 'rb') as f:
            m2d = f.read()
        ok = 0
        for idx, rel_path, entry in files:
            off, size = entry['offset'], entry['block_size']
            if off + size > len(m2d): bad_total += 1; continue
            block = m2d[off:off+size]
            clean = block.replace(b'=', b'')
            pad = (4 - len(clean) % 4) % 4
            if pad == 3: bad_total += 1; continue
            try:
                decoded = base64.b64decode(clean + b'=' * pad)
            except:
                bad_total += 1; continue

            ki = entry['file_size'] & 0x7F
            try:
                dec = aes_ctr_ecb(osk[ki], oiv[ki], decoded)
            except:
                bad_total += 1; continue

            if dec[0] == 0x78 and dec[1] in (0x01, 0x5E, 0x9C, 0xDA):
                try:
                    dec = zlib.decompress(dec)
                except:
                    bad_total += 1; continue

            op = os.path.join(out_dir, rel_path.replace('/', os.sep))
            os.makedirs(os.path.dirname(op), exist_ok=True)
            with open(op, 'wb') as f:
                f.write(dec)
            ok += 1

        ok_total += ok
        bad_total += len(files) - ok

    total = ok_total + bad_total
    okpct = ok_total * 100 // total if total else 0
    if not HAS_TQDM:
        print(f'  {name}: {ok_total}/{total} ({okpct}%)')
    print(f'  {name} done: {ok_total}/{total} ({okpct}%)')
    return ok_total, bad_total

def extract_ps2f(name, cfg, data_dir, output_dir, psk_xor):
    csv_path = os.path.join(SCRIPT_DIR, cfg['csv'])
    ft_path = os.path.join(SCRIPT_DIR, cfg['ft'])
    sub = cfg['subdir']
    res_dir = os.path.join(data_dir, 'Resource', sub) if sub else os.path.join(data_dir, 'Resource')
    if not os.path.exists(csv_path) or not os.path.exists(ft_path):
        print(f'  [!] Missing: {cfg["csv"]} / {cfg["ft"]}')
        return 0, 0

    csv_entries = load_csv(cfg['csv'])
    ft_entries = load_ft(cfg['ft'])

    files_by_m2d = defaultdict(list)
    for i, e in enumerate(ft_entries):
        if i >= len(csv_entries):
            m2d_id = f'unnamed_{i}'
            path = f'unnamed_{i}'
        else:
            _, m2d_id, path = csv_entries[i]
        files_by_m2d[m2d_id].append((i, path, e))

    if sub:
        out_dir = os.path.join(output_dir, 'Resource', sub, name)
    else:
        out_dir = os.path.join(output_dir, 'Resource', name)
    os.makedirs(out_dir, exist_ok=True)

    n_m2d = len(files_by_m2d)
    print(f'\n{"="*60}')
    print(f'{name} (PS2F XOR): {len(ft_entries)} files, {n_m2d} M2Ds -> {out_dir}')
    print(f'  XOR key: {len(psk_xor)} bytes ({len(psk_xor)//4} x uint32)')
    print(f'{"="*60}')

    ok_total = bad_total = 0
    m2d_list = sorted(files_by_m2d.keys())
    it = tqdm(m2d_list, desc=f'  {name}', unit='m2d') if HAS_TQDM else m2d_list

    for m2d_id in it:
        files = files_by_m2d[m2d_id]
        fpath = os.path.join(res_dir, f'{cfg["prefix"]}{m2d_id}.m2d')
        if not os.path.exists(fpath):
            bad_total += len(files)
            continue

        ok = 0
        for idx, rel_path, entry in files:
            off, size, flag = entry['offset'], entry['block_size'], entry['flag']

            if flag == 0xFF000000:
                with open(fpath, 'rb') as f:
                    f.seek(off)
                    block = f.read(size)
                dec = xor_decrypt(block, psk_xor)
            elif flag == 0xFF000009:
                with open(fpath, 'rb') as f:
                    f.seek(off)
                    block = f.read(size)
                dec = xor_decrypt(block, psk_xor)
                if dec[0] == 0x78 and dec[1] in (0x01, 0x5E, 0x9C, 0xDA):
                    try:
                        dec = zlib.decompress(dec)
                    except:
                        bad_total += 1; continue
                else:
                    bad_total += 1; continue
            else:
                bad_total += 1; continue

            op = os.path.join(out_dir, rel_path.replace('/', os.sep))
            os.makedirs(os.path.dirname(op), exist_ok=True)
            with open(op, 'wb') as f:
                f.write(dec)
            ok += 1

        ok_total += ok
        bad_total += len(files) - ok

    total = ok_total + bad_total
    okpct = ok_total * 100 // total if total else 0
    if not HAS_TQDM:
        print(f'  {name}: {ok_total}/{total} ({okpct}%)')
    print(f'  {name} done: {ok_total}/{total} ({okpct}%)')
    return ok_total, bad_total

def main():
    parser = argparse.ArgumentParser(description='MapleStory2 M2D Universal Extractor')
    parser.add_argument('--resource','-r',
                        choices=['all','Image','Exported','Map','Effect','Item','Npc','Textures','Movie'],
                        default='all', help='Resource to extract')
    parser.add_argument('--data-dir','-d', default=r'D:\WeGameApps\冒险岛2\Client\Data', help='Game Data directory')
    parser.add_argument('--output-dir','-o', default=None, help='Output directory (default: ./extracted/)')
    args = parser.parse_args()

    if not os.path.isdir(args.data_dir):
        print(f'Error: Data directory not found: {args.data_dir}'); sys.exit(1)
    if args.output_dir is None:
        args.output_dir = os.path.join(SCRIPT_DIR, 'extracted')
    if not os.path.exists(KEYS_FILE):
        print(f'Error: Keys file not found: {KEYS_FILE}'); sys.exit(1)

    with open(KEYS_FILE) as f:
        k = json.load(f)
    osk = [bytes(kk) for kk in k['OS2F_USER_KEY']]
    oiv = [bytes(iv) for iv in k['OS2F_IV_CHAIN']]

    # PS2F_XOR_KEY: stored as 512 uint32 ints, pack to 2048 little-endian bytes
    psk_list = k.get('PS2F_XOR_KEY', [])
    psk_xor = bytes(k.get('PS2F_XOR_KEY', [])) * 4  # 512 bytes * 4 = 2048

    all_os2f = list(OS2F_RESOURCES.keys())
    all_ps2f = list(PS2F_RESOURCES.keys())

    if args.resource == 'all':
        targets_os2f = all_os2f
        targets_ps2f = all_ps2f
    elif args.resource in OS2F_RESOURCES:
        targets_os2f = [args.resource]
        targets_ps2f = []
    elif args.resource in PS2F_RESOURCES:
        targets_os2f = []
        targets_ps2f = [args.resource]
    else:
        targets_os2f = []
        targets_ps2f = []

    targets_all = targets_os2f + targets_ps2f
    print(f'Data: {args.data_dir}')
    print(f'Output: {args.output_dir}')
    print(f'Resources: {targets_all}')
    print(f'Output layout: {{out}}/Resource/[Model]/{{name}}/{{csv_path}}')
    if not HAS_TQDM:
        print('(pip install tqdm for progress bars)')
    print()

    grand_ok = grand_bad = 0

    for name in targets_os2f:
        ok, bad = extract_os2f(name, OS2F_RESOURCES[name], args.data_dir, args.output_dir, osk, oiv)
        grand_ok += ok; grand_bad += bad

    for name in targets_ps2f:
        if not psk_xor:
            print(f'  [!] PS2F_XOR_KEY missing, skipping {name}')
            continue
        ok, bad = extract_ps2f(name, PS2F_RESOURCES[name], args.data_dir, args.output_dir, psk_xor)
        grand_ok += ok; grand_bad += bad

    total = grand_ok + grand_bad
    print(f'\n{"="*60}')
    print(f'ALL DONE: {grand_ok}/{total} files extracted')
    if grand_bad: print(f'  Failed: {grand_bad}')
    print(f'{"="*60}')

if __name__ == '__main__':
    main()
