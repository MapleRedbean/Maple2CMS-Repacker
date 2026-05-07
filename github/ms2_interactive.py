# -*- coding: utf-8 -*-
"""
MapleStory2 M2D Interactive Extractor
======================================
Interactive extraction tool with resource auto-discovery.
Scans a data directory for M2H/M2D pairs, detects format/version,
and lets the user select which resources to extract.

Usage:
  python ms2_interactive.py

Requires: pycryptodome, tqdm (optional)
Companion files: ms2_extract_all.py, orion2_keys.json
                 + pre-decrypted CSV/FT files for OS2F/PS2F resources
"""

import struct, base64, zlib, json, os, sys, glob
from collections import defaultdict
from io import BytesIO

# ── Import core functions from ms2_extract_all ───────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

try:
    from ms2_extract_all import (
        aes_ctr_ecb, xor_decrypt,
        MS2F_MAGIC, NS2F_MAGIC, OS2F_MAGIC, PS2F_MAGIC,
        parse_stream_v1, parse_stream_v2,
        parse_filetable_ver1, parse_filetable_ver2,
        AES_ZLIB, XOR, XOR_ZLIB,
        load_predecrypted_csv, load_predecrypted_ft,
    )
    HAS_MODULE = True
except ImportError:
    HAS_MODULE = False
    print("[!] ms2_extract_all.py not found in script directory")

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    def tqdm(iterable, **kw): return iterable

KEYS_FILE = os.path.join(SCRIPT_DIR, 'orion2_keys.json')

# ── Color helpers for terminal output ────────────────────────────────
class C:
    """ANSI color codes (auto-disabled if stdout is not a TTY)."""
    _ok = sys.stdout.isatty()
    R = '\033[91m' if _ok else ''; G = '\033[92m' if _ok else ''
    Y = '\033[93m' if _ok else ''; B = '\033[94m' if _ok else ''
    C = '\033[96m' if _ok else ''; W = '\033[97m' if _ok else ''
    M = '\033[95m' if _ok else ''; X = '\033[0m' if _ok else ''

def header(text):
    print(f"\n{C.C}{'='*60}{C.X}")
    print(f"{C.W}{text}{C.X}")
    print(f"{C.C}{'='*60}{C.X}")

def ok(text):   print(f"  {C.G}\u2713{C.X} {text}")
def warn(text): print(f"  {C.Y}\u26A0{C.X} {text}")
def info(text): print(f"  {C.B}\u2139{C.X} {text}")
def err(text):  print(f"  {C.R}\u2717{C.X} {text}")

# ── Resource scanner ─────────────────────────────────────────────────

def scan_resources(data_dir):
    """
    Walk data_dir and discover all M2H+M2D resource groups.
    Returns a sorted list of {'name': str, 'm2h': path, 'm2d_files': [path,...],
                               'format': 'OS2F'|'MS2F'|'NS2F'|'PS2F'|'UNKNOWN',
                               'magic': hex_int, 'm2d_count': int,
                               'data_root': bool}
    """
    discovered = []
    seen_prefixes = set()

    for root, dirs, files in os.walk(data_dir):
        m2h_files = [f for f in files if f.endswith('.m2h')]
        for m2h_name in m2h_files:
            prefix = m2h_name[:-4]  # Strip '.m2h'

            # Find all M2D files with the same prefix in the same directory
            m2d_files = sorted([
                os.path.join(root, f)
                for f in files
                if f.startswith(prefix + '_') and f.endswith('.m2d')
                   or f == prefix + '.m2d'
            ])

            if not m2d_files:
                # Also check: the m2d might be named exactly prefix.m2d
                candidate = os.path.join(root, prefix + '.m2d')
                if os.path.exists(candidate):
                    m2d_files = [candidate]

            m2h_path = os.path.join(root, m2h_name)

            # Read magic to determine format
            fmt = 'UNKNOWN'
            magic = 0
            try:
                with open(m2h_path, 'rb') as f:
                    magic = struct.unpack('<I', f.read(4))[0]
                magic_map = {
                    MS2F_MAGIC: 'MS2F',
                    NS2F_MAGIC: 'NS2F',
                    OS2F_MAGIC: 'OS2F',
                    PS2F_MAGIC: 'PS2F',
                }
                fmt = magic_map.get(magic, f'0x{magic:08X}')
            except Exception:
                pass

            # Determine if this resource is in the Data root (not Resource)
            is_data_root = not ('Resource' in root.replace(data_dir, '').split(os.sep))

            discovered.append({
                'name': prefix,
                'm2h': m2h_path,
                'm2d_files': m2d_files,
                'm2d_count': len(m2d_files),
                'format': fmt,
                'magic': magic,
                'root': root,
                'data_root': is_data_root,
                'total_m2d_size': sum(os.path.getsize(p) for p in m2d_files),
            })

    # Sort by format then name
    discovered.sort(key=lambda x: (x['format'], x['name']))
    return discovered


def count_files_in_m2h(m2h_path, fmt, magic):
    """
    Quick count of files in M2H header without full decryption.
    Returns (file_count, ver) or (None, None) if unreadable.
    """
    try:
        with open(m2h_path, 'rb') as f:
            data = f.read()

        if magic in (MS2F_MAGIC,):
            # Ver1: FileListCount at offset 4+4+8+8+8+8+8+8 = 56
            off = 4
            if magic == MS2F_MAGIC:
                off += 4  # uReserved
                off += 8  # CompressedDataSize
                off += 8  # EncodedDataSize
                off += 8  # HeaderSize
                off += 8  # CompressedHeaderSize
                off += 8  # EncodedHeaderSize
                count = struct.unpack_from('<Q', data, off)[0]
                return count, 1
        elif magic in (NS2F_MAGIC,):
            # Ver2: FileListCount at offset 4+4 = 8 (uint32)
            count = struct.unpack_from('<I', data, 4)[0]
            return count, 2
        elif magic in (OS2F_MAGIC, PS2F_MAGIC):
            # Ver3: HeaderSize at 4+8+8=20, FT count = HeaderSize/40
            hdr_size = struct.unpack_from('<Q', data, 20)[0]
            return hdr_size // 40, 3
        return None, None
    except Exception:
        return None, None


# ── Interactive UI ───────────────────────────────────────────────────

def prompt_directory(prompt_text, default=''):
    """Prompt for a directory path with optional default."""
    print(f"\n{C.C}{prompt_text}{C.X}")
    if default:
        user = input(f"  [{default}]: ").strip()
        return user if user else default
    else:
        while True:
            user = input("  > ").strip()
            if user and os.path.isdir(user):
                return user
            if user:
                warn(f"Directory not found: {user}")
            print("  Please enter a valid directory path.")


def display_resources(discovered):
    """Display discovered resources in a formatted table."""
    if not discovered:
        warn("No M2H/M2D pairs found in this directory.")
        return

    header("Discovered Resources")

    # Column widths
    fmt_width = max(max(len(r['format']) for r in discovered), 6)
    name_width = max(max(len(r['name']) for r in discovered), 4)

    # Table header
    print(f"  {'#':>3s}  {C.G}{'Resource':<{name_width}s}  {'Format':<{fmt_width}s}  {'Files':>7s}  {'M2Ds':>4s}  {'Size':>8s}  {'Dir'}{C.X}")
    print(f"  {'─'*3}  {'─'*name_width}  {'─'*fmt_width}  {'─'*7}  {'─'*4}  {'─'*8}  {'─'*3}")

    total_files = 0
    for i, r in enumerate(discovered):
        fc, ver = count_files_in_m2h(r['m2h'], r['format'], r['magic'])
        fc_str = str(fc) if fc else '?'
        total_files += (fc or 0)

        sz_str = fmt_size(r['total_m2d_size'])
        dir_tag = 'Data' if r['data_root'] else 'Res'
        fmt_color = {'OS2F': C.C, 'MS2F': C.B, 'NS2F': C.M, 'PS2F': C.Y}.get(r['format'], C.W)

        print(f"  {C.G}{i+1:3d}{C.X}  {r['name']:<{name_width}s}  {fmt_color}{r['format']:<{fmt_width}s}{C.X}  {fc_str:>7s}  {r['m2d_count']:4d}  {sz_str:>8s}  {C.Y}{dir_tag}{C.X}")

    print(f"\n  {C.W}Total: {C.G}{total_files:>7d}{C.X} files across {len(discovered)} resource groups")
    return total_files


def fmt_size(size_bytes):
    """Format byte size to human-readable."""
    for unit in ('B', 'KB', 'MB', 'GB'):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def select_resources(discovered):
    """Interactive resource selection menu."""
    choices = [r['name'] for r in discovered]

    print(f"\n{C.C}Select resources to extract:{C.X}")
    print(f"  {C.G}a{C.X} or {C.G}all{C.X}  - Extract all resources")
    print(f"  {C.G}1-{len(discovered)}{C.X}     - Enter numbers separated by commas (e.g. 1,3,5-8)")

    while True:
        user = input("\n  > ").strip().lower()
        if user in ('a', 'all', ''):
            return list(range(len(discovered)))

        # Parse comma-separated numbers and ranges
        selected = set()
        try:
            for part in user.split(','):
                part = part.strip()
                if '-' in part:
                    lo, hi = part.split('-', 1)
                    lo, hi = int(lo.strip()), int(hi.strip())
                    if lo < 1 or hi > len(discovered) or lo > hi:
                        raise ValueError
                    selected.update(range(lo - 1, hi))
                else:
                    n = int(part)
                    if n < 1 or n > len(discovered):
                        raise ValueError
                    selected.add(n - 1)

            if not selected:
                warn("No valid resources selected.")
                continue
            return sorted(selected)

        except (ValueError, IndexError):
            warn(f"Invalid selection. Enter numbers 1-{len(discovered)}, ranges (1-3), or 'all'.")


def confirm_selection(discovered, indices):
    """Show selected resources and confirm."""
    print()
    for i in indices:
        r = discovered[i]
        fc, _ = count_files_in_m2h(r['m2h'], r['format'], r['magic'])
        print(f"  {C.G}{i+1:3d}{C.X} {r['name']} ({r['format']}, ~{fc or '?'} files, {fmt_size(r['total_m2d_size'])})")

    user = input(f"\n{C.C}Proceed with extraction? [Y/n]: {C.X}").strip().lower()
    return user in ('', 'y', 'yes')


# ── Extraction engine ────────────────────────────────────────────────

def load_keys():
    """Load and parse all key tables from orion2_keys.json."""
    if not os.path.exists(KEYS_FILE):
        raise FileNotFoundError(f"Key file not found: {KEYS_FILE}")
    with open(KEYS_FILE) as f:
        k = json.load(f)
    return {
        'osk': [bytes(kk) for kk in k['OS2F_USER_KEY']],
        'oiv': [bytes(iv) for iv in k['OS2F_IV_CHAIN']],
        'msk': [bytes(kk) for kk in k['MS2F_USER_KEY']],
        'miv': [bytes(iv) for iv in k['MS2F_IV_CHAIN']],
        'nsk': [bytes(kk) for kk in k['NS2F_USER_KEY']],
        'niv': [bytes(iv) for iv in k['NS2F_IV_CHAIN']],
        'psk': bytes(k.get('PS2F_XOR_KEY', [])),
        # PS2F XOR key is 512 bytes, repeated 4x = 2048 bytes for rotate
    }


def extract_os2f_resource(r, keys, data_dir, output_dir):
    """
    Extract OS2F resource using pre-decrypted CSV/FT files bundled in SCRIPT_DIR.
    Maintains directory mirroring from CSV paths.
    """
    name = r['name']
    osk, oiv = keys['osk'], keys['oiv']
    prefix = name + '_'

    # Find pre-decrypted files
    csv_file = f"{name}.m2h.header"
    ft_file = f"{name}.filetable.decrypted_v2.bin"

    # Handle Npc special naming
    if name == 'Npc':
        csv_file = 'Npc_02.header'
        ft_file = 'Npc_02.filetable.decrypted_v2.bin'

    csv_path = os.path.join(SCRIPT_DIR, csv_file)
    ft_path = os.path.join(SCRIPT_DIR, ft_file)

    # Check for alternative filenames
    if not os.path.exists(csv_path):
        alt_csv = os.path.join(SCRIPT_DIR, f"{name}.m2h.header")
        if os.path.exists(alt_csv):
            csv_path = alt_csv
    if not os.path.exists(ft_path):
        for alt in [f"{name}.filetable.decrypted.bin", "filetable_decrypted.bin"]:
            alt_ft = os.path.join(SCRIPT_DIR, alt)
            if os.path.exists(alt_ft):
                ft_path = alt_ft
                break

    if not os.path.exists(csv_path):
        warn(f"{name}: CSV file not found ({csv_file}), trying M2H direct parse...")
        return extract_packstream_resource(r, keys, data_dir, output_dir)
    if not os.path.exists(ft_path):
        warn(f"{name}: FT file not found ({ft_file})")
        return 0, 0

    csv_entries = load_predecrypted_csv(os.path.basename(csv_path))
    ft_entries = load_predecrypted_ft(os.path.basename(ft_path))

    files_by_m2d = defaultdict(list)
    for i, e in enumerate(ft_entries):
        if i >= len(csv_entries):
            break
        idx, m2d_id, path = csv_entries[i]
        files_by_m2d[m2d_id].append((idx, path, e))

    # Determine output base
    # Mirror the source structure: if source is in Model/Name, output in Resource/Model/Name
    rel_root = os.path.relpath(r['root'], data_dir)

    out_dir = os.path.join(output_dir, rel_root, name) if rel_root != '.' else os.path.join(output_dir, 'Resource', name)
    os.makedirs(out_dir, exist_ok=True)

    total_files = len(files_by_m2d)
    total_size = r['total_m2d_size']
    header(f"Extracting {name} (OS2F) — {', '.join(str(len(v)) for v in files_by_m2d.values())} files, {fmt_size(total_size)}")

    ok_total = bad_total = 0
    m2d_list = sorted(files_by_m2d.keys())
    it = tqdm(m2d_list, desc=f'  {name}', unit='m2d') if HAS_TQDM else m2d_list

    for m2d_id in it:
        files = files_by_m2d[m2d_id]
        fpath = os.path.join(r['root'], f'{prefix}{m2d_id}.m2d')
        if not os.path.exists(fpath):
            bad_total += len(files)
            continue
        with open(fpath, 'rb') as f:
            m2d = f.read()
        ok = 0
        for idx, rel_path, entry in files:
            off, size = entry['offset'], entry['block_size']
            if off + size > len(m2d):
                bad_total += 1
                continue
            block = m2d[off:off + size]
            clean = block.replace(b'=', b'')
            pad = (4 - len(clean) % 4) % 4
            if pad == 3:
                bad_total += 1
                continue
            try:
                decoded = base64.b64decode(clean + b'=' * pad)
            except Exception:
                bad_total += 1
                continue
            ki = len(decoded) & 0x7F
            try:
                dec = aes_ctr_ecb(osk[ki], oiv[ki], decoded)
            except Exception:
                bad_total += 1
                continue
            if dec[0] == 0x78 and dec[1] in (0x01, 0x5E, 0x9C, 0xDA):
                try:
                    dec = zlib.decompress(dec)
                except Exception:
                    bad_total += 1
                    continue
            op = os.path.join(out_dir, rel_path.replace('/', os.sep))
            os.makedirs(os.path.dirname(op), exist_ok=True)
            with open(op, 'wb') as f:
                f.write(dec)
            ok += 1
        ok_total += ok
        bad_total += len(files) - ok

    total = ok_total + bad_total
    pc = ok_total * 100 // total if total else 0
    if bad_total:
        warn(f"{name}: {ok_total}/{total} ({pc}%), {bad_total} failed")
    else:
        ok(f"{name}: {ok_total}/{total} ({pc}%)")
    return ok_total, bad_total


def extract_ps2f_resource(r, keys, data_dir, output_dir):
    """
    Extract PS2F (Movie) resource using XOR decryption.
    """
    name = r['name']
    psk = keys['psk']
    if not psk:
        warn(f"{name}: PS2F_XOR_KEY missing in key file")
        return 0, 0

    # Build XOR key: 512 bytes repeated 4x
    xor_key = psk * 4

    # Find pre-decrypted CSV/FT
    csv_path = os.path.join(SCRIPT_DIR, f"{name}.m2h.header")
    ft_path = os.path.join(SCRIPT_DIR, f"{name}.filetable.decrypted_v2.bin")

    if not os.path.exists(csv_path) or not os.path.exists(ft_path):
        warn(f"{name}: Pre-decrypted CSV/FT files not found")
        return 0, 0

    csv_entries = load_predecrypted_csv(os.path.basename(csv_path))
    ft_entries = load_predecrypted_ft(os.path.basename(ft_path))

    csv_m2d_set = {m2d_id for (_, m2d_id, _) in csv_entries}

    # Build size-to-m2d mapping for unnamed entries
    size_to_m2d = {}
    if os.path.isdir(r['root']):
        prefix = name + '_'
        for fname in os.listdir(r['root']):
            if fname.startswith(prefix) and fname.endswith('.m2d'):
                mid = fname[len(prefix):-4]
                if mid not in csv_m2d_set:
                    fsz = os.path.getsize(os.path.join(r['root'], fname))
                    if fsz not in size_to_m2d:
                        size_to_m2d[fsz] = mid

    files_by_m2d = defaultdict(list)
    extra_from_size = 0

    for i, e in enumerate(ft_entries):
        if i >= len(csv_entries):
            sz = e['block_size']
            if sz in size_to_m2d:
                m2d_id = size_to_m2d[sz]
                del size_to_m2d[sz]
                path = f'unknown/unnamed_{i:04d}.usm'
                extra_from_size += 1
            else:
                m2d_id = f'unnamed_{i}'
                path = f'unnamed_{i}_sz_{sz}.usm'
        else:
            _, m2d_id, path = csv_entries[i]
        files_by_m2d[m2d_id].append((i, path, e))

    rel_root = os.path.relpath(r['root'], data_dir)
    out_dir = os.path.join(output_dir, rel_root, name) if rel_root != '.' else os.path.join(output_dir, 'Resource', name)
    os.makedirs(out_dir, exist_ok=True)

    total = len(files_by_m2d)
    header(f"Extracting {name} (PS2F XOR) — {sum(len(v) for v in files_by_m2d.values())} files, {total} M2Ds, {fmt_size(r['total_m2d_size'])}")
    if extra_from_size:
        info(f"Size-matched unnamed entries: {extra_from_size}")

    ok_total = bad_total = 0
    prefix = name + '_'
    m2d_list = sorted(files_by_m2d.keys())
    it = tqdm(m2d_list, desc=f'  {name}', unit='m2d') if HAS_TQDM else m2d_list

    for m2d_id in it:
        files = files_by_m2d[m2d_id]
        fpath = os.path.join(r['root'], f'{prefix}{m2d_id}.m2d')
        if not os.path.exists(fpath):
            bad_total += len(files)
            continue
        ok = 0
        for idx, rel_path, entry in files:
            off, size, flag = entry['offset'], entry['block_size'], entry['flag']
            if flag not in (XOR, XOR_ZLIB):
                bad_total += 1
                continue
            try:
                with open(fpath, 'rb') as f:
                    f.seek(off)
                    block = f.read(size)
                dec = xor_decrypt(block, xor_key)
                if flag == XOR_ZLIB:
                    if dec[0] == 0x78 and dec[1] in (0x01, 0x5E, 0x9C, 0xDA):
                        dec = zlib.decompress(dec)
                    else:
                        bad_total += 1
                        continue
            except Exception:
                bad_total += 1
                continue
            op = os.path.join(out_dir, rel_path.replace('/', os.sep))
            os.makedirs(os.path.dirname(op), exist_ok=True)
            with open(op, 'wb') as f:
                f.write(dec)
            ok += 1
        ok_total += ok
        bad_total += len(files) - ok

    total = ok_total + bad_total
    pc = ok_total * 100 // total if total else 0
    if bad_total:
        warn(f"{name}: {ok_total}/{total} ({pc}%), {bad_total} failed")
    else:
        ok(f"{name}: {ok_total}/{total} ({pc}%)")
    return ok_total, bad_total


def extract_packstream_resource(r, keys, data_dir, output_dir):
    """
    Extract MS2F/NS2F PackStream resource by directly parsing M2H header.
    Works for Gfx (Ver1) and Xml (Ver2).
    Also falls back for OS2F when pre-decrypted files are unavailable.
    """
    name = r['name']
    magic = r['magic']

    if magic == MS2F_MAGIC:
        ver = 1
        key_tab, iv_tab = keys['msk'], keys['miv']
        ft_parser = parse_filetable_ver1
        ft_entry_size = 48
    elif magic == NS2F_MAGIC:
        ver = 2
        key_tab, iv_tab = keys['nsk'], keys['niv']
        ft_parser = parse_filetable_ver2
        ft_entry_size = 36
    elif magic == OS2F_MAGIC:
        # OS2F: try PackStreamVer3 style parsing
        # The M2H for multi-M2D OS2F resources contains the header inline
        warn(f"{name}: OS2F PackStreamVer3 direct parse not yet implemented, skipped")
        return 0, 0
    else:
        err(f"{name}: Unsupported magic 0x{magic:08X}")
        return 0, 0

    m2h_path = r['m2h']
    m2d_path = r['m2d_files'][0] if r['m2d_files'] else None

    if not m2d_path or not os.path.exists(m2d_path):
        err(f"{name}: M2D file not found")
        return 0, 0

    with open(m2h_path, 'rb') as f:
        m2h_data = f.read()

    # Parse stream header
    off = 4
    if ver == 1:
        hdr = parse_stream_v1(m2h_data, off)
    else:
        hdr = parse_stream_v2(m2h_data, off)

    off = hdr['_next']

    # Decrypt CSV (file paths)
    enc_csv = m2h_data[off:off + hdr['EncodedHeaderSize']]
    off += hdr['EncodedHeaderSize']
    csv_ki = hdr['CompressedHeaderSize'] & 0x7F
    csv_decoded = base64.b64decode(enc_csv)
    csv_decrypted = aes_ctr_ecb(key_tab[csv_ki], iv_tab[csv_ki], csv_decoded)
    csv_text = zlib.decompress(csv_decrypted).decode('utf-8', errors='replace')

    info(f"CSV: compressed={hdr['CompressedHeaderSize']} key={csv_ki} raw={len(csv_text)}B {hdr['FileListCount']} files")

    # Parse CSV
    file_names = {}
    for line in csv_text.split('\r\n'):
        line = line.strip()
        if not line:
            continue
        parts = line.split(',')
        if len(parts) >= 2:
            try:
                idx = int(parts[0])
                nm = parts[-1] if len(parts) <= 2 else parts[2]
                file_names[idx] = nm
            except ValueError:
                pass

    # Decrypt FT
    enc_ft = m2h_data[off:off + hdr['EncodedDataSize']]
    ft_ki = hdr['CompressedDataSize'] & 0x7F
    ft_decoded = base64.b64decode(enc_ft)
    ft_decrypted = aes_ctr_ecb(key_tab[ft_ki], iv_tab[ft_ki], ft_decoded)
    ft_raw = zlib.decompress(ft_decrypted)
    ft_entries = ft_parser(ft_raw, hdr['FileListCount'])

    info(f"FT: compressed={hdr['CompressedDataSize']} key={ft_ki} raw={len(ft_raw)}B {len(ft_entries)} entries")

    # Determine output directory
    if r['data_root']:
        out_dir = os.path.join(output_dir, 'Data', name)
    else:
        rel_root = os.path.relpath(r['root'], data_dir)
        out_dir = os.path.join(output_dir, rel_root, name) if rel_root != '.' else os.path.join(output_dir, 'Resource', name)
    os.makedirs(out_dir, exist_ok=True)

    header(f"Extracting {name} ({r['format']}) — {len(ft_entries)} files, {fmt_size(r['total_m2d_size'])}")

    ok_total = bad_total = 0
    with open(m2d_path, 'rb') as m2d_f:
        it = tqdm(ft_entries, desc=f'  {name}', unit='file') if HAS_TQDM else ft_entries
        for entry in it:
            idx = entry['FileIndex']
            encoded_sz = entry['EncodedFileSize']
            comp_sz = entry['CompressedFileSize']
            buf_flag = entry['BufferFlag']
            off_m2d = entry['Offset']

            if encoded_sz == 0 or comp_sz == 0:
                bad_total += 1
                continue

            m2d_f.seek(off_m2d)
            block = m2d_f.read(encoded_sz)

            if len(block) != encoded_sz:
                bad_total += 1
                continue

            try:
                bits = struct.pack('<I', buf_flag)
                if (bits[3] & 1) == 0:
                    ki = comp_sz & 0x7F
                    decoded = base64.b64decode(block)
                    data = aes_ctr_ecb(key_tab[ki], iv_tab[ki], decoded)
                else:
                    data = block
                if bits[0] != 0:
                    data = zlib.decompress(data)
            except Exception:
                bad_total += 1
                continue

            path = file_names.get(idx, f'unnamed_{idx:06d}')
            op = os.path.join(out_dir, path.replace('/', os.sep))
            os.makedirs(os.path.dirname(op), exist_ok=True)
            with open(op, 'wb') as f:
                f.write(data)
            ok_total += 1

    total = ok_total + bad_total
    pc = ok_total * 100 // total if total else 0
    if bad_total:
        warn(f"{name}: {ok_total}/{total} ({pc}%), {bad_total} failed")
    else:
        ok(f"{name}: {ok_total}/{total} ({pc}%)")
    return ok_total, bad_total


def extract_ms2f_single_resource(r, keys, data_dir, output_dir):
    """Extract single-file MS2F resource (entire M2D = one base64+zlib block)."""
    name = r['name']
    msk, miv = keys['msk'], keys['miv']

    m2d_path = r['m2d_files'][0] if r['m2d_files'] else None
    if not m2d_path or not os.path.exists(m2d_path):
        err(f"{name}: M2D not found")
        return 0, 0

    with open(m2d_path, 'rb') as f:
        raw = f.read()

    rel_root = os.path.relpath(r['root'], data_dir)
    out_dir = os.path.join(output_dir, rel_root, name) if rel_root != '.' else os.path.join(output_dir, 'Resource', name)
    os.makedirs(out_dir, exist_ok=True)

    try:
        decoded = base64.b64decode(raw)
        ki = len(decoded) & 0x7F
        dec = aes_ctr_ecb(msk[ki], miv[ki], decoded)
        if dec[0] == 0x78 and dec[1] in (0x01, 0x5E, 0x9C, 0xDA):
            dec = zlib.decompress(dec)
    except Exception as e:
        err(f"{name}: Decrypt failed: {e}")
        return 0, 1

    out_path = os.path.join(out_dir, f'{name}')
    with open(out_path, 'wb') as f:
        f.write(dec)
    ok(f"{name} (MS2F key {ki}): {len(raw)//1024} KB -> {len(dec)//1024} KB")
    return 1, 0


# ── Main interactive flow ────────────────────────────────────────────

def main():
    print(f"\n{C.W}╔{'═'*58}╗{C.X}")
    print(f"{C.W}║{C.X}  {C.C}MapleStory2 M2D Interactive Extractor{C.X}" + ' ' * 20 + f"{C.W}║{C.X}")
    print(f"{C.W}║{C.X}  Orion2 PackStreamVer 1/2/3  |  key = comp_size & 0x7F" + ' ' * 12 + f"{C.W}║{C.X}")
    print(f"{C.W}╚{'═'*58}╝{C.X}")

    if not os.path.exists(KEYS_FILE):
        err(f"Key file not found: {KEYS_FILE}")
        err("Place orion2_keys.json in the same directory as this script.")
        sys.exit(1)

    if not HAS_MODULE:
        err("ms2_extract_all.py not found in script directory.")
        err("Both scripts must be in the same folder.")
        sys.exit(1)

    # 1. Prompt for data directory
    data_dir = prompt_directory("Enter game Data directory path", default='')
    if not data_dir or not os.path.isdir(data_dir):
        err("Invalid directory.")
        sys.exit(1)
    info(f"Scanning: {data_dir}")

    # 2. Scan for resources
    discovered = scan_resources(data_dir)

    if not discovered:
        print(f"\n{C.R}No M2H/M2D resource pairs found in this directory.{C.X}")
        print("Make sure you're pointing to the correct 'Data' folder containing .m2h and .m2d files.")
        sys.exit(1)

    # 3. Display discovered resources
    total = display_resources(discovered)

    # 4. Select resources
    indices = select_resources(discovered)

    if not indices:
        return

    # 5. Confirm
    if not confirm_selection(discovered, indices):
        print(f"\n{C.Y}Aborted.{C.X}")
        return

    # 6. Prompt for output directory
    default_out = os.path.join(SCRIPT_DIR, 'extracted')
    output_dir = prompt_directory("Enter output directory", default=default_out)
    os.makedirs(output_dir, exist_ok=True)
    info(f"Output: {output_dir}")

    # 7. Load keys
    keys = load_keys()

    # 8. Extract selected resources
    grand_ok = grand_bad = 0

    for i in indices:
        r = discovered[i]
        fmt = r['format']

        try:
            if fmt == 'OS2F':
                # Try pre-decrypted CSV/FT first, fallback to PackStream
                ok_n, bad_n = extract_os2f_resource(r, keys, data_dir, output_dir)
                grand_ok += ok_n
                grand_bad += bad_n
            elif fmt == 'PS2F':
                ok_n, bad_n = extract_ps2f_resource(r, keys, data_dir, output_dir)
                grand_ok += ok_n
                grand_bad += bad_n
            elif fmt == 'MS2F':
                if r['m2d_count'] == 1 and r.get('total_m2d_size', 0) < 100 * 1024 * 1024:
                    # Small single M2D → single-file resource (Library, Shaders, etc.)
                    ok_n, bad_n = extract_ms2f_single_resource(r, keys, data_dir, output_dir)
                else:
                    # Multi-file PackStream → parse M2H directly (Gfx)
                    ok_n, bad_n = extract_packstream_resource(r, keys, data_dir, output_dir)
                grand_ok += ok_n
                grand_bad += bad_n
            elif fmt == 'NS2F':
                ok_n, bad_n = extract_packstream_resource(r, keys, data_dir, output_dir)
                grand_ok += ok_n
                grand_bad += bad_n
            else:
                warn(f"{r['name']}: Unknown format {fmt}, skipped")
        except Exception as e:
            err(f"{r['name']}: Unexpected error: {e}")
            import traceback
            traceback.print_exc()

    # 9. Summary
    total = grand_ok + grand_bad
    header("Extraction Complete")
    if grand_bad:
        print(f"  {C.G}Success: {grand_ok}{C.X}  |  {C.R}Failed: {grand_bad}{C.X}  |  {C.W}Total: {total}{C.X}")
        warn("Some files failed. Check the output above for details.")
    else:
        print(f"  {C.G}All {grand_ok} files extracted successfully!{C.X}")

    print(f"  Output: {C.C}{output_dir}{C.X}")
    print()


if __name__ == '__main__':
    main()
