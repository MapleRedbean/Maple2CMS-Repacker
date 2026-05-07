# MapleStory2 M2D Universal Extractor v7

Universal M2D/M2H archive decryption, extraction, and repacking toolkit.
Built from Orion2-Repacker2026 source analysis.
Full support for **CMS / GMS / KMS** clients.

---

## Extraction Overview — 15 Resources at 100%

| Resource | CMS | GMS | KMS | Output Formats |
|----------|-----|-----|-----|----------------|
| Image | 18,536 | 1,053,408 | — | PNG / DDS / BMP |
| Exported | 15,305 | 730,560 | 15,330 | .flat / .xblock |
| Map | 21,551 | 1,028,736 | — | .nif (Gamebryo v30) |
| Effect | 16,535 | 753,984 | — | .nif |
| Item | 8,177 | 13,344 | — | .nif |
| Npc / NPC | 37,097 | 1,752,048 | — | .kfm / .kf / .nif |
| Textures | 34,446 | 1,590,048 | — | .dds |
| Movie | 392 | 48 | — | .usm (CRI USM) |
| Gfx | 1,360 | 64,080 | — | .gfx / .dds |
| Xml | 45,273 | 5,574,624 | — | .xml |
| Library / Shaders / etc. | 2,340 (5 resources) | 5 resources | — | .fxo / .xml / .nt / .ini / .bin |

---

## CMS / GMS / KMS Architecture Comparison

| Property | CMS (China) | GMS (Global) | KMS (Korea) |
|----------|------------|-------------|------------|
| **M2H Format** | OS2F/PS2F Ver3 | MS2F PackStreamVer1 | MS2F PackStreamVer1 |
| **M2D Format** | Multi-volume split | Single M2D | Single M2D |
| **M2D Magic** | `OS2F` / `PS2F` | `MS2F` | `yVNZ` |
| **Encryption** | AES-CTR + XOR | AES-CTR | AES-CTR (custom keys) |
| **Key Table** | OS2F + PS2F | MS2F (=CMS MS2F) | KMS standalone |
| **Total Files** | ~500K | ~12.8M | — |
| **Orphan M2Ds** | 483 (~9.3 GB) | 0 | — |

> **Summary**: KMS = GMS (MS2F single-M2D architecture) ≠ CMS (OS2F multi-M2D architecture)

---

## Resource Directory Mapping (CMS)

| Resource | Data Subdirectory |
|----------|-------------------|
| Xml | `Data/` |
| Precompiled | `Data/lua/` |
| Image, Exported, Movie, Gfx, Shaders, Library, asset-web-*, Camera, Character, Common | `Data/Resource/` |
| Map, Effect, Item, Npc, Textures, Tool, Path | `Data/Resource/Model/` |
| PrecomputedTerrain | `Data/Resource/` |

---

## Requirements

```bash
pip install -r requirements.txt
```

Python 3.7+, pycryptodome, tqdm (optional).

---

## Usage

### Interactive Extraction (Recommended)

```bash
python ms2_interactive.py
```

Workflow: enter data directory → auto-scan → select resources → enter output directory → extract.
Auto-detects format and supports CMS/GMS/KMS.

### CLI Extraction

```bash
# Extract everything
python ms2_extract_all.py -d "D:\WeGameApps\冒险岛2\Client\Data" -o ./output

# Extract specific resource
python ms2_extract_all.py -r Gfx -d "<data_dir>" -o ./output
```

Available resources: Image, Exported, Map, Effect, Item, Npc, Textures, Movie,
Gfx, Xml, Library, Shaders, PrecomputedTerrain, asset-web-config, asset-web-metadata, and more.

### Interactive Repacking (Recommended)

```bash
python ms2_interactive_pack.py
```

Workflow: enter extracted directory → auto-scan resources → select → choose output format → specify Data directory → pack.

**Format Selection** (Step 3.5):
- `[1] MS2F` — Single M2D (recommended, Orion2-Repacker compatible)
- `[2] OS2F` — Multi-volume M2D (classic CMS)
- `[3] Auto` — Keep original format

Supports CMS OS2F → MS2F cross-format conversion. Movie sub-resources (common / emotion / item) can be independently packed as MS2F.

### CLI Repacking

```bash
# OS2F (CMS main resources, multi-volume)
python ms2_pack.py -i ./modified -r Image -o ./output --max-m2d-size 200

# MS2F (GMS/KMS all resources, single M2D)
python ms2_pack.py -i ./gfx_mod -r Gfx -o ./output

# NS2F (Xml)
python ms2_pack.py -i ./xml_mod -r Xml -o ./output
```

Supports 33 resource types across all four formats (OS2F×7 + PS2F×1 + MS2F×24 + NS2F×1).

---

## Decryption Pipeline

### Universal Key Formula

```
key_index = compressed_size & 0x7F
```

Unifies key derivation for OS2F / MS2F / NS2F AES encryption.
Derived from `CipherKeys.GetKeyAndIV(uVer, uLenCompressed)`.

### AES-CTR Implementation

Byte-identical to Orion2 `AESCipher.cs`: 16-byte IV chain entry as counter, AES-ECB encrypts counter to produce keystream, counter increments as big-endian 128-bit integer.

### Four Formats

| Format | Magic (LE) | FT Entry | Pipeline | Used By |
|--------|-----------|----------|----------|---------|
| MS2F | `0x4632534D` | 48B | base64 → AES-CTR → zlib | GMS/KMS all resources |
| NS2F | `0x4632534E` | 36B | base64 → AES-CTR → zlib | CMS Xml |
| OS2F | `0x4632534F` | 40B | base64 → AES-CTR → zlib | CMS main resources |
| PS2F | `0x46325350` | 40B | XOR 32-bit rotate | CMS Movie |

### PackStream M2H Flow

```
M2H → PackStream header → EncodedHeader → base64 → AES → zlib → CSV
                         → EncodedData   → base64 → AES → zlib → FT
M2D → per FT entry → base64 → AES → zlib → raw file
```

---

## M2H Header Layouts

### PackStreamVer1 (MS2F, 64B)
```
magic(4) + uReserved(4) + CompressedDataSize(8) + EncodedDataSize(8) +
HeaderSize(8) + CompressedHeaderSize(8) + EncodedHeaderSize(8) +
FileListCount(8) + DataSize(8)
```

### PackStreamVer2 (NS2F, 56B)
```
magic(4) + FileListCount(4) + CompressedDataSize(8) + EncodedDataSize(8) +
HeaderSize(8) + CompressedHeaderSize(8) + EncodedHeaderSize(8) + DataSize(8)
```

### PackStreamVer3 (OS2F/PS2F, 60B)
```
magic(4) + FileListCount(4) + Reserved(4) + CompressedDataSize(8) +
EncodedDataSize(8) + CompressedHeaderSize(8) + EncodedHeaderSize(8) +
DataSize(8) + HeaderSize(8)
```

---

## FileTable Entry Layouts

| Version | Entry Size | Field Layout |
|---------|-----------|--------------|
| Ver1 (MS2F) | 48B | PackingDef(4)+FileIndex(4)+BufferFlag(4)+Reserved(4)+Offset(8)+EncodedSize(4)+Reserved(4)+CompressedSize(8)+FileSize(8) |
| Ver2 (NS2F) | 36B | BufferFlag(4)+FileIndex(4)+EncodedSize(4)+CompressedSize(8)+FileSize(8)+Offset(8) |
| Ver3 (OS2F/PS2F) | 40B | BufferFlag(4)+FileIndex(4)+EncodedSize(4)+Reserved(4)+CompressedSize(8)+FileSize(8)+Offset(8) |

---

## Encryption Keys

`orion2_keys.json` — 7 key tables:

| Table | Entries | Per Entry | Purpose |
|-------|---------|-----------|---------|
| OS2F_USER_KEY | 128 | 32B | CMS OS2F resources |
| OS2F_IV_CHAIN | 128 | 16B | CMS OS2F resources |
| MS2F_USER_KEY | 128 | 32B | GMS + CMS MS2F |
| MS2F_IV_CHAIN | 128 | 16B | GMS + CMS MS2F |
| NS2F_USER_KEY | 128 | 32B | CMS Xml |
| NS2F_IV_CHAIN | 128 | 16B | CMS Xml |
| PS2F_XOR_KEY | 512 | int | CMS Movie |

> ⚠️ KMS uses an independent key table not included in this project.

---

## Project Files

```
├── README.md / README_ENG.md
├── requirements.txt
├── orion2_keys.json                 # 7 key tables
├── ms2_extract_all.py               # CLI extraction tool
├── ms2_interactive.py               # Interactive extraction tool
├── ms2_pack.py                      # CLI repacking tool
├── ms2_interactive_pack.py          # Interactive repacking tool (recommended)
│
├── Image.m2h.header                 # CMS pre-decrypted CSV/FT (OS2F/PS2F only)
├── filetable_decrypted.bin
├── Exported.m2h.header
├── ...
└── Movie.filetable.decrypted_v2.bin
```

> Gfx / Xml / GMS / KMS resources are parsed directly from M2H headers — no pre-decrypted files needed.

---

## Key Technical Discoveries

1. **Universal key formula**: `key_index = compressed_size & 0x7F` from `CipherKeys.GetKeyAndIV()`
2. **AES-CTR implementation**: 16-byte IV counter + AES-ECB, byte-identical to Orion2 `AESCipher.cs` — ensures packed files are readable by Orion2-Repacker
3. **PackStreamVer1/2/3 end-to-end parsing & repacking**: All four formats fully supported for M2H header construction + CSV/FT encryption + file data encryption
4. **CMS → MS2F cross-format conversion**: OS2F/PS2F resources can be converted to GMS-style single M2D, Orion2-Repacker compatible
5. **CMS orphan M2Ds**: 483 unreferenced M2D files (~9.3 GB), including Npc_11/21/23 and hash-encoded legacy data
6. **KMS M2D magic**: `yVNZ` (0x5A4E5679), same structure as GMS MS2F but with independent key table

---

## References

- Orion2-Repacker2026: Original MapleStory2 C# unpacker/repacker
- `CipherKeys.cs`: `GetKeyAndIV(uVer, uLenCompressed)` — universal key formula source
- `AESCipher.cs`: AES-CTR implementation reference
- `CryptoMan.cs`: Complete encryption/decryption pipeline
- `PackStreamVer1.cs` / `PackStreamVer2.cs` / `PackStreamVer3.cs`: M2H header parsing
- `PackFileHeaderVer1.cs` / `PackFileHeaderVer2.cs` / `PackFileHeaderVer3.cs`: FT entry layouts

For educational and research purposes only.
