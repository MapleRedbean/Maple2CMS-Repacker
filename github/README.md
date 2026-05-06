# MapleStory2 Resource Extractors

冒险岛2（MapleStory2）资源文件批量提取工具集。

## 提取总览

| 资源包 | 格式 | 文件数 | 提取率 | 文件格式 |
|--------|------|--------|--------|----------|
| Image | OS2F | 18,536 | **100%** | PNG: 16,541 / DDS: 1,992 / BMP: 2 |
| Exported | OS2F | 15,305 | **100%** | .flat: 13,378 / .xblock: 1,927 |
| Map | OS2F | 21,551 | **100%** | .nif (Gamebryo) |
| Effect | OS2F | 16,535 | **100%** | .nif (Gamebryo) |
| Item | OS2F | 8,193 | **99.8%** | .nif (Gamebryo) |
| Npc | OS2F | 37,097 | **100%** | .kfm / .kf / .nif |
| Textures | OS2F | 34,446 | **100%** | .dds |
| Movie | **PS2F** | 392 | **100%** | .usm (CRI USM) |
| **合计** | | **152,055** | **~99.9%** | |

## 环境要求

```bash
pip install pycryptodome
```

Python 3.7+

---

## 通用提取工具

一次提取所有资源（Image / Exported / Map / Effect / Item / Npc / Textures / Movie）：

```bash
# 提取全部
python ms2_extract_all.py --data-dir "D:\WeGameApps\冒险岛2\Client\Data"

# 只提取指定资源（支持 Image/Exported/Map/Effect/Item/Npc/Textures/Movie）
python ms2_extract_all.py --resource Movie --data-dir "D:\WeGameApps\冒险岛2\Client\Data"

# 指定输出目录
python ms2_extract_all.py --output-dir D:\output
```

---

## 解密方案

### OS2F（7 类资源：Image~Textures）
```
M2D → base64 解码 → AES-CTR(ECB, key=file_size&0x7F) → zlib 解压 → 原始文件
```

### PS2F（Movie）
```
M2D → XOR(PS2F_XOR_KEY, 2048B循环, 32位字) → 原始 .usm 文件
（无 base64 编码，无 zlib 压缩）
```

### Movie M2H 解密
```
M2H → base64 分两段:
  CSV: base64 → AES-CTR(PS2F key[depends]) → zlib → CSV
  FT:  base64 → AES-CTR(PS2F key[100], len&0x7F) → zlib → FT (40B×392)
```

---

## FileTable 格式（OS2F & PS2F）

每个条目 40 字节，10 个 uint32：

| 偏移 | OS2F 字段 | PS2F 字段 | 含义 |
|------|-----------|-----------|------|
| +0x00 | V0 | V0 | 加密标志（0xEE000009=AES+zlib, 0xFF000000=XOR） |
| +0x04 | V1 | V1 | 文件索引 |
| +0x08 | V2 | V2 | block_size（M2D 中的块大小） |
| +0x10 | V4 | V4 | file_size（OS2F: key推导用; PS2F: 原始文件大小） |
| +0x18 | V6 | V6 | raw_size（解压后大小） |
| +0x20 | V8 | V8 | offset（M2D 中的字节偏移） |

---

## 文件清单

```
github/                             14.5 MB
├── ms2_extract_all.py              ← 通用提取工具（OS2F + PS2F）
├── ms2_image_extract.py            ← Image 单资源提取（旧版）
├── ms2_exported_extract.py         ← Exported 单资源提取（旧版）
├── orion2_keys.json                ← 密钥表（含 PS2F_XOR_KEY）
├── requirements.txt                ← pip install pycryptodome
├── README.md
│
├── Image.m2h.header + filetable_decrypted.bin
├── Exported.m2h.header + Exported.filetable.decrypted.bin
├── Map.m2h.header + Map.filetable.decrypted_v2.bin
├── Effect.m2h.header + Effect.filetable.decrypted_v2.bin
├── Item.m2h.header + Item.filetable.decrypted_v2.bin
├── Npc_02.header + Npc_02.filetable.decrypted_v2.bin
├── Textures.m2h.header + Textures.filetable.decrypted_v2.bin
└── Movie.m2h.header + Movie.filetable.decrypted_v2.bin
```

---

## 不可提取资源

| 资源 | 原因 |
|------|------|
| Xml.m2h (NS2F) | 有专用工具，不在此工具包内 |
| MS2F 资源（Gfx/Library/Shaders等） | 已由 Orion2-Repacker 直接解压 |

仅供学习研究使用。
