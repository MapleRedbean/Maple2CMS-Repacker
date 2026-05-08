# MapleStory2 M2D Universal Extractor v7 testing

冒险岛2 资源文件批量解密提取 / 打包工具，基于 Orion2-Repacker2026 源码分析实现。
全面支持 **CMS / GMS / KMS** 三种客户端。

---

## 提取总览 — 15 类资源 100% 覆盖

| 资源 | CMS | GMS | KMS | 文件格式 |
|------|-----|-----|-----|----------|
| Image | 18,536 ✅ | 1,053,408 MS2F | — | PNG / DDS / BMP |
| Exported | 15,305 ✅ | 730,560 MS2F | 15,330 MS2F | .flat / .xblock |
| Map | 21,551 ✅ | 1,028,736 MS2F | — | .nif (Gamebryo v30) |
| Effect | 16,535 ✅ | 753,984 MS2F | — | .nif |
| Item | 8,177 ✅ | 13,344 MS2F | — | .nif |
| Npc / NPC | 37,097 ✅ | 1,752,048 MS2F | — | .kfm / .kf / .nif |
| Textures | 34,446 ✅ | 1,590,048 MS2F | — | .dds |
| Movie | 392 ✅ | 48 MS2F | — | .usm |
| Gfx | 1,360 ✅ | 64,080 MS2F | — | .gfx / .dds |
| Xml | 45,273 ✅ | 5,574,624 MS2F | — | .xml |
| Library / Shaders / etc. | 2,340 (5 resources) ✅ | 5 resources MS2F | — | .fxo / .xml / .nt / .ini / .bin |

---

## CMS / GMS / KMS 架构对比

| 属性 | CMS (国服) | GMS (国际服) | KMS (韩服) |
|------|-----------|------------|-----------|
| **M2H 格式** | OS2F/PS2F Ver3 | MS2F PackStreamVer1 | MS2F PackStreamVer1 |
| **M2D 格式** | 多 M2D 分卷 | 单 M2D | 单 M2D |
| **M2D 魔数** | `OS2F`/`PS2F` | `MS2F` | `yVNZ` |
| **加密** | AES-CTR + XOR | AES-CTR | AES-CTR (独立密钥) |
| **密钥表** | OS2F + PS2F | MS2F (=CMS) | KMS 独立 |
| **文件数** | ~50 万 | ~1,280 万 | — |
| **孤儿 M2D** | 483 个 (~9.3 GB) | 0 | — |

> **结论**: KMS = GMS（MS2F 单 M2D 架构）≠ CMS（OS2F 多 M2D 分卷架构）

---

## 资源目录映射 (CMS)

| 资源 | Data 子目录 |
|------|------------|
| Xml | `Data/` |
| Precompiled | `Data/lua/` |
| Image, Exported, Movie, Gfx, Shaders, Library, asset-web-*, Camera, Character, Common | `Data/Resource/` |
| Map, Effect, Item, Npc, Textures, Tool, Path | `Data/Resource/Model/` |
| PrecomputedTerrain | `Data/Resource/` |

---

## 环境要求

```bash
pip install -r requirements.txt
```

Python 3.7+, pycryptodome, tqdm (可选).

---

## 使用方法

### 交互式提取（推荐）

```bash
python ms2_interactive.py
```

交互流程：输入资源目录 → 自动扫描 → 选择资源 → 输入输出目录 → 自动提取。内置格式检测，支持 CMS/GMS/KMS。

### 命令行提取

```bash
# 提取全部
python ms2_extract_all.py -d "D:\WeGameApps\冒险岛2\Client\Data" -o ./output

# 提取指定资源（CMS: Image/Exported/Map/Effect/Item/Npc/Textures/Movie/Gfx/Xml/...）
python ms2_extract_all.py -r Gfx -d "D:\...\Data" -o ./output
```

### 交互式打包（推荐）

```bash
python ms2_interactive_pack.py
```

交互流程：输入解包目录 → 自动扫描资源 → 选择资源 → 选择输出格式 → 指定 Data 目录 → 自动打包。

**格式选择**（Step 3.5）：
- `[1] MS2F` — 单 M2D（推荐，兼容 GMS/Orion2-Repacker）
- `[2] OS2F` — 多 M2D 分卷（经典 CMS）
- `[3] Auto` — 保持原始格式

支持 CMS OS2F → MS2F 跨格式转换。Movie 子资源（common / emotion / item）可独立打包为 MS2F。

### 命令行打包

```bash
# OS2F (CMS 主资源，多 M2D 分卷)
python ms2_pack.py -i ./modified -r Image -o ./output --max-m2d-size 200

# MS2F (GMS/KMS 全部资源，单 M2D)
python ms2_pack.py -i ./gfx_mod -r Gfx -o ./output

# NS2F (Xml)
python ms2_pack.py -i ./xml_mod -r Xml -o ./output
```

支持 33 种资源类型（OS2F×7 + PS2F×1 + MS2F×24 + NS2F×1）。

---

## 解密方案

### 通用密钥公式

```
key_index = compressed_size & 0x7F
```

统一 OS2F / MS2F / NS2F 三种 AES 加密格式的密钥推导。

### AES-CTR 实现

与 Orion2 `AESCipher.cs` 完全一致：16 字节计数器 = IV 链条目，AES-ECB 加密计数器产生密钥流，计数器大端 128 位递增。

### 四种格式

| 格式 | 魔数 | FT 条目 | 加密链 | 使用资源 |
|------|------|--------|--------|---------|
| MS2F | `0x4632534D` | 48B | base64 → AES-CTR → zlib | GMS/KMS 全资源 |
| NS2F | `0x4632534E` | 36B | base64 → AES-CTR → zlib | CMS Xml |
| OS2F | `0x4632534F` | 40B | base64 → AES-CTR → zlib | CMS 主资源 |
| PS2F | `0x46325350` | 40B | XOR 32-bit 循环 | CMS Movie |

### M2H 解密流程 (PackStream)

```
M2H → PackStream header → EncodedHeader → base64→AES→zlib→CSV
                         → EncodedData   → base64→AES→zlib→FT
M2D → 按 FT 偏移逐块 → base64→AES→zlib→原始文件
```

---

## M2H 头部布局

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

## FileTable 条目布局

| 版本 | 条目大小 | 字段布局 |
|------|---------|---------|
| Ver1 (MS2F) | 48B | PackingDef(4)+FileIndex(4)+BufferFlag(4)+Reserved(4)+Offset(8)+EncodedSize(4)+Reserved(4)+CompressedSize(8)+FileSize(8) |
| Ver2 (NS2F) | 36B | BufferFlag(4)+FileIndex(4)+EncodedSize(4)+CompressedSize(8)+FileSize(8)+Offset(8) |
| Ver3 (OS2F/PS2F) | 40B | BufferFlag(4)+FileIndex(4)+EncodedSize(4)+Reserved(4)+CompressedSize(8)+FileSize(8)+Offset(8) |

---

## 加密密钥

`orion2_keys.json` — 7 套密钥表：

| 表名 | 条目 | 每条 | 用途 |
|------|------|------|------|
| OS2F_USER_KEY | 128 | 32B | CMS OS2F 资源 |
| OS2F_IV_CHAIN | 128 | 16B | CMS OS2F 资源 |
| MS2F_USER_KEY | 128 | 32B | GMS + CMS MS2F |
| MS2F_IV_CHAIN | 128 | 16B | GMS + CMS MS2F |
| NS2F_USER_KEY | 128 | 32B | CMS Xml |
| NS2F_IV_CHAIN | 128 | 16B | CMS Xml |
| PS2F_XOR_KEY | 512 | int | CMS Movie |

> ⚠️ KMS 使用独立密钥表，未包含在本项目中。

---

## 项目文件

```
├── README.md / README_ENG.md
├── requirements.txt
├── orion2_keys.json              # 7 套密钥表
├── ms2_extract_all.py            # 命令行提取工具
├── ms2_interactive.py            # 交互式提取工具
├── ms2_pack.py                   # 命令行打包工具
├── ms2_interactive_pack.py       # 交互式打包工具（推荐）
│
├── Image.m2h.header              # CMS 预解密 CSV/FT (仅 OS2F/PS2F 需要)
├── filetable_decrypted.bin
├── Exported.m2h.header
├── ...
└── Movie.filetable.decrypted_v2.bin
```

> Gfx / Xml / GMS / KMS 资源由工具直接解析 M2H 头，无需预解密文件。

---

## 核心技术发现

1. **通用密钥公式**: `key_index = compressed_size & 0x7F` — 来源于 `CipherKeys.GetKeyAndIV()`
2. **AES-CTR 实现**: 16 字节 IV 计数器 + AES-ECB，与 Orion2 `AESCipher.cs` 字节级一致，确保打包文件可被 Orion2-Repacker 读取
3. **PackStreamVer1/2/3 端到端解析与重打包**: 四种格式完整支持 M2H 头部构造 + CSV/FT 加密 + 文件数据加密
4. **CMS → MS2F 跨格式转换**: OS2F/PS2F 资源可转为 GMS 风格单 M2D，兼容 Orion2-Repacker
5. **CMS 孤儿 M2D**: 483 个无引用 M2D (~9.3 GB)，含 Npc_11/21/23 及 hash 编码旧数据
6. **KMS M2D 魔数**: `yVNZ` (0x5A4E5679)，结构同 GMS MS2F 但使用独立密钥表

---

## 参考

- Orion2-Repacker2026: MapleStory2 C# 解包/打包工具
- `CipherKeys.cs`: `GetKeyAndIV(uVer, uLenCompressed)` — 通用密钥公式来源
- `AESCipher.cs`: AES-CTR 实现参考
- `CryptoMan.cs`: 完整加密/解密流程
- `PackStreamVer1.cs` / `PackStreamVer2.cs` / `PackStreamVer3.cs`: M2H 头解析
- `PackFileHeaderVer1.cs` / `PackFileHeaderVer2.cs` / `PackFileHeaderVer3.cs`: FT 条目布局

仅供学习研究使用。
