# MapleStory2 M2D Universal Extractor v7

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
| Library / Shaders / 等 | 5 资源 ✅ | 5 资源 MS2F | — | .xml / .bin / .cfg |

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

### 打包回封

```bash
# OS2F (CMS 主资源，多 M2D 分卷)
python ms2_pack.py -i ./modified -r Image -o ./output --max-m2d-size 200

# MS2F (GMS/KMS 全部资源，单 M2D)
python ms2_pack.py -i ./gfx_mod -r Gfx -o ./output

# NS2F (Xml)
python ms2_pack.py -i ./xml_mod -r Xml -o ./output
```

支持 30 种资源类型（OS2F×7 + PS2F×1 + MS2F×21 + NS2F×1）。

---

## 解密方案

### 通用密钥公式

```
key_index = compressed_size & 0x7F
```

统一 OS2F / MS2F / NS2F 三种 AES 加密格式的密钥推导。

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

## FileTable 格式

| 版本 | 魔数 | 条目大小 | 使用 |
|------|------|---------|------|
| Ver1 (MS2F) | `0x4632534D` | 48B | Gfx, GMS/KMS 全部 |
| Ver2 (NS2F) | `0x4632534E` | 36B | Xml |
| Ver3 (OS2F) | `0x4632534F` | 40B | CMS Image~Textures |
| Ver3 (PS2F) | `0x46325350` | 40B | Movie |

---

## 项目文件

```
├── README.md / README_ENG.md
├── requirements.txt
├── orion2_keys.json           # 7 套密钥表
├── ms2_extract_all.py         # 命令行提取工具
├── ms2_interactive.py         # 交互式提取工具
├── ms2_pack.py                # 打包回封工具
│
├── Image.m2h.header           # CMS 预解密 CSV/FT (仅 OS2F/PS2F 需要)
├── filetable_decrypted.bin
├── Exported.m2h.header
├── ...
└── Movie.filetable.decrypted_v2.bin
```

> Gfx / Xml / GMS / KMS 资源由工具直接解析 M2H 头，无需预解密文件。

---

## 核心技术发现

1. **通用密钥公式**: `key_index = compressed_size & 0x7F` — 来源于 `CipherKeys.GetKeyAndIV()`
2. **PackStreamVer1/2/3 端到端解析**: 从加密 M2H 直接解密 CSV + FT
3. **CMS 孤儿 M2D**: 483 个无引用 M2D (~9.3 GB)，含 Npc_11/21/23 及 hash 编码旧数据
4. **KMS M2D 魔数**: `yVNZ` (0x5A4E5679)，结构同 GMS MS2F 但使用独立密钥表
5. **CMS vs GMS 架构**: 多 M2D 分卷 vs 单 M2D — GMS 采用更现代化的打包架构

---

## 参考

- Orion2-Repacker2026: MapleStory2 C# 解包/打包工具
- `CipherKeys.cs`: `GetKeyAndIV(uVer, uLenCompressed)` — 通用密钥公式来源
- `CryptoMan.cs`: 完整解密流程
- `PackStreamVer1.cs` / `PackStreamVer2.cs`: M2H 头解析

仅供学习研究使用。
