# MapleStory2 M2D Universal Extractor

冒险岛2（MapleStory2）资源文件批量解密提取工具。

## 提取总览

| 资源 | 格式 | 文件数 | 提取率 | 文件格式 |
|--------|------|--------|--------|----------|
| Image | OS2F | 18,536 | 100% | PNG: 16,541 / DDS: 1,992 / BMP: 2 |
| Exported | OS2F | 15,305 | 100% | .flat: 13,378 / .xblock: 1,927 |
| Map | OS2F | 21,551 | 100% | .nif (Gamebryo v30) |
| Effect | OS2F | 16,535 | 100% | .nif (Gamebryo v30) |
| Item | OS2F | 8,193 | 99.8% | .nif (Gamebryo v30) |
| Npc | OS2F | 37,097 | 100% | .kfm / .kf / .nif |
| Textures | OS2F | 34,446 | 100% | .dds |
| Movie | PS2F | 392 | 100% | .usm (CRI USM) |
| **合计** | | **~152,055** | **~99.9%** | |

## 环境要求

```bash
pip install -r requirements.txt
```

Python 3.7+, pycryptodome, tqdm.

## 使用方法

### 提取全部资源

```bash
python ms2_extract_all.py -d "D:\WeGameApps\冒险岛2\Client\Data" -o ./output
```

### 提取指定资源

```bash
# 单资源
python ms2_extract_all.py -r Movie -d "D:\...\Data" -o ./output
python ms2_extract_all.py -r Item -d "D:\...\Data" -o ./output

# 可选: Image / Exported / Map / Effect / Item / Npc / Textures / Movie / all
```

### 输出目录结构

输出完全镜像游戏源目录层级：

```
{output}/
  Resource/
    Image/           # {csv_path}
    Exported/        # {csv_path}
    Model/
      Map/           # {csv_path}
      Effect/        # {csv_path}
      Item/          # {csv_path}
      Npc/           # {csv_path}
      Textures/      # {csv_path}
    Movie/           # {csv_path}
```

## 解密方案

### OS2F（7 类资源：Image ~ Textures）

```
M2D → base64 解码 → AES-CTR(ECB, key=file_size&0x7F) → zlib 解压 → 原始文件
```

每个文件独立 AES-CTR 加密，密钥由 `file_size & 0x7F` 索引 128 组密钥表，计数器独立重置。

### PS2F（Movie）

```
M2D → XOR(PS2F_XOR_KEY, 2048B 循环, 32-bit 字) → 原始 .usm 文件
```

- 无 base64 编码，无 zlib 压缩
- 每个 M2D 包含 1 个完整文件（offset=0, block_size=文件大小）
- XOR 密钥：512 字节循环 4 次 = 2048 字节，按 32-bit 小端字 XOR，`& 0x1FF` 旋转

## 加密密钥

所有密钥存储在 `orion2_keys.json`：

- `OS2F_USER_KEY`：128 组 AES 密钥
- `OS2F_IV_CHAIN`：128 组 AES 初始化向量
- `PS2F_XOR_KEY`：512 字节 XOR 密钥

## FileTable 格式

每个条目 40 字节（10 × uint32 小端）：

| 偏移 | 字段 | 含义 |
|------|------|------|
| +0x00 | V0 | 加密标志（OS2F: 0xEE000009=AES+zlib, PS2F: 0xFF000000=XOR） |
| +0x04 | V1 | 文件索引 |
| +0x08 | V2 | block_size（M2D 中的块大小） |
| +0x10 | V4 | file_size（OS2F: 用于密钥推导, PS2F: 原始文件大小） |
| +0x18 | V6 | raw_size（解压后大小） |
| +0x20 | V8 | offset（M2D 中的字节偏移） |

## 文件清单

```
├── .gitignore
├── README.md
├── requirements.txt
├── orion2_keys.json                     # 加密密钥表
├── ms2_extract_all.py                   # 通用提取工具（OS2F + PS2F）
│
├── Image.m2h.header                     # Image CSV 路径表
├── filetable_decrypted.bin              # Image FileTable
│
├── Exported.m2h.header                  # Exported CSV 路径表
├── Exported.filetable.decrypted.bin     # Exported FileTable
│
├── Map.m2h.header                       # Map CSV 路径表
├── Map.filetable.decrypted_v2.bin       # Map FileTable
│
├── Effect.m2h.header                    # Effect CSV 路径表
├── Effect.filetable.decrypted_v2.bin    # Effect FileTable
│
├── Item.m2h.header                      # Item CSV 路径表
├── Item.filetable.decrypted_v2.bin      # Item FileTable
│
├── Npc_02.header                        # Npc CSV 路径表
├── Npc_02.filetable.decrypted_v2.bin    # Npc FileTable
│
├── Textures.m2h.header                  # Textures CSV 路径表
├── Textures.filetable.decrypted_v2.bin  # Textures FileTable
│
├── Movie.m2h.header                     # Movie CSV 路径表
└── Movie.filetable.decrypted_v2.bin     # Movie FileTable
```

## 已知限制

| 资源 | 说明 |
|------|------|
| Xml.m2h (NS2F) | 有专用工具处理，不在此工具包范围 |
| MS2F 资源（Gfx/Library/Shaders 等） | 由 Orion2-Repacker 直接解压 |

仅供学习研究使用。
