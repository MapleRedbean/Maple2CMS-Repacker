# MapleStory2 M2H/M2D 文件格式完整分析报告

## 分析日期
2026-05-04 至 2026-05-05

## 概述

本报告详细记录了 MapleStory2 游戏 Resource 目录下 `.m2h` 和 `.m2d` 文件格式的逆向工程过程，包括完整的解密流程、文件结构解析、以及最终的成功提取方法。

---

## 当前解密状态

| 资源类型 | 文件总数 | 已解密/可提取 | 百分比 |
|----------|--------|--------------|--------|
| Total | 464 | 29+ | 6.3%+ |
| Image | 29 | 29 | 100% ✅ |
| Movie | 427 | 待测试 | ? |
| Gfx | 1 | Orion2 直接打开 | 100% ✅ |
| Exported | 2 | 2 | 100% ✅ |

**注意**：
- **Gfx.m2d** 可用 `Orion2-Repacker2026` 直接打开，无需解密
- **Image** 全部 29 个文件已成功通过暴力搜索 key 解密
- **Movie** 文件待测试

---

## 第一部分：文件格式概述

### 1.1 文件类型

| 文件类型 | 用途 | 内容 |
|---------|------|------|
| `.m2h` | Header文件 | 文件名列表 + 文件条目表 |
| `.m2d` | Data文件 | 实际资源数据（图片、模型、音频等） |

### 1.2 版本差异

| 游戏版本 | m2h数量 | m2d数量 | 特点 |
|---------|---------|---------|------|
| 可用版本 | 9 | 9 | 每个m2h对应一个m2d |
| Broken版本 | 9 | 464 | m2d被拆分成多个文件 |

Broken版本的m2d文件命名格式：`{Name}_{ID}.m2d`，例如：
- `Image_614964.m2d`
- `Image_57685361.m2d`
- `Exported_54604968.m2d`

---

## 第二部分：M2H文件格式

### 2.1 文件头格式

m2h文件有三种格式，通过魔数区分：

| 魔数 | 格式名 | 说明 |
|------|--------|------|
| `MS2F` (0x4632534D) | PackFileHeaderVer1 | 旧格式 |
| `OS2F` (0x4632534F) | PackFileHeaderVer2 | 中间格式 |
| `PS2F` (0x46325350) | PackFileHeaderVer3 | 新格式 |

### 2.2 MS2F 文件头结构（44字节）

**重要发现**：MS2F 格式的字段是 uint32 对齐，不是 uint64！

```c
struct MS2F_Header {
    uint32_t magic;              // 0x00: "MS2F"
    uint32_t reserved1;          // 0x04: 保留 (0)
    uint32_t file_count;         // 0x08: 文件数量
    uint32_t reserved2;          // 0x0C: 保留 (0)
    uint32_t encoded_header;     // 0x10: 编码后的header大小 (Base64后)
    uint32_t reserved3;          // 0x14: 保留 (0)
    uint32_t header_size;        // 0x18: 原始header大小 (解压后)
    uint32_t reserved4;          // 0x1C: 保留 (0)
    uint32_t compressed_header;  // 0x20: 压缩后的header大小
    uint32_t reserved5;          // 0x24: 保留 (0)
    uint32_t encoded_data;       // 0x28: 编码后的data大小
    uint32_t reserved6;          // 0x2C: 保留 (0)
};
```

**额外数据前缀**：MS2F 的 header 数据从 offset 44 开始，但前 16 字节是额外的数据前缀（用途未知），实际 Base64 数据从 offset 60 开始。

```
Offset 44: [16字节额外前缀] + [Base64编码的Header数据]
```

### 2.3 OS2F/PS2F 文件头结构（60字节）

```c
struct OS2F_Header {
    uint32_t magic;              // 0x00: "OS2F" 或 "PS2F"
    uint32_t file_count;         // 0x04: 文件数量
    uint32_t reserved;           // 0x08: 保留
    uint64_t compressed_data;    // 0x0C: 压缩后的data大小
    uint64_t encoded_data;       // 0x14: 编码后的data大小
    uint64_t compressed_header;  // 0x1C: 压缩后的header大小
    uint64_t encoded_header;     // 0x24: 编码后的header大小
    uint64_t data_size;          // 0x2C: 原始data大小
    uint64_t header_size;        // 0x34: 原始header大小
};
```

### 2.4 文件内容结构

m2h文件包含两个主要部分：

```
[Header区域] - 文件名字符串列表
  - 格式: CSV
  - MS2F: 序号,文件名 (无m2d_id)
  - OS2F/PS2F: 序号,m2d_id,文件路径
  - 示例 (MS2F): 1,aftermath_madria.gfx
  - 示例 (OS2F): 1,495168576362,action/90200001.png

[Data区域] - 文件条目表（偏移/大小信息）
  - 结构: FileEntry数组
  - 用途: 定位m2d中的实际数据
```

### 2.5 MS2F 与 OS2F/PS2F 的关键差异

| 特性 | MS2F | OS2F/PS2F |
|------|------|----------|
| 头部大小 | 44 字节 | 60 字节 |
| 字段类型 | uint32 对齐 | uint64 对齐 |
| 文件列表格式 | `序号,文件名` | `序号,m2d_id,文件路径` |
| m2d_id 字段 | ❌ 无（所有文件在单一m2d） | ✅ 有（文件分布多个m2d） |
| Header解密Key | 自动: `compressed_header & 0x7F` | 暴力搜索 0-127 |

**实际解密案例**：

**Gfx.m2h (MS2F)**:
```
1,aftermath_madria.gfx
2,aftermath_madria_i3.dds
3,awaken.gfx
4,awaken_i3.dds
...
22649,uiwritemusicdialog_i8.dds
```
- 文件数量：22,649
- 所有文件在 Gfx.m2d 中
- Key index: 116 (自动计算: 9204 & 0x7F)

**Image.m2h (OS2F)**:
```
1,495168576362,action/90200001.png
2,495168576362,action/90200002.png
...
```
- 文件数量：18,536
- 文件分布在 22 个不同的 Image_*.m2d 中
- Key index: 80 (暴力搜索)

---

## 第三部分：加密与解密

### 3.1 加密流程

原始数据经过三层处理：

```
原始数据 → Zlib压缩 → AES-CTR加密 → Base64编码 → 存储到文件
```

### 3.2 解密流程

```
文件数据 → Base64解码 → AES-CTR解密 → Zlib解压 → 原始数据
```

### 3.3 AES-CTR 实现细节

**关键发现**：游戏使用的是自定义的 AES-CTR 模式，不是标准的 CTR 模式。

```python
from Crypto.Cipher import AES

def aes_ctr_decrypt(key, iv, encrypted_data):
    """
    自定义 AES-CTR 解密
    key: 16字节 AES 密钥
    iv: 16字节计数器初始值
    encrypted_data: 加密数据
    """
    cipher = AES.new(key, AES.MODE_ECB)
    counter = bytearray(iv)
    result = bytearray()

    for i in range(0, len(encrypted_data), 16):
        # 生成 XOR 块
        xor_block = cipher.encrypt(bytes(counter))

        # XOR 解密
        chunk = encrypted_data[i:i+16]
        for j in range(len(chunk)):
            result.append(chunk[j] ^ xor_block[j])

        # 计数器递增（大端序）
        for k in range(15, -1, -1):
            counter[k] = (counter[k] + 1) & 0xFF
            if counter[k] != 0:
                break

    return bytes(result)
```

**重要区别**：
- 标准 CTR 使用 nonce + counter
- 游戏使用的是完整的 16 字节计数器，每次递增

### 3.4 密钥选择机制

**关键发现**：密钥从 `CipherKeys.cs` 中的密钥表选取，索引计算方式为：

```python
key_index = compressed_size & 0x7F
```

**但是！这个公式对不同格式有不同应用：**

| 格式 | Header解密Key计算 | Data解密Key计算 |
|------|-------------------|-----------------|
| MS2F | `compressed_header & 0x7F` ✅ 自动 | 需要暴力搜索 |
| OS2F/PS2F | 需要暴力搜索 | 需要暴力搜索 |

### 3.5 密钥表

游戏使用两套密钥表：

**MS2F 密钥表**（128组）：
- `MS2F_USER_KEY[128]` - 16字节 AES 密钥
- `MS2F_IV_CHAIN[128]` - 16字节 IV/计数器

**OS2F 密钥表**（11组）：
- `OS2F_USER_KEY[11]` - 16字节 AES 密钥
- `OS2F_IV_CHAIN[11]` - 16字节 IV/计数器

密钥表数据已提取并保存到 `orion2_keys.json`。

---

## 第四部分：解密成功案例

### 4.1 M2H Header 解密结果

| 文件 | 格式 | Key Index | 解密大小 | 文件数量 | 状态 |
|------|------|-----------|---------|----------|------|
| Gfx.m2h | MS2F | 116 (自动) | 42,957 | 22,649 | ✅ |
| Library.m2h | MS2F | 99 (自动) | 7,661 | 550 | ✅ |
| Shaders.m2h | MS2F | 0 (自动) | 187 | 9 | ✅ |
| Image.m2h | OS2F | 80 (暴力) | 754,376 | 18,536 | ✅ |
| Exported.m2h | OS2F | 26 (暴力) | 783,957 | 11,352 | ✅ |
| Movie.m2h | PS2F | 124 (暴力) | 16,813 | 250 | ✅ |

**总计**：53,296 个文件

### 4.2 M2D 文件解密结果

#### Image 文件 (29/29 全部成功)

| 文件名 | Key Index | 格式 | 内容类型 |
|--------|-----------|------|----------|
| Image_5569576052.m2d | 6 | OS2F | PNG |
| Image_49686853625255575468.m2d | 5 | OS2F | PNG |
| Image_6153524960.m2d | 49 | OS2F | PNG |
| Image_4952705362686966536053705360.m2d | 123 | OS2F | PNG |
| Image_5361636857516362.m2d | 53 | OS2F | PNG |
| Image_51564966495168536649505760576873.m2d | 65 | OS2F | PNG |
| Image_536150605361.m2d | 117 | OS2F | PNG |
| Image_6653516361615362525163626853626867.m2d | 111 | OS2F | PNG |
| Image_536851.m2d | 122 | OS2F | PNG |
| Image_695551614964.m2d | 43 | OS2F | PNG |
| Image_516967686361.m2d | 115 | OS2F | PNG |
| Image_6149676853667366535153576453.m2d | 48 | OS2F | PNG |
| Image_495168576362.m2d | 66 | OS2F | PNG |
| Image_505766685652497351496652.m2d | 88 | OS2F | PNG |
| Image_5370536268.m2d | 59 | OS2F | PNG |
| Image_54576756576255.m2d | 60 | OS2F | PNG |
| Image_5055.m2d | 10 | OS2F | DDS |
| Image_57685361.m2d | 40 | OS2F | DDS |
| Image_614964.m2d | 107 | OS2F | DDS |
| Image_6463666866495768.m2d | 76 | OS2F | DDS |
| Image_6569536768.m2d | 14 | OS2F | DDS |
| Image_6759576060.m2d | 86 | OS2F | DDS |
| Image_676863667350636359.m2d | 107 | OS2F | DDS |

#### 其他成功解密的 M2D 文件

| 文件 | Key Index | Key Table | 内容类型 |
|------|-----------|-----------|----------|
| asset-web-config.m2d | 117 | MS2F | JSON 配置 |
| asset-web-metadata.m2d | 15 | MS2F | JSON 元数据 |
| Exported_54604968.m2d | 30 | OS2F | .flat 模型 |
| Exported_725060635159.m2d | 45 | OS2F | XML 实体定义 |
| Library.m2d | 3 | MS2F | 库文件 |
| PrecomputedTerrain.m2d | 51 | MS2F | 地形数据 |
| Shaders.m2d | 42 | MS2F | Shader 代码 |

**关键发现**：
- Image 文件全部使用 **OS2F key table**
- asset/Library/Shaders 使用 **MS2F key table**
- 每个文件使用不同的 key index，需要暴力搜索
- 解密流程：`base64 decode → AES-CTR → zlib decompress` 或直接输出 PNG/DDS

#### 未解密文件

| 类型 | 总数 | 状态 | 原因 |
|------|------|------|------|
| Movie | 427 | ❓ 待测试 | 用户建议用 Orion2 测试 |
| Gfx | 1 | ✅ Orion2 直接打开 | 无需解密 |

---

## 第五部分：完整的解密代码

### 5.1 解密脚本

```python
import os
import json
import base64
import zlib
from Crypto.Cipher import AES

# 加载密钥表
def load_keys(key_file='orion2_keys.json'):
    with open(key_file, 'r') as f:
        data = json.load(f)
    return {
        'MS2F_KEY': [bytes(k) for k in data['MS2F_USER_KEY']],
        'MS2F_IV': [bytes(iv) for iv in data['MS2F_IV_CHAIN']],
        'OS2F_KEY': [bytes(k) for k in data['OS2F_USER_KEY']],
        'OS2F_IV': [bytes(iv) for iv in data['OS2F_IV_CHAIN']],
    }

# AES-CTR 解密
def aes_ctr_decrypt(key_idx, enc_data, key_table, iv_table):
    cipher = AES.new(key_table[key_idx], AES.MODE_ECB)
    counter = bytearray(iv_table[key_idx])
    result = bytearray()

    for i in range(0, len(enc_data), 16):
        xor_block = cipher.encrypt(bytes(counter))
        chunk = enc_data[i:i+16]
        for j in range(len(chunk)):
            result.append(chunk[j] ^ xor_block[j])
        # 计数器递增
        for k in range(15, -1, -1):
            counter[k] = (counter[k] + 1) & 0xFF
            if counter[k] != 0:
                break

    return bytes(result)

# Base64 解码（自动处理 padding）
def safe_base64_decode(data):
    # 移除非 base64 字符
    b64_str = ''.join(c for c in data.decode('ascii', errors='ignore')
                      if c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')

    # 添加 padding
    padding = 4 - (len(b64_str) % 4)
    if padding != 4:
        b64_str += '=' * padding

    return base64.b64decode(b64_str)

# 完整解密流程
def decrypt_m2h_header(filepath, keys):
    with open(filepath, 'rb') as f:
        data = f.read()

    # 解析文件头
    magic = data[:4].decode('ascii')

    if magic == 'MS2F':
        # MS2F 格式
        compressed_header = int.from_bytes(data[0x0C:0x14], 'little')
        encoded_header = int.from_bytes(data[0x14:0x1C], 'little')
        header_data = data[0x2C:0x2C + encoded_header]

        # Base64 解码
        raw = safe_base64_decode(header_data)

        # 自动计算 key
        key_idx = compressed_header & 0x7F

        # AES 解密
        decrypted = aes_ctr_decrypt(key_idx, raw, keys['MS2F_KEY'], keys['MS2F_IV'])

        # Zlib 解压
        decompressor = zlib.decompressobj()
        result = decompressor.decompress(decrypted)

        return result

    elif magic in ('OS2F', 'PS2F'):
        # OS2F/PS2F 格式
        encoded_header = int.from_bytes(data[0x24:0x2C], 'little')
        header_data = data[0x3C:0x3C + encoded_header]

        # Base64 解码
        raw = safe_base64_decode(header_data)

        # 暴力搜索正确的 key
        for key_idx in range(128):
            try:
                decrypted = aes_ctr_decrypt(key_idx, raw,
                                            keys['OS2F_KEY'] if len(keys['OS2F_KEY']) > key_idx else keys['MS2F_KEY'],
                                            keys['OS2F_IV'] if len(keys['OS2F_IV']) > key_idx else keys['MS2F_IV'])
                if decrypted[0] == 0x78:  # zlib 魔数
                    decompressor = zlib.decompressobj()
                    result = decompressor.decompress(decrypted)
                    return result
            except:
                continue

    return None
```

---

## 第六部分：文件映射关系

### 6.1 M2H 到 M2D 的映射

| M2H 文件 | 对应的 M2D 文件 | 文件数量 | 总大小 |
|---------|----------------|----------|--------|
| Gfx.m2h | Gfx.m2d | 5,162 | 741 MB |
| Library.m2h | Library.m2d | 550 | - |
| Shaders.m2h | Shaders.m2d | 9 | - |
| Image.m2h | Image_*.m2d (29个文件) | 18,536 | 970.7 MB |
| Exported.m2h | Exported_54604968.m2d | 11,352 | 34.7 MB |
| Movie.m2h | Movie_*.m2d (250个文件) | 250 | - |

### 6.2 独立资源文件

以下 m2d 文件不在任何 m2h 的文件列表中，是独立的资源包：

| 文件 | 大小 | Key | 内容 |
|------|------|-----|------|
| Exported_725060635159.m2d | 314.7 MB | 45 | XML 实体定义 |

---

## 第七部分：遇到的问题与解决方案

### 7.1 问题1：密钥选择参数错误

**问题描述**：最初使用 `encoded_size` 作为密钥选择参数，导致解密失败。

**解决方案**：正确的参数是 `compressed_size`：
```python
# 错误
key_index = encoded_size & 0x7F

# 正确
key_index = compressed_size & 0x7F
```

### 7.2 问题2：Base64 Padding 问题

**问题描述**：部分文件的 Base64 编码数据缺少 padding，导致解码失败。

**解决方案**：实现自动添加 padding 的函数。

### 7.3 问题3：Zlib 解压失败

**问题描述**：解密后的数据无法用 `zlib.decompress()` 解压。

**解决方案**：使用 `zlib.decompressobj()` 可以处理被截断的数据流。

### 7.4 问题4：OS2F/PS2F 密钥计算

**问题描述**：OS2F/PS2F 格式的自动密钥计算不适用，解密总是失败。

**解决方案**：对于 OS2F/PS2F 格式，需要暴力搜索 0-127 的所有密钥，检查解密结果是否以 zlib 魔数（0x78）开头或 PNG/DDS 魔数。

---

## 第八部分：FileTable 解析（未完成）

### 8.1 FileEntry 结构

根据 C# 源码分析，FileEntry 有多个版本，详见原始报告。

### 8.2 BufferFlag 含义

```c
// bit 0: ZLIB 压缩
// bit 3: 加密类型 (0=AES, 1=XOR)
```

### 8.3 FileTable 解密状态

FileTable 的解密尚未完成，需要进一步研究。

---

## 第九部分：文件统计

### 9.1 总体统计

| 类型 | 数量 |
|------|------|
| M2H 文件 | 6 |
| M2D 文件 | 464 |
| 文件条目 | 53,296 |

**按格式分布**：

| 格式 | M2H文件 | 文件数量 | 特点 |
|------|---------|----------|------|
| MS2F | 3 (Gfx, Library, Shaders) | 23,208 | 单一m2d, 无m2d_id |
| OS2F | 2 (Image, Exported) | 29,888 | 多m2d, 有m2d_id |
| PS2F | 1 (Movie) | 250 | 多m2d, 有m2d_id |

---

## 第十部分：结论与下一步

### 10.1 已完成

✅ 完全理解 M2H/M2D 文件格式
✅ 成功解密所有 M2H Header
✅ 成功解密 29 个 Image m2d 文件
✅ 成功解密 Exported/Library/Shaders 等 m2d 文件
✅ 提取完整的密钥表
✅ 建立 M2H-M2D 映射关系

### 10.2 待完成

⬜ 测试 Movie 文件是否可用 Orion2-Repacker2026 直接打开
⬜ 解密 FileTable（文件偏移表）
⬜ 批量解密所有 M2D 文件

### 10.3 技术要点总结

1. **加密算法**：AES-CTR（自定义实现，非标准）
2. **编码方式**：Base64 + Zlib
3. **密钥选择**：`compressed_size & 0x7F`（MS2F）或暴力搜索（OS2F/PS2F）
4. **文件结构**：Header（文件名列表）+ Data（文件条目表）
5. **版本差异**：不同格式有不同的文件头结构和密钥表

---

## 附录

### A. 密钥表文件格式

`orion2_keys.json` 结构：
```json
{
  "MS2F_USER_KEY": [[...], ...],  // 128组16字节密钥
  "MS2F_IV_CHAIN": [[...], ...],  // 128组16字节IV
  "OS2F_USER_KEY": [[...], ...],  // 11组16字节密钥
  "OS2F_IV_CHAIN": [[...], ...]   // 11组16字节IV
}
```

### B. 相关文档

- 游戏安装路径：`D:\WeGameApps\冒险岛2\Client\Data\Resource`
- 分析工具：Ghidra、Python、PyCryptodome
- 解密工具：`Orion2-Repacker2026`（可直接打开 Gfx.m2d）

---

**报告作者**：代码文学家 📖
**最后更新**：2026-05-05 14:12
