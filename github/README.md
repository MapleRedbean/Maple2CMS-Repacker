# MapleStory2 Image Resource Extractor

从冒险岛2（MapleStory2）的 `Image_*.m2d` 资源包中提取所有图片文件。

## 最终结果

| 指标 | 数值 |
|------|------|
| 文件总数 | 18,536 |
| 提取成功率 | **100%** |
| 总大小 | 1,267 MB |
| 格式分布 | PNG: 16,541 / DDS: 1,992 / BMP: 2 |
| 子目录 | 22 个 |

## 依赖

```bash
pip install pycryptodome
```

Python 3.7+，无其他依赖。

## 快速开始

### 准备材料

| 文件 | 说明 |
|------|------|
| `Image_*.m2d` | 游戏 Resource 目录中 22 个资源包 |
| `Image.m2h.header` | 解密后的 CSV（index,m2d_id,filepath） |
| `filetable_decrypted.bin` | 解密后的 FileTable（40 字节/条目） |
| `orion2_keys.json` | AES 密钥表 |

### 运行

```bash
python ms2_image_extract.py --m2d "D:\WeGameApps\冒险岛2\Client\Data\Resource" --out ./output
```

### 验证模式

```bash
python ms2_image_extract.py --m2d ./Resource --dry-run
```

## 命令行参数

```
--m2d  PATH    游戏 Resource 目录 [必需]
--csv  PATH    解密后的 CSV [默认: Image.m2h.header]
--ft   PATH    解密后的 FileTable [默认: filetable_decrypted.bin]
--keys PATH    AES 密钥表 [默认: orion2_keys.json]
--out  PATH    输出目录 [默认: ./extracted]
--dry-run      仅验证，不提取
```

## 解密流程

```
M2D 原始文件的每个文件块独立处理：

1. 读取 base64 块 (offset + block_size)
2. Base64 解码 (扣除 = 填充)
3. AES-CTR 解密 (key = file_size & 0x7F, counter 独立)
4. zlib 解压 (如果首字节 0x78)
5. Magic 校验 (PNG 0x89504E47 / DDS 0x44445320 / BMP 0x424D)
6. 保存文件
```

## 关键技术点

1. **每个文件独立加密** — AES counter 逐文件重置，不能整体解密
2. **密钥 = file_size & 0x7F** — 文件大小低 7 位决定 key 索引
3. **FileTable V8 偏移量指向原始 M2D 文件** — 非解码后数据
4. **Base64 块之间无分隔符** — 直接拼接，按 V2 长度切割

## FileTable 条目结构（40 字节）

```
[V0: const] [V1: index] [V2: block_size] [V3: 0]
[V4: file_size] [V5: 0] [V6: file_size] [V7: 0]
[V8: offset] [V9: 0]
```

## 许可

仅供学习研究使用。
