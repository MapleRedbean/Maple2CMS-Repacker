---
name: code-doc-generator
description: "代码文档自动生成。为 Python/JS 代码自动生成专业注释和 API 文档 This skill should be used when the user asks about 代码文档自动生成. Keywords: 生成文档, 代码注释, API文档."
---

# 代码文档自动生成

> 为 Python/JS 代码自动生成专业注释和 API 文档

## 前置依赖

```bash
pip install requests
```

## 核心能力

### 能力1：读取指定代码文件（read_file）

用 `web_fetch` 抓取页面内容 / 用 `read_file` 读取文件。

### 能力2：解析函数/类/模块结构（codebase_search）

用 `read_file` 读取代码文件，用 `codebase_search` 搜索函数和类定义，用 `list_dir` 了解项目结构。

### 能力3：自动生成 Docstring/JSDoc 注释

用 `write_to_file` 生成文件。

### 能力4：生成 API 文档（Markdown）

用 `write_to_file` 生成文件。

### 能力5：统计文档覆盖率

用 `read_file` 读取代码文件，用 `codebase_search` 搜索函数和类定义，用 `list_dir` 了解项目结构。

## 使用流程

### 步骤 1：收集用户需求

向用户确认以下信息（如果未主动提供）：
- 代码文件或项目路径
- 需要生成什么文档？（API文档/README/函数注释/架构文档）
- 文档格式（Markdown/HTML/PDF）
- 面向的读者（开发者/非技术人员）

### 步骤 2：运行脚本处理数据

```bash
python3 scripts/code_doc_generator_tool.py run \
  --input "用户提供的输入" \
  --output "/path/to/output_file"
```

读取脚本输出的结果，确认数据处理成功。

### 步骤 3：生成最终产出

基于脚本输出和搜索到的资源，用 `write_to_file` 生成以下文件：

- **API 文档（Markdown）**
- **注释后的代码文件**

输出格式要求：Markdown API 文档 + 带注释代码

### 步骤 4：汇总交付

向用户展示：
1. 生成的文件路径和内容摘要
2. 搜集到的资源链接列表
3. 关键发现和建议

## 输出格式

```markdown
# 📋 代码文档自动生成 — 执行报告

**生成时间**: YYYY-MM-DD HH:MM
**目标用户**: 开发工程师、技术主管、开源项目维护者

## 执行摘要
[基于实际执行结果的一段话摘要]

## 详细结果

### 📊 生成的文件
| 文件名 | 类型 | 说明 |
|--------|------|------|
| [文件名] | [类型] | [说明] |

### 🔗 资源链接
| 名称 | 链接 | 说明 |
|------|------|------|
| [资源] | [URL] | [说明] |

## 行动建议
[具体的下一步建议]
```

## 验收标准

- ✅ 所有函数有注释
- ✅ API 文档完整
- ✅ 覆盖率≥80%
- ✅ 格式规范

## 场景化适配

根据语言（Python/JS/Go）调整文档格式


## 依赖 Skills

本 Skill 参考以下已有 Skill 的能力进行增强：
- **code-doc**

## 注意事项

- 所有数据必须来自 `web_search` / `web_fetch` 的真实搜索结果，**严禁编造数据**
- 数据缺失时标注"数据不可用"而非猜测
- 报告必须保存为文件（`write_to_file`），不能只在对话中输出
- 建议结合人工判断使用，AI 分析仅供参考
