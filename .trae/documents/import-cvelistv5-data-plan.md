# 导入 CVEProject/cvelistV5 数据 - 实施计划

## 目标

将 CVEProject/cvelistV5 作为平台的主要 CVE 数据源，实现高效、及时的数据导入。

## 实施步骤

### Step 1: 创建 cvelistV5 数据爬虫

创建 `backend/app/crawlers/cvelistv5_crawler.py`：

* 支持 Git Clone 方式获取数据

* 解析 CVE JSON 5 格式

* 提取关键字段：CVE ID、标题、描述、CVSS、CWE、厂商、产品等

* 支持增量更新（通过 delta.json）

### Step 2: 克隆 cvelistV5 仓库

在 backend 目录下克隆仓库：

```bash
cd /home/u01/cybersecurity_vulnerability_intelligence_platform/backend
git clone --depth 1 https://github.com/CVEProject/cvelistV5.git
```

### Step 3: 实现数据解析器

解析 CVE JSON 5 格式，映射到数据库模型：

* cveMetadata.cveId → cve\_id

* containers.cna.title → title

* containers.cna.descriptions → description

* containers.cna.metrics → cvss\_v3\_score, cvss\_v4\_score

* containers.cna.affected → vendor, product

* containers.cna.problemTypes → cwes

### Step 4: 批量导入数据

编写批量导入脚本：

* 遍历所有年份目录

* 解析每个 CVE JSON 文件

* 批量插入数据库

* 处理重复数据（更新或跳过）

### Step 5: 实现增量更新

通过 delta.json 实现增量同步：

* 读取 delta.json 获取变更列表

* 只处理新增和更新的 CVE

* 定期执行（每 30 分钟）

### Step 6: 测试验证

* 验证数据完整性

* 检查字段映射正确性

* 测试增量更新功能

## 预期结果

* 成功导入 cvelistV5 的所有 CVE 数据

* 实现自动化的增量更新机制

* 数据更新延迟控制在 30 分钟以内

## 风险评估

* **中风险**: 数据量大，导入时间可能较长

* **缓解措施**: 使用批量插入和事务处理

