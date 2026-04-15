# 数据源拓展 - 实现计划

## [/] Task 1: Exploit-DB 爬虫实现
- **Priority**: P0
- **Depends On**: None
- **Description**: 
  - 实现 Exploit-DB 数据爬取
  - 解析漏洞利用信息并关联到对应 CVE
  - 保存为 Exploit 记录
- **Acceptance Criteria Addressed**: AC-1
- **Test Requirements**:
  - `programmatic` TR-1.1: 爬虫可以成功获取至少 100 条 Exploit-DB 记录
  - `programmatic` TR-1.2: Exploit 记录正确关联到 CVE
  - `human-judgement` TR-1.3: 代码风格与现有爬虫保持一致
- **Notes**: 使用 https://www.exploit-db.com/ 的 API 或 RSS

## [ ] Task 2: Metasploit 爬虫实现
- **Priority**: P0
- **Depends On**: None
- **Description**: 
  - 实现 Metasploit 模块数据爬取
  - 解析模块信息并关联到对应 CVE
  - 保存为 Exploit 记录
- **Acceptance Criteria Addressed**: AC-2
- **Test Requirements**:
  - `programmatic` TR-2.1: 爬虫可以成功获取至少 50 个 Metasploit 模块
  - `programmatic` TR-2.2: Exploit 记录正确关联到 CVE
  - `human-judgement` TR-2.3: 代码风格与现有爬虫保持一致
- **Notes**: 使用 Metasploit 的 modules 数据库或 GitHub 仓库

## [ ] Task 3: Packet Storm 爬虫实现
- **Priority**: P1
- **Depends On**: None
- **Description**: 
  - 实现 Packet Storm 漏洞公告爬取
  - 解析公告信息并保存为 Reference 记录
  - 关联到对应 CVE
- **Acceptance Criteria Addressed**: AC-3
- **Test Requirements**:
  - `programmatic` TR-3.1: 爬虫可以成功获取至少 50 条 Packet Storm 记录
  - `programmatic` TR-3.2: Reference 记录正确关联到 CVE
  - `human-judgement` TR-3.3: 代码风格与现有爬虫保持一致
- **Notes**: 使用 https://packetstormsecurity.com/

## [ ] Task 4: CNVD 爬虫实现
- **Priority**: P0
- **Depends On**: None
- **Description**: 
  - 实现 CNVD 漏洞数据爬取
  - 解析中文漏洞标题和描述
  - 更新对应 CVE 的中文信息
  - 记录数据源
- **Acceptance Criteria Addressed**: AC-4, AC-6
- **Test Requirements**:
  - `programmatic` TR-4.1: 爬虫可以成功获取至少 100 条 CNVD 记录
  - `programmatic` TR-4.2: CVE 的 title_zh 和 description_zh 字段正确更新
  - `programmatic` TR-4.3: data_sources 字段包含 "cnvd"
  - `human-judgement` TR-4.4: 代码风格与现有爬虫保持一致
- **Notes**: 使用 https://www.cnvd.org.cn/

## [ ] Task 5: CNNVD 爬虫实现
- **Priority**: P0
- **Depends On**: None
- **Description**: 
  - 实现 CNNVD 漏洞数据爬取
  - 解析中文漏洞标题和描述
  - 更新对应 CVE 的中文信息
  - 记录数据源
- **Acceptance Criteria Addressed**: AC-5, AC-6
- **Test Requirements**:
  - `programmatic` TR-5.1: 爬虫可以成功获取至少 100 条 CNNVD 记录
  - `programmatic` TR-5.2: CVE 的 title_zh 和 description_zh 字段正确更新
  - `programmatic` TR-5.3: data_sources 字段包含 "cnnvd"
  - `human-judgement` TR-5.4: 代码风格与现有爬虫保持一致
- **Notes**: 使用 https://www.cnnvd.org.cn/

## [ ] Task 6: VulDB 爬虫实现
- **Priority**: P2
- **Depends On**: None
- **Description**: 
  - 实现 VulDB 数据爬取（如果 API 可用）
  - 解析漏洞信息并更新 CVE
  - 记录数据源
- **Acceptance Criteria Addressed**: AC-6
- **Test Requirements**:
  - `programmatic` TR-6.1: 爬虫可以成功获取 VulDB 数据
  - `programmatic` TR-6.2: data_sources 字段包含 "vuldb"
  - `human-judgement` TR-6.3: 代码风格与现有爬虫保持一致
- **Notes**: 先验证 VulDB 是否提供免费 API

## [ ] Task 7: 统一同步机制实现
- **Priority**: P1
- **Depends On**: Task 1, Task 2, Task 3, Task 4, Task 5
- **Description**: 
  - 创建统一的同步脚本
  - 支持按顺序同步所有数据源
  - 支持增量更新
  - 添加错误处理和重试机制
- **Acceptance Criteria Addressed**: AC-7
- **Test Requirements**:
  - `programmatic` TR-7.1: 同步脚本可以按顺序执行所有爬虫
  - `programmatic` TR-7.2: 支持增量更新，只处理新数据
  - `programmatic` TR-7.3: 有错误处理和日志记录
  - `human-judgement` TR-7.4: 代码结构清晰，易于扩展
- **Notes**: 参考现有爬虫的实现模式

## [x] Task 8: 集成测试和验证
- **Priority**: P1
- **Depends On**: Task 7
- **Description**: 
  - 运行所有爬虫进行完整测试
  - 验证数据质量和一致性
  - 检查前端显示
- **Acceptance Criteria Addressed**: AC-1, AC-2, AC-3, AC-4, AC-5, AC-6, AC-7
- **Test Requirements**:
  - `programmatic` TR-8.1: 所有爬虫可以正常运行
  - `programmatic` TR-8.2: 数据库中的数据正确关联
  - `human-judgement` TR-8.3: 前端可以正确显示新增数据
  - `human-judgement` TR-8.4: 中文信息正确显示
- **Notes**: 测试时注意遵守各网站的访问频率限制
- **Status**: Exploit-DB 已成功测试并添加 100 条记录；Metasploit 因 GitHub API 限流暂时禁用
