# 数据源拓展 - 产品需求文档

## Overview
- **Summary**: 为网络安全漏洞情报平台拓展更多高质量的漏洞数据源，包括 Exploit-DB、Metasploit、Packet Storm、VulDB、CNVD 和 CNNVD 等，提升漏洞情报的丰富性和时效性。
- **Purpose**: 解决当前数据源单一的问题，通过集成多个权威漏洞数据源，为用户提供更全面、更及时的漏洞情报信息。
- **Target Users**: 安全研究人员、渗透测试工程师、漏洞分析人员、企业安全团队。

## Goals
- 集成 Exploit-DB 漏洞利用数据
- 集成 Metasploit 漏洞利用模块数据
- 集成 Packet Storm 漏洞公告数据
- 集成 VulDB 漏洞数据库
- 集成国内 CNVD 漏洞数据源
- 集成国内 CNNVD 漏洞数据源
- 建立统一的数据采集和更新机制
- 确保数据质量和一致性

## Non-Goals (Out of Scope)
- 不修改现有 cvelistV5 数据源的导入逻辑
- 不实现实时数据推送功能
- 不修改前端 UI 布局
- 不实现数据源的自定义配置界面

## Background & Context
当前平台已集成以下数据源：
- CVEProject/cvelistV5（主数据源）
- CISA KEV（已知被利用漏洞目录）
- EPSS（漏洞利用预测评分）
- GitHub PoC（漏洞概念验证仓库）
- NVD（美国国家漏洞数据库）

为了提供更全面的漏洞情报，需要拓展更多权威数据源，特别是国内数据源和专门的漏洞利用数据源。

## Functional Requirements
- **FR-1**: Exploit-DB 爬虫 - 从 Exploit-DB 获取漏洞利用代码和详情
- **FR-2**: Metasploit 爬虫 - 从 Metasploit 获取漏洞利用模块信息
- **FR-3**: Packet Storm 爬虫 - 从 Packet Storm 获取漏洞公告和安全工具
- **FR-4**: VulDB 爬虫 - 从 VulDB 获取漏洞数据
- **FR-5**: CNVD 爬虫 - 从国家信息安全漏洞共享平台获取漏洞数据
- **FR-6**: CNNVD 爬虫 - 从国家信息安全漏洞库获取漏洞数据
- **FR-7**: 统一数据同步机制 - 支持所有数据源的定时同步和增量更新
- **FR-8**: 数据源追踪 - 记录每个漏洞的数据来源

## Non-Functional Requirements
- **NFR-1**: 性能 - 单个数据源同步时间不超过 30 分钟
- **NFR-2**: 可靠性 - 爬虫失败率低于 5%，支持重试机制
- **NFR-3**: 可扩展性 - 易于添加新的数据源
- **NFR-4**: 数据质量 - 避免重复数据，确保数据一致性

## Constraints
- **Technical**: 使用 Python + FastAPI + SQLAlchemy，保持与现有代码风格一致
- **Business**: 遵守各数据源的使用条款和 robots.txt
- **Dependencies**: httpx, beautifulsoup4, lxml 等常用爬虫库

## Assumptions
- 各数据源提供公开可访问的 API 或 RSS/Atom 订阅
- 国内数据源（CNVD、CNNVD）可以正常访问
- 数据格式相对稳定，不会频繁变化

## Acceptance Criteria

### AC-1: Exploit-DB 数据集成
- **Given**: Exploit-DB 网站可正常访问
- **When**: 运行 Exploit-DB 爬虫
- **Then**: 成功获取漏洞利用数据并保存到数据库，关联到对应 CVE
- **Verification**: `programmatic`
- **Notes**: 验证至少 100 条 Exploit-DB 记录成功导入

### AC-2: Metasploit 数据集成
- **Given**: Metasploit 模块数据库可访问
- **When**: 运行 Metasploit 爬虫
- **Then**: 成功获取 Metasploit 模块信息并关联到对应 CVE
- **Verification**: `programmatic`
- **Notes**: 验证至少 50 个 Metasploit 模块成功导入

### AC-3: Packet Storm 数据集成
- **Given**: Packet Storm 网站可正常访问
- **When**: 运行 Packet Storm 爬虫
- **Then**: 成功获取漏洞公告数据并保存到数据库
- **Verification**: `programmatic`
- **Notes**: 验证至少 50 条 Packet Storm 记录成功导入

### AC-4: CNVD 数据集成
- **Given**: CNVD 网站可正常访问
- **When**: 运行 CNVD 爬虫
- **Then**: 成功获取 CNVD 漏洞数据并保存到数据库，支持中文展示
- **Verification**: `programmatic`
- **Notes**: 验证至少 100 条 CNVD 记录成功导入

### AC-5: CNNVD 数据集成
- **Given**: CNNVD 网站可正常访问
- **When**: 运行 CNNVD 爬虫
- **Then**: 成功获取 CNNVD 漏洞数据并保存到数据库，支持中文展示
- **Verification**: `programmatic`
- **Notes**: 验证至少 100 条 CNNVD 记录成功导入

### AC-6: 数据源追踪
- **Given**: 多个数据源的漏洞数据已导入
- **When**: 查看漏洞详情
- **Then**: 可以看到该漏洞的所有数据来源
- **Verification**: `human-judgment`
- **Notes**: 验证 data_sources 字段正确记录了所有数据源

### AC-7: 统一同步机制
- **Given**: 所有爬虫已实现
- **When**: 运行统一同步脚本
- **Then**: 所有数据源按顺序同步，支持增量更新
- **Verification**: `programmatic`
- **Notes**: 验证同步脚本可以正常执行并更新数据

## Open Questions
- [ ] CNVD 和 CNNVD 是否需要登录才能获取完整数据？
- [ ] VulDB 是否需要 API Key？
- [ ] 是否需要实现数据去重逻辑？
