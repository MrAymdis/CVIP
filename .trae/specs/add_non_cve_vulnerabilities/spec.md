# 增加非CVE漏洞情报数据 - 产品需求文档

## Overview
- **Summary**: 扩展漏洞情报平台，支持非CVE格式的漏洞数据，包括安全公告、厂商漏洞编号、漏洞利用报告等多种数据源
- **Purpose**: 提供更全面的漏洞情报覆盖，满足安全研究人员对非标准漏洞信息的需求
- **Target Users**: 安全研究人员、渗透测试工程师、安全运维人员

## Goals
- 支持非CVE漏洞数据的存储和管理
- 提供统一的漏洞搜索和浏览界面
- 支持多种非CVE漏洞来源的导入
- 保持与现有CVE数据的兼容性

## Non-Goals (Out of Scope)
- 不支持漏洞数据的自动发现和爬取（需手动导入或API接入）
- 不提供漏洞评分系统（使用现有CVSS评分）
- 不支持漏洞修复建议的自动生成

## Background & Context
当前平台仅支持CVE格式的漏洞数据，但实际安全工作中需要处理多种非CVE漏洞情报，包括：
- 厂商安全公告（如Microsoft Security Advisory、Apple Security Updates）
- 漏洞利用数据库（如Exploit-DB中无CVE编号的条目）
- 安全研究报告
- 0day漏洞情报

## Functional Requirements
- **FR-1**: 支持非CVE漏洞的创建和存储
- **FR-2**: 支持非CVE漏洞的搜索和筛选
- **FR-3**: 支持从多种来源导入非CVE漏洞数据
- **FR-4**: 提供非CVE漏洞的详情展示页面
- **FR-5**: 支持非CVE漏洞与CVE漏洞的关联

## Non-Functional Requirements
- **NFR-1**: 支持至少10万条非CVE漏洞数据的存储
- **NFR-2**: 搜索响应时间 < 1秒
- **NFR-3**: 支持漏洞数据的增量更新

## Constraints
- **Technical**: 基于现有FastAPI + PostgreSQL架构
- **Dependencies**: 需要与现有CVE数据模型兼容

## Assumptions
- 非CVE漏洞数据可能没有标准的漏洞编号
- 部分非CVE漏洞可能没有CVSS评分
- 需要支持自定义漏洞标识符

## Acceptance Criteria

### AC-1: 非CVE漏洞数据模型创建
- **Given**: 系统需要存储非CVE漏洞
- **When**: 创建新的漏洞数据模型
- **Then**: 模型支持非CVE漏洞的基本字段（标题、描述、来源、严重程度等）
- **Verification**: `programmatic`

### AC-2: 非CVE漏洞搜索功能
- **Given**: 用户在搜索页面输入关键词
- **When**: 搜索包含非CVE漏洞
- **Then**: 返回包含CVE和非CVE漏洞的混合结果
- **Verification**: `programmatic`

### AC-3: 非CVE漏洞详情页面
- **Given**: 用户点击非CVE漏洞
- **When**: 进入详情页面
- **Then**: 显示漏洞的完整信息，包括来源、描述、参考链接等
- **Verification**: `human-judgment`

### AC-4: 非CVE漏洞导入功能
- **Given**: 有外部漏洞数据源
- **When**: 执行导入脚本
- **Then**: 非CVE漏洞数据被正确导入数据库
- **Verification**: `programmatic`

## Open Questions
- [ ] 是否需要支持漏洞状态管理（如已修复、待验证等）
- [ ] 是否需要支持漏洞的分类标签系统
- [ ] 是否需要提供API接口供外部系统接入