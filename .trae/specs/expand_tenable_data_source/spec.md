# 拓展 Tenable 数据源 - 产品需求文档

## Overview

- **Summary**: 为网络安全漏洞情报平台拓展 Tenable 数据源，获取 Tenable 公开的漏洞情报数据，包括 CVE 详细信息、漏洞评级、检测插件等
- **Purpose**: 丰富漏洞情报数据来源，提供更全面的漏洞信息，特别是检测插件信息，提升平台的实用性
- **Target Users**: 网络安全研究人员、安全运维人员、漏洞管理人员

## Goals

- 集成 Tenable 漏洞数据源
- 获取 Tenable 公开的 CVE 漏洞情报
- 检测 CVE 是否有对应的 Tenable 检测插件
- 将插件页面 URL 作为参考链接添加到 CVE 数据中
- 与现有数据源进行关联整合

## Non-Goals (Out of Scope)

- 不实现 Tenable 付费 API 的访问
- 不实现 Tenable 企业版功能集成
- 不修改前端展示逻辑（仅添加数据源）

## Background & Context

- 当前平台已集成 cvelistV5、Exploit-DB、Metasploit、Packet Storm、Tenable 等数据源
- Tenable 提供公开的漏洞数据库和检测插件信息
- 需要检测插件页面是否有数据，如果有则添加为参考链接

## Functional Requirements

- **FR-1**: 创建 Tenable 爬虫模块，支持获取公开漏洞数据
- **FR-2**: 解析 Tenable 数据格式，提取 CVE ID、描述、CVSS 评分等信息
- **FR-3**: 检测 CVE 是否有对应的 Tenable 检测插件
- **FR-4**: 如果插件页面有数据，将插件页面 URL 添加为参考链接
- **FR-5**: 将数据存储到数据库，与现有 CVE 记录关联
- **FR-6**: 支持增量更新和去重

## Non-Functional Requirements

- **NFR-1**: 爬虫需要遵守 Tenable 网站的 robots.txt 规则
- **NFR-2**: 支持配置请求速率限制，避免被封禁
- **NFR-3**: 代码风格与现有爬虫保持一致

## Constraints

- **Technical**: Python 3.10+, FastAPI, SQLAlchemy
- **Dependencies**: httpx（已有）、现有数据库模型

## Assumptions

- Tenable 公开数据可以通过 HTTP 请求访问
- 插件页面返回 "No plugins found for this CVE" 表示没有插件
- 数据格式稳定且有规律

## Acceptance Criteria

### AC-1: Tenable 爬虫模块创建成功

- **Given**: 系统已启动
- **When**: 运行 Tenable 爬虫
- **Then**: 成功获取漏洞数据并存储到数据库
- **Verification**: `programmatic`

### AC-2: 数据解析正确

- **Given**: Tenable 爬虫运行中
- **When**: 解析漏洞数据
- **Then**: 正确提取 CVE ID、描述、评分等字段
- **Verification**: `programmatic`

### AC-3: 插件检测功能正常

- **Given**: CVE 有 Tenable 检测插件
- **When**: 访问插件页面
- **Then**: 检测到插件存在，将 URL 添加为参考链接
- **Verification**: `programmatic`

### AC-4: 数据去重正常

- **Given**: 多次运行爬虫
- **When**: 导入重复数据
- **Then**: 不会创建重复记录
- **Verification**: `programmatic`

## Open Questions

- [ ] Tenable 插件页面的具体响应格式
- [x] 插件检测逻辑已实现

