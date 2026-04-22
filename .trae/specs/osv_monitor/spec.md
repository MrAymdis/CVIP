# OSV实时监控功能 - 产品需求文档

## Overview
- **Summary**: 实现OSV (Open Source Vulnerability) 漏洞数据库的实时监控功能，每小时检查并同步增量漏洞数据到本地数据库。
- **Purpose**: 确保漏洞情报平台能够及时获取OSV数据库的最新漏洞信息，提供更及时的安全预警能力。
- **Target Users**: 安全研究人员、漏洞管理平台管理员

## Goals
- [ ] 实现OSV漏洞增量监控，每小时自动检查更新
- [ ] 获取最近修改的OSV漏洞数据
- [ ] 将增量数据入库，支持新增和更新操作

## Non-Goals (Out of Scope)
- [ ] 全量同步OSV数据库（已有其他方式处理）
- [ ] 修改现有OSV数据模型结构
- [ ] 修改现有API接口

## Background & Context
- OSV是Google维护的开源漏洞数据库，提供REST API接口
- 参考NVD监控器的实现模式 (`crawlers/nvd_monitor.py`)
- 已有OSV数据模型支持存储完整的OSV漏洞信息

## Functional Requirements
- **FR-1**: 实现OSV监控器类，支持获取最近N小时修改的漏洞
- **FR-2**: 实现漏洞数据解析和数据库入库功能
- **FR-3**: 支持单次运行和持续监控两种模式
- **FR-4**: 支持命令行参数控制运行模式

## Non-Functional Requirements
- **NFR-1**: 每小时自动执行检查
- **NFR-2**: 处理API限流和异常情况
- **NFR-3**: 输出清晰的日志信息

## Constraints
- **Technical**: 使用Python 3.x，遵循现有代码风格，使用requests库进行HTTP请求
- **Dependencies**: OSV API (https://api.osv.dev/)

## Assumptions
- [ ] OSV API服务可用
- [ ] 数据库连接正常
- [ ] 网络连接稳定

## Acceptance Criteria

### AC-1: 获取最近1小时修改的OSV漏洞
- **Given**: OSV监控器已初始化
- **When**: 调用获取增量漏洞方法
- **Then**: 返回最近1小时内修改的漏洞列表
- **Verification**: `programmatic`

### AC-2: 将漏洞数据入库
- **Given**: 获取到增量漏洞数据
- **When**: 调用入库方法
- **Then**: 新漏洞被插入，已有漏洞被更新
- **Verification**: `programmatic`

### AC-3: 支持单次运行模式
- **Given**: 命令行无--continuous参数
- **When**: 执行监控脚本
- **Then**: 执行一次检查后退出
- **Verification**: `human-judgment`

### AC-4: 支持持续监控模式
- **Given**: 命令行有--continuous参数
- **When**: 执行监控脚本
- **Then**: 每小时执行一次检查
- **Verification**: `human-judgment`

## Open Questions
- [ ] OSV API是否有使用限制或需要认证？
