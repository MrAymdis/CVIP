# CWE信息完善 - 产品需求文档

## Overview
- **Summary**: 完善现有CWE（Common Weakness Enumeration）模型，添加更多关键字段以支持完整的安全漏洞分类和分析功能
- **Purpose**: 提升漏洞情报平台对CWE信息的管理能力，提供更全面的弱点分类、严重程度评估和缓解措施建议
- **Target Users**: 安全研究人员、漏洞分析人员、开发人员

## Goals
- 扩展CWE模型，添加完整的CWE数据字段
- 提供CWE数据的CRUD API接口
- 支持CWE数据的批量导入和更新
- 建立CWE与CVE漏洞的关联分析能力

## Non-Goals (Out of Scope)
- 不涉及前端界面开发
- 不修改现有CVE模型结构
- 不涉及权限认证系统

## Background & Context
- 当前CWE模型仅包含基础字段：cwe_id, name, description, cve_count
- 需要参考MITRE CWE官方数据规范进行扩展
- 项目使用FastAPI + SQLAlchemy技术栈

## Functional Requirements
- **FR-1**: 扩展CWE数据库模型，包含完整的CWE字段（弱点类型、严重程度、攻击向量、影响范围等）
- **FR-2**: 创建CWE数据的Pydantic Schema定义
- **FR-3**: 实现CWE的CRUD API接口（列表查询、详情、创建、更新、删除）
- **FR-4**: 实现CWE数据的批量导入功能
- **FR-5**: 实现CWE与CVE的关联查询功能

## Non-Functional Requirements
- **NFR-1**: API响应时间<100ms（单条查询）
- **NFR-2**: 支持批量导入1000+条CWE数据
- **NFR-3**: 数据库表需建立合适的索引以优化查询性能

## Constraints
- **Technical**: Python 3.10+, FastAPI, SQLAlchemy, PostgreSQL
- **Dependencies**: 需与现有项目结构保持一致

## Assumptions
- 项目已正确配置数据库连接
- 现有代码风格和架构模式将被遵循

## Acceptance Criteria

### AC-1: CWE模型扩展完成
- **Given**: 现有CWE模型仅包含4个基础字段
- **When**: 执行数据库迁移并创建新表结构
- **Then**: CWE表包含完整的字段定义（弱点类型、严重程度、攻击向量、影响范围、缓解措施等）
- **Verification**: `programmatic`

### AC-2: CWE Schema定义完成
- **Given**: 需要定义CWE数据的输入输出格式
- **When**: 创建pydantic schema文件
- **Then**: 提供CWEBase、CWECreate、CWEUpdate、CWEResponse等schema类
- **Verification**: `programmatic`

### AC-3: CWE CRUD API实现完成
- **Given**: 前端需要访问CWE数据
- **When**: 实现API路由
- **Then**: 提供GET /api/v1/cwe (列表)、GET /api/v1/cwe/{cwe_id} (详情)、POST/PUT/DELETE等接口
- **Verification**: `programmatic`

### AC-4: CWE批量导入功能完成
- **Given**: 需要从CWE官方数据源导入数据
- **When**: 调用批量导入接口
- **Then**: 支持JSON格式批量导入，返回导入成功/失败统计
- **Verification**: `programmatic`

### AC-5: CWE与CVE关联查询完成
- **Given**: 用户需要查询某CWE关联的所有CVE
- **When**: 调用关联查询接口
- **Then**: 返回该CWE关联的CVE列表及统计信息
- **Verification**: `programmatic`

## Open Questions
- [ ] 是否需要支持CWE的层级分类（Category/View/Weakness）？
- [ ] 是否需要支持中文字段（name_zh, description_zh）？
