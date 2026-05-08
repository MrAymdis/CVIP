# 用户认证与权限校验 - 产品需求文档

## Overview
- **Summary**: 为网络安全漏洞情报平台增加完整的用户认证和权限校验功能，包括用户注册、登录、JWT 令牌管理、角色权限控制等。
- **Purpose**: 保护平台敏感数据和功能，确保只有授权用户可以访问特定资源和操作。
- **Target Users**: 平台管理员、普通用户、API 调用者

## Goals
- 实现用户注册和登录功能
- 提供安全的 JWT 令牌管理
- 实现基于角色的访问控制 (RBAC)
- 保护现有的 API 端点
- 确保密码安全存储

## Non-Goals (Out of Scope)
- 第三方 OAuth 登录（如 GitHub、Google）
- 多因素认证 (MFA)
- 单点登录 (SSO)
- 细粒度的资源级权限控制（第一版只做角色级）

## Background & Context
- 当前平台使用 FastAPI 框架，没有任何认证机制
- 数据库使用 PostgreSQL，ORM 为 SQLAlchemy
- 已有用户、角色等相关概念需要定义
- 需要遵循安全最佳实践

## Functional Requirements
- **FR-1**: 用户可以注册新账户
- **FR-2**: 用户可以使用用户名/密码登录
- **FR-3**: 系统使用 JWT 进行身份验证
- **FR-4**: 系统支持多种用户角色（如 admin、user）
- **FR-5**: API 端点可以通过装饰器进行权限保护
- **FR-6**: 用户可以刷新访问令牌
- **FR-7**: 用户可以登出（失效令牌）

## Non-Functional Requirements
- **NFR-1**: 密码使用 bcrypt 等强加密算法存储
- **NFR-2**: JWT 令牌设置合理的过期时间
- **NFR-3**: 认证和权限检查性能不显著影响 API 响应时间
- **NFR-4**: 所有敏感操作记录审计日志

## Constraints
- **Technical**: FastAPI 框架、SQLAlchemy ORM、PostgreSQL 数据库
- **Business**: 需要在不破坏现有功能的情况下集成
- **Dependencies**: python-jose、passlib[bcrypt]、python-multipart

## Assumptions
- 平台目前没有现有用户数据
- 所有现有 API 默认需要认证（可选择性公开）
- 管理员角色拥有所有权限

## Acceptance Criteria

### AC-1: 用户注册
- **Given**: 用户提供有效的用户名、邮箱、密码
- **When**: 用户调用注册 API
- **Then**: 系统创建用户账户，密码被安全哈希存储，返回成功响应
- **Verification**: `programmatic`

### AC-2: 用户登录
- **Given**: 用户提供正确的用户名和密码
- **When**: 用户调用登录 API
- **Then**: 系统返回有效的访问令牌和刷新令牌
- **Verification**: `programmatic`

### AC-3: 无效凭证登录
- **Given**: 用户提供错误的用户名或密码
- **When**: 用户调用登录 API
- **Then**: 系统返回 401 错误，不返回任何令牌
- **Verification**: `programmatic`

### AC-4: JWT 令牌验证
- **Given**: 用户拥有有效的访问令牌
- **When**: 用户访问需要认证的 API 端点
- **Then**: 系统验证令牌并允许访问
- **Verification**: `programmatic`

### AC-5: 过期令牌处理
- **Given**: 用户的访问令牌已过期
- **When**: 用户访问需要认证的 API 端点
- **Then**: 系统返回 401 错误，提示令牌过期
- **Verification**: `programmatic`

### AC-6: 刷新令牌
- **Given**: 用户拥有有效的刷新令牌
- **When**: 用户调用刷新令牌 API
- **Then**: 系统返回新的访问令牌
- **Verification**: `programmatic`

### AC-7: 基于角色的权限控制
- **Given**: 用户拥有特定角色权限
- **When**: 用户访问需要特定角色的 API 端点
- **Then**: 系统检查用户角色，符合条件则允许访问，否则返回 403 错误
- **Verification**: `programmatic`

## Open Questions
- [ ] 具体需要哪些角色？（默认建议：admin、user）
- [ ] 哪些 API 端点应该公开？哪些需要认证？
- [ ] 令牌过期时间设置多久合适？
