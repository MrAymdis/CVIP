# 用户认证与权限校验 - 实现计划

## [x] Task 1: 添加依赖包和配置更新
- **Priority**: high
- **Depends On**: None
- **Description**:
  - 更新 requirements.txt，添加必要的依赖包（python-jose、passlib[bcrypt]
  - 更新 config.py，添加 JWT 相关配置项
- **Acceptance Criteria Addressed**: NFR-1, NFR-2
- **Test Requirements**:
  - `programmatic` TR-1.1: 依赖包能够正确安装
  - `programmatic` TR-1.2: 配置项正确加载
- **Notes**: 使用环境变量包括：SECRET_KEY、ACCESS_TOKEN_EXPIRE_MINUTES、REFRESH_TOKEN_EXPIRE_DAYS

## [x] Task 2: 创建用户和角色数据模型
- **Priority**: high
- **Depends On**: Task 1
- **Description**:
  - 在 models/ 目录下创建 user.py 和 role.py
  - 定义 User 模型，包含字段：id、username、email、hashed_password、is_active、role_id、created_at、updated_at
  - 定义 Role 模型，包含字段：id、name、description、created_at
  - 创建 User-Role 关系
- **Acceptance Criteria Addressed**: FR-4
- **Test Requirements**:
  - `programmatic` TR-2.1: 数据模型定义正确
  - `programmatic` TR-2.2: 数据库表能够正确创建
- **Notes**: 默认角色包括 admin 和 user

## [x] Task 3: 创建认证相关的 Schema
- **Priority**: high
- **Depends On**: Task 2
- **Description**:
  - 在 schemas/ 目录下创建 auth.py
  - 定义 UserCreate、UserLogin、Token、TokenData 等 Pydantic 模型
- **Acceptance Criteria Addressed**: FR-1, FR-2
- **Test Requirements**:
  - `programmatic` TR-3.1: Schema 定义正确，验证有效

## [x] Task 4: 实现认证服务层
- **Priority**: high
- **Depends On**: Task 3
- **Description**:
  - 在 services/ 目录下创建 auth.py
  - 实现密码哈希和验证
  - 实现 JWT 令牌创建和验证
  - 实现用户认证逻辑
- **Acceptance Criteria Addressed**: FR-1, FR-2, FR-3, FR-6, FR-7
- **Test Requirements**:
  - `programmatic` TR-4.1: 密码正确哈希和验证
  - `programmatic` TR-4.2: JWT 正确创建和验证
  - `programmatic` TR-4.3: 令牌刷新功能正常
- **Notes**: 使用 bcrypt 哈希算法

## [x] Task 5: 创建认证路由
- **Priority**: high
- **Depends On**: Task 4
- **Description**:
  - 在 routers/ 目录下创建 auth.py
  - 实现 /register、/login、/refresh-token、/logout 端点
- **Acceptance Criteria Addressed**: FR-1, FR-2, FR-6, FR-7
- **Test Requirements**:
  - `programmatic` TR-5.1: 注册端点能够创建用户
  - `programmatic` TR-5.2: 登录端点能够返回令牌
  - `programmatic` TR-5.3: 刷新令牌端点能够刷新访问令牌
  - `programmatic` TR-5.4: 所有认证端点错误处理正确

## [x] Task 6: 实现依赖项和权限装饰器
- **Priority**: high
- **Depends On**: Task 5
- **Description**:
  - 创建 dependencies.py，实现 get_current_user、get_current_active_user 等依赖项
  - 实现基于角色的权限检查依赖项
- **Acceptance Criteria Addressed**: FR-4, FR-5, AC-7
- **Test Requirements**:
  - `programmatic` TR-6.1: 依赖项能够正确获取当前用户
  - `programmatic` TR-6.2: 权限检查能够正确验证角色

## [x] Task 7: 保护现有 API 端点
- **Priority**: high
- **Depends On**: Task 6
- **Description**:
  - 更新 main.py 中集成 auth 路由
  - 为现有的 API 端点添加认证和权限保护
  - 确定哪些端点公开，哪些需要认证
- **Acceptance Criteria Addressed**: FR-5, AC-4, AC-5, AC-7
- **Test Requirements**:
  - `programmatic` TR-7.1: 需要认证的端点在没有令牌时返回 401
  - `programmatic` TR-7.2: 认证通过的端点可以正常访问
  - `programmatic` TR-7.3: 需要特定角色的端点在角色不匹配时返回 403

## [x] Task 8: 初始化默认用户和角色
- **Priority**: medium
- **Depends On**: Task 2
- **Description**:
  - 创建初始化脚本，用于创建默认角色和管理员用户
- **Acceptance Criteria Addressed**: FR-4
- **Test Requirements**:
  - `human-judgement` TR-8.1: 脚本能够正确创建默认角色
  - `human-judgement` TR-8.2: 脚本能够创建默认管理员用户

## [x] Task 9: 更新文档和测试
- **Priority**: medium
- **Depends On**: Task 7
- **Description**:
  - 更新 API 文档中添加认证相关文档
  - 编写单元测试和集成测试
- **Acceptance Criteria Addressed**: 所有 AC
- **Test Requirements**:
  - `human-judgement` TR-9.1: API 文档完整
  - `programmatic` TR-9.2: 测试覆盖主要功能
