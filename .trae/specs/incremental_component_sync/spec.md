# 增量漏洞数据更新组件信息 Spec

## Why
现有组件同步逻辑存在以下问题：
1. 每次同步都从全部漏洞数据重新遍历，效率低下
2. 无法增量处理新增加的漏洞数据
3. 组件关联的漏洞ID可能重复添加
4. 使用 Python hash() 生成组件ID不稳定，导致相同产品产生不同ID

## What Changes
- 新增增量同步功能：只处理自上次同步后新增或更新的漏洞
- 基于 updated_at 字段判断增量数据
- 新增定时增量同步任务
- 优化组件合并逻辑，避免重复关联漏洞ID

## Impact
- Affected specs: 组件信息管理
- Affected code:
  - backend/app/services/component_parser.py
  - backend/app/routers/components.py
  - 新增: backend/app/services/incremental_sync.py (定时任务)

## ADDED Requirements

### Requirement: 增量同步API
系统 SHALL 提供增量同步组件的API接口

#### Scenario: 增量同步组件数据
- **WHEN** 调用 POST /components/sync/incremental
- **THEN** 仅同步自上次同步时间点之后新增或更新的漏洞数据

### Requirement: 增量同步状态记录
系统 SHALL 记录每次同步的时间戳和状态

#### Scenario: 记录同步状态
- **WHEN** 增量同步完成时
- **THEN** 记录同步时间戳、同步的漏洞数量、添加的组件数量、更新关联的组件数量

### Requirement: 定时增量同步
系统 SHALL 支持定时执行增量同步任务，频率为每天1次

#### Scenario: 自动增量同步
- **WHEN** 每天定时时间到达（默认凌晨2点）
- **THEN** 自动执行增量同步任务

## MODIFIED Requirements

### Requirement: 组件同步函数
修改 `sync_components_from_vulnerabilities` 函数：
- 添加增量模式支持
- 仅处理指定时间之后的漏洞数据
- 避免重复关联漏洞ID

## REMOVED Requirements
无

## Implementation Notes
- 使用 PostgreSQL 的 updated_at 字段进行增量判断
- 在 Redis 或数据库中存储上次同步时间戳
- 批量处理时每5000条提交一次
- 确保组件ID生成使用稳定的哈希算法（已使用 md5）
