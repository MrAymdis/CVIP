# Tasks

## Task 1: 创建增量同步状态管理模块
- [x] SubTask 1.1: 在 Redis 中创建同步状态存储键 (key: component_sync:last_timestamp)
- [x] SubTask 1.2: 创建获取上次同步时间戳的函数
- [x] SubTask 1.3: 创建更新同步时间戳的函数

## Task 2: 修改组件解析器支持增量模式
- [x] SubTask 2.1: 修改 sync_components_from_vulnerabilities 函数添加增量参数
- [x] SubTask 2.2: 基于 updated_at 过滤增量漏洞数据
- [x] SubTask 2.3: 添加去重逻辑避免重复关联漏洞ID

## Task 3: 创建增量同步API接口
- [x] SubTask 3.1: 创建 POST /components/sync/incremental 接口
- [x] SubTask 3.2: 返回同步结果（新增组件数、更新组件数、处理的漏洞数）
- [x] SubTask 3.3: 自动更新同步时间戳

## Task 4: 创建定时增量同步任务
- [x] SubTask 4.1: 创建独立的后台同步脚本
- [x] SubTask 4.2: 支持配置同步间隔（每天凌晨2点执行）
- [x] SubTask 4.3: 记录同步日志

## Task 5: 验证增量同步功能
- [x] SubTask 5.1: 测试增量同步API正常工作
- [x] SubTask 5.2: 验证新增漏洞能被正确同步
- [x] SubTask 5.3: 验证重复同步不会重复添加漏洞ID

# Task Dependencies
- Task 3 依赖 Task 1 和 Task 2
- Task 4 依赖 Task 1 和 Task 2
- Task 5 依赖 Task 1, Task 2, Task 3
