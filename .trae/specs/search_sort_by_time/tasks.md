# 搜索页面漏洞列表按时间排序功能 - 实现计划

## [ ] Task 1: 后端API添加排序参数支持
- **Priority**: P0
- **Depends On**: None
- **Description**: 
  - 在unified_search.py的unified_search函数中添加sort_by和sort_order参数
  - 支持按published_date和modified_date排序
  - 根据参数动态调整排序逻辑
- **Acceptance Criteria Addressed**: AC-3, AC-4
- **Test Requirements**:
  - `programmatic` TR-1.1: GET /api/v1/search?sort_by=published_date&sort_order=asc 返回按发布日期升序排列的结果
  - `programmatic` TR-1.2: GET /api/v1/search?sort_by=modified_date&sort_order=desc 返回按修改日期降序排列的结果
- **Notes**: 需要注意日期字段可能为None的情况

## [ ] Task 2: 前端添加排序选择器组件
- **Priority**: P0
- **Depends On**: Task 1
- **Description**: 
  - 在search/page.tsx中添加排序字段选择器（发布日期/修改日期）
  - 添加排序方向选择器（升序/降序）
  - 将排序参数添加到搜索请求中
  - 支持URL参数保持排序状态
- **Acceptance Criteria Addressed**: AC-1, AC-2, AC-5
- **Test Requirements**:
  - `human-judgment` TR-2.1: 排序选择器在页面上清晰可见，位于结果统计区域
  - `programmatic` TR-2.2: 排序参数正确传递到API请求中
  - `programmatic` TR-2.3: URL包含sort_by和sort_order参数，刷新后保持状态

## [ ] Task 3: 集成测试与验证
- **Priority**: P1
- **Depends On**: Task 1, Task 2
- **Description**: 
  - 测试各种排序组合的正确性
  - 验证排序与筛选条件的组合使用
  - 检查分页与排序的兼容性
- **Acceptance Criteria Addressed**: AC-1~AC-5
- **Test Requirements**:
  - `programmatic` TR-3.1: 排序后第一页数据符合预期顺序
  - `programmatic` TR-3.2: 排序+筛选组合功能正常
  - `programmatic` TR-3.3: 排序+分页组合功能正常
