# 搜索页面漏洞列表按时间排序功能 - 产品需求文档

## Overview
- **Summary**: 为搜索页面添加漏洞列表的时间排序功能，支持用户选择按发布日期升序或降序排列
- **Purpose**: 提升用户体验，让用户可以根据需求灵活调整漏洞列表的显示顺序
- **Target Users**: 安全研究人员、漏洞管理人员

## Goals
- 支持按发布日期升序/降序排序
- 支持按修改日期升序/降序排序（可选）
- 提供直观的排序选择界面
- 保持与现有筛选功能的兼容性

## Non-Goals (Out of Scope)
- 不支持其他字段的排序（如CVSS分数、严重程度等）
- 不修改搜索结果的数据结构

## Background & Context
- 当前搜索页面已支持高级筛选（类型、严重程度、日期范围等）
- 后端统一搜索API已默认按发布日期降序排序
- 需要添加可配置的排序参数

## Functional Requirements
- **FR-1**: 用户可以在搜索结果页面选择排序字段（发布日期/修改日期）
- **FR-2**: 用户可以选择排序方向（升序/降序）
- **FR-3**: 排序设置与其他筛选条件协同工作

## Non-Functional Requirements
- **NFR-1**: 排序切换后页面响应时间 < 2秒
- **NFR-2**: 排序状态应在URL参数中保持，支持页面刷新后保持状态

## Constraints
- **Technical**: 基于Next.js和FastAPI的现有架构
- **Dependencies**: 需要修改前端search/page.tsx和后端unified_search.py

## Assumptions
- 用户期望最新发布的漏洞优先显示（默认降序）
- 用户可能需要按时间顺序查看历史漏洞

## Acceptance Criteria

### AC-1: 排序选项UI展示
- **Given**: 用户访问搜索页面
- **When**: 页面加载完成
- **Then**: 显示排序选择器，包含"排序方式"和"排序方向"两个下拉框
- **Verification**: `human-judgment`

### AC-2: 按发布日期降序排序（默认）
- **Given**: 用户未修改排序设置
- **When**: 搜索结果显示
- **Then**: 漏洞按发布日期从新到旧排列
- **Verification**: `programmatic`

### AC-3: 按发布日期升序排序
- **Given**: 用户选择"发布日期"和"升序"
- **When**: 触发搜索
- **Then**: 漏洞按发布日期从旧到新排列
- **Verification**: `programmatic`

### AC-4: 按修改日期排序
- **Given**: 用户选择"修改日期"作为排序字段
- **When**: 触发搜索
- **Then**: 漏洞按修改日期排列
- **Verification**: `programmatic`

### AC-5: URL参数保持排序状态
- **Given**: 用户设置了排序条件
- **When**: 页面刷新
- **Then**: 排序状态保持不变
- **Verification**: `programmatic`

## Open Questions
- [ ] 是否需要支持按CVSS分数或严重程度排序？（当前只实现时间排序）
