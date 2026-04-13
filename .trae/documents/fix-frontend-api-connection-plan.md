# 修复前端 API 连接 - 实施计划

## 问题分析

当前前端页面在 Docker 环境中运行时，无法正确连接到后端 API。主要问题：

1. **环境变量未正确传递**: `NEXT_PUBLIC_API_URL` 在 Docker 构建时未被正确设置
2. **API 请求地址错误**: 前端代码中使用 `process.env.NEXT_PUBLIC_API_URL` 但在浏览器端可能为 `undefined`
3. **Docker 网络通信**: 前端容器需要正确访问后端容器

## 解决方案

### 方案 1: 硬编码 API URL (推荐用于开发)
在前端代码中直接使用相对路径或完整 URL，不依赖环境变量。

### 方案 2: 配置 Next.js 重写规则
在 `next.config.ts` 中配置 API 重写，将前端请求代理到后端。

### 方案 3: 修复环境变量传递
修改 Docker 配置，确保环境变量正确传递到前端容器。

## 实施步骤

### Step 1: 修改前端 API 调用方式
将前端代码中的 API 调用从：
```typescript
const API_URL = process.env.NEXT_PUBLIC_API_URL
```
改为：
```typescript
const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8006'
```

### Step 2: 更新 next.config.ts
配置 Next.js 重写规则，在开发环境中代理 API 请求：
```typescript
async rewrites() {
  return [
    {
      source: '/api/:path*',
      destination: 'http://backend:8000/api/:path*',
    },
  ];
}
```

### Step 3: 修复 Docker Compose 配置
确保前端容器可以访问后端服务：
- 前端容器通过 `http://backend:8000` 访问后端
- 或者使用主机网络模式

### Step 4: 创建 API 客户端工具
统一封装 API 调用，便于管理和调试：
```typescript
// lib/api.ts
const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8006';

export async function fetchCVE(cveId: string) {
  const res = await fetch(`${API_BASE}/api/v1/cve/${cveId}`);
  return res.json();
}
```

### Step 5: 测试验证
1. 重启 Docker 容器
2. 访问前端页面
3. 测试搜索功能
4. 测试详情页功能

## 预期结果
- 前端搜索页能正确显示 CVE 列表
- 详情页能正确加载 CVE 数据
- 统计页能正确显示数据

## 风险评估
- **低风险**: 主要是配置修改，不影响数据库和核心逻辑
- **回滚方案**: 如有问题可快速回滚到之前版本
