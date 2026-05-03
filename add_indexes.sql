-- 添加 view_count 索引
CREATE INDEX IF NOT EXISTS idx_unified_view_count 
ON unified_vulnerabilities (view_count);

-- 添加 view_count 降序索引
CREATE INDEX IF NOT EXISTS idx_unified_view_count_desc 
ON unified_vulnerabilities (view_count DESC);

-- 优化统计查询的复合索引
CREATE INDEX IF NOT EXISTS idx_unified_stats_composite 
ON unified_vulnerabilities (published_date, modified_date, severity, cisa_kev, exploits_count);

-- 验证索引
SELECT indexname, indexdef 
FROM pg_indexes 
WHERE tablename = 'unified_vulnerabilities'
ORDER BY indexname;
