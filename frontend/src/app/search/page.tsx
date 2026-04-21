"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Search, Filter, ChevronDown, Shield, AlertTriangle, Bug, FileCode } from "lucide-react";

interface Vulnerability {
  type: string;
  id: string;
  title: string;
  description?: string;
  source: string;
  severity?: string;
  cvss_score?: number;
  published_date: string | null;
  references_count: number;
  exploits_count: number;
}

interface SearchResponse {
  total: number;
  page: number;
  page_size: number;
  data: Vulnerability[];
  cve_count: number;
  vulnerability_count: number;
  osv_count: number;
}

const severityColors: Record<string, string> = {
  CRITICAL: "bg-red-500 text-white",
  HIGH: "bg-orange-500 text-white",
  MEDIUM: "bg-yellow-500 text-black",
  LOW: "bg-blue-500 text-white",
  MODERATE: "bg-yellow-500 text-black",
  critical: "bg-red-500 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-yellow-500 text-black",
  low: "bg-blue-500 text-white",
  moderate: "bg-yellow-500 text-black",
};

const severityLabels: Record<string, string> = {
  CRITICAL: "严重",
  HIGH: "高危",
  MEDIUM: "中危",
  LOW: "低危",
  MODERATE: "中危",
  critical: "严重",
  high: "高危",
  medium: "中危",
  low: "低危",
  moderate: "中危",
};

export default function SearchPage() {
  const searchParams = useSearchParams();
  const [query, setQuery] = useState(searchParams.get("q") || "");
  const [results, setResults] = useState<SearchResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [showFilters, setShowFilters] = useState(false);
  
  // Filters
  const [severity, setSeverity] = useState("");
  const [vulnType, setVulnType] = useState("all"); // all, cve, vulnerability
  const [hasExploit, setHasExploit] = useState<string>(""); // "", "yes", "no"
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");
  const [sortBy, setSortBy] = useState(searchParams.get("sort_by") || "published_date");
  const [sortOrder, setSortOrder] = useState(searchParams.get("sort_order") || "desc");

  const doFetch = async (currentQuery: string, currentPage: number) => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (currentQuery) params.set("q", currentQuery);
      if (severity) params.set("severity", severity);
      if (vulnType !== "all") params.set("type", vulnType);
      if (hasExploit === "yes") params.set("has_exploit", "true");
      if (hasExploit === "no") params.set("has_exploit", "false");
      if (startDate) params.set("published_after", startDate);
      if (endDate) params.set("published_before", endDate);
      params.set("sort_by", sortBy);
      params.set("sort_order", sortOrder);
      params.set("page", currentPage.toString());
      params.set("page_size", pageSize.toString());

      const response = await fetch(
        `/api/v1/search?${params.toString()}`
      );
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.json();
      setResults(data);
    } catch (error) {
      console.error("Search error:", error);
      setResults(null);
    } finally {
      setLoading(false);
    }
  };

  const resetFilters = () => {
    setSeverity("");
    setVulnType("all");
    setHasExploit("");
    setStartDate("");
    setEndDate("");
    setPage(1);
  };

  useEffect(() => {
    doFetch(query, page);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query, page, pageSize, severity, vulnType, hasExploit, startDate, endDate, sortBy, sortOrder]);

  const fetchResults = () => {
    doFetch(query, page);
  };

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return 'N/A';
    return new Date(dateStr).toLocaleDateString("zh-CN");
  };

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-900">
      {/* Header */}
      <header className="border-b bg-white dark:bg-slate-950 sticky top-0 z-10">
        <div className="container mx-auto px-4 h-16 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2">
            <Shield className="h-8 w-8 text-primary" />
            <span className="text-xl font-bold">漏洞情报平台</span>
          </Link>
          <nav className="flex items-center gap-6">
            <Link href="/search" className="text-sm font-medium text-primary">
              搜索
            </Link>
            <Link href="/stats" className="text-sm font-medium hover:text-primary">
              统计
            </Link>
          </nav>
        </div>
      </header>

      <div className="container mx-auto px-4 py-8">
        {/* Search Bar */}
        <div className="max-w-3xl mx-auto mb-8">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              fetchResults();
            }}
            className="relative"
          >
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 h-5 w-5 text-muted-foreground" />
            <input
              type="text"
              placeholder="搜索漏洞 ID、标题、描述..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="w-full pl-12 pr-4 py-4 bg-white dark:bg-slate-800 rounded-xl border shadow-sm text-lg focus:outline-none focus:ring-2 focus:ring-primary"
            />
          </form>
          
          {/* Filter Toggle */}
          <button
            onClick={() => setShowFilters(!showFilters)}
            className="mt-4 flex items-center gap-2 text-sm text-muted-foreground hover:text-primary"
          >
            <Filter className="h-4 w-4" />
            高级筛选
            <ChevronDown className={`h-4 w-4 transition-transform ${showFilters ? "rotate-180" : ""}`} />
          </button>

          {/* Filters */}
          {showFilters && (
            <div className="mt-4 p-4 bg-white dark:bg-slate-800 rounded-xl border">
              <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
                <div>
                  <label className="text-sm font-medium mb-2 block">漏洞类型</label>
                  <select
                    value={vulnType}
                    onChange={(e) => setVulnType(e.target.value)}
                    className="w-full p-2 border rounded-lg bg-background"
                  >
                    <option value="all">全部</option>
                    <option value="cve">CVE漏洞</option>
                    <option value="cnvd">CNVD漏洞</option>
                    <option value="osv">OSV漏洞</option>
                  </select>
                </div>
                <div>
                  <label className="text-sm font-medium mb-2 block">严重程度</label>
                  <select
                    value={severity}
                    onChange={(e) => setSeverity(e.target.value)}
                    className="w-full p-2 border rounded-lg bg-background"
                  >
                    <option value="">全部</option>
                    <option value="CRITICAL">严重</option>
                    <option value="HIGH">高危</option>
                    <option value="MEDIUM">中危</option>
                    <option value="LOW">低危</option>
                  </select>
                </div>
                <div>
                  <label className="text-sm font-medium mb-2 block">是否有Exploit</label>
                  <select
                    value={hasExploit}
                    onChange={(e) => setHasExploit(e.target.value)}
                    className="w-full p-2 border rounded-lg bg-background"
                  >
                    <option value="">全部</option>
                    <option value="yes">有Exploit</option>
                    <option value="no">无Exploit</option>
                  </select>
                </div>
                <div>
                  <label className="text-sm font-medium mb-2 block">发布日期开始</label>
                  <input
                    type="date"
                    value={startDate}
                    onChange={(e) => setStartDate(e.target.value)}
                    className="w-full p-2 border rounded-lg bg-background"
                  />
                </div>
                <div>
                  <label className="text-sm font-medium mb-2 block">发布日期结束</label>
                  <input
                    type="date"
                    value={endDate}
                    onChange={(e) => setEndDate(e.target.value)}
                    className="w-full p-2 border rounded-lg bg-background"
                  />
                </div>
                <div className="flex items-end">
                  <button
                    onClick={resetFilters}
                    className="w-full p-2 border rounded-lg bg-muted hover:bg-muted/80 text-sm"
                  >
                    重置筛选
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Results */}
        <div className="max-w-4xl mx-auto">
          {loading ? (
            <div className="text-center py-12">
              <div className="animate-spin h-8 w-8 border-2 border-primary border-t-transparent rounded-full mx-auto"></div>
              <p className="mt-4 text-muted-foreground">搜索中...</p>
            </div>
          ) : results && results.data ? (
            <>
              <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
                <div className="text-sm text-muted-foreground">
                  找到 {results.total} 条结果
                  {results.cve_count > 0 && (
                    <span className="mx-2">|</span>
                  )}
                  {results.cve_count > 0 && (
                    <span>CVE: {results.cve_count}</span>
                  )}
                  {results.vulnerability_count > 0 && (
                    <>
                      <span className="mx-2">|</span>
                      <span>CNVD: {results.vulnerability_count}</span>
                    </>
                  )}
                  {results.osv_count > 0 && (
                    <>
                      <span className="mx-2">|</span>
                      <span>OSV: {results.osv_count}</span>
                    </>
                  )}
                </div>
                <div className="flex items-center gap-4">
                  <div className="flex items-center gap-2">
                    <label className="text-sm text-muted-foreground">排序：</label>
                    <select
                      value={sortBy}
                      onChange={(e) => {
                        setSortBy(e.target.value);
                        setPage(1);
                      }}
                      className="px-3 py-1 border rounded-lg text-sm bg-white dark:bg-slate-800"
                    >
                      <option value="published_date">发布日期</option>
                      <option value="modified_date">修改日期</option>
                    </select>
                    <select
                      value={sortOrder}
                      onChange={(e) => {
                        setSortOrder(e.target.value);
                        setPage(1);
                      }}
                      className="px-3 py-1 border rounded-lg text-sm bg-white dark:bg-slate-800"
                    >
                      <option value="desc">降序</option>
                      <option value="asc">升序</option>
                    </select>
                  </div>
                  <div className="flex items-center gap-2">
                    <label className="text-sm text-muted-foreground">每页显示：</label>
                    <select
                      value={pageSize}
                      onChange={(e) => {
                        setPageSize(Number(e.target.value));
                        setPage(1);
                      }}
                      className="px-3 py-1 border rounded-lg text-sm bg-white dark:bg-slate-800"
                    >
                      <option value={20}>20条</option>
                      <option value={50}>50条</option>
                      <option value={100}>100条</option>
                    </select>
                  </div>
                </div>
              </div>

              <div className="space-y-4">
                {results.data.map((vuln, index) => (
                  <Link
                    key={`${vuln.type}-${vuln.id}-${index}`}
                    href={`/vuln/${vuln.id}`}
                    className="block p-6 bg-white dark:bg-slate-800 rounded-xl border hover:shadow-md transition-shadow"
                  >
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-3 mb-2">
                          <span className="font-mono font-bold text-lg">{vuln.id}</span>
                          <span className={`px-2 py-0.5 text-xs rounded-full font-medium ${
                            vuln.type === 'cve' 
                              ? 'bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-300'
                              : vuln.type === 'osv'
                                ? 'bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300'
                                : 'bg-purple-100 dark:bg-purple-900 text-purple-700 dark:text-purple-300'
                          }`}>
                            {vuln.type === 'cve' ? 'CVE' : vuln.type === 'osv' ? 'OSV' : 'Vulnerability'}
                          </span>
                          {vuln.exploits_count > 0 && (
                            <span className="px-2 py-0.5 bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300 text-xs rounded-full font-medium flex items-center gap-1">
                              <FileCode className="h-3 w-3" />
                              {vuln.exploits_count}
                            </span>
                          )}
                        </div>
                        <h3 className="font-medium mb-2 line-clamp-2">
                          {vuln.title || "无标题"}
                        </h3>
                        <div className="flex items-center gap-4 text-sm text-muted-foreground">
                          <span>来源: {vuln.source}</span>
                          <span>{formatDate(vuln.published_date)}</span>
                          {vuln.references_count > 0 && (
                            <span>参考: {vuln.references_count}</span>
                          )}
                        </div>
                      </div>
                      <div className="flex flex-col items-end gap-2">
                        {vuln.severity && (
                          <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                            severityColors[vuln.severity] || "bg-gray-500 text-white"
                          }`}>
                            {vuln.cvss_score ? `${vuln.cvss_score.toFixed(1)} ` : ""}
                            {severityLabels[vuln.severity] || vuln.severity}
                          </span>
                        )}
                      </div>
                    </div>
                  </Link>
                ))}
              </div>

              {/* Pagination */}
              {results.total > results.page_size && (
                <div className="flex justify-center gap-2 mt-8">
                  <button
                    onClick={() => setPage(page - 1)}
                    disabled={page === 1}
                    className="px-4 py-2 border rounded-lg disabled:opacity-50 hover:bg-muted"
                  >
                    上一页
                  </button>
                  <span className="px-4 py-2">
                    第 {page} 页 / 共 {Math.ceil(results.total / results.page_size)} 页
                  </span>
                  <button
                    onClick={() => setPage(page + 1)}
                    disabled={page >= Math.ceil(results.total / results.page_size)}
                    className="px-4 py-2 border rounded-lg disabled:opacity-50 hover:bg-muted"
                  >
                    下一页
                  </button>
                </div>
              )}
            </>
          ) : (
            <div className="text-center py-12">
              <AlertTriangle className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p className="text-muted-foreground">未找到相关漏洞</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}