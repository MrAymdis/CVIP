"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Search, Filter, ChevronDown, Shield, AlertTriangle, Bug, FileCode, Flame, Clock, Building, ChevronRight, Star } from "lucide-react";

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
  github_advisory_count: number;
}

interface StatsResponse {
  total_cves: number;
  total_exploits: number;
  high_severity_count: number;
  cisa_kev_count: number;
  cves_this_year: number;
  github_advisory_critical_count: number;
  github_advisory_high_count: number;
  github_advisory_medium_count: number;
  github_advisory_low_count: number;
}

interface HotVulnerability {
  id: string;
  title: string;
  severity: string;
  published_date: string;
  source: string;
  vendor: string;
  product: string;
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

const severityBadgeColors: Record<string, string> = {
  CRITICAL: "bg-red-100 text-red-700",
  HIGH: "bg-orange-100 text-orange-700",
  MEDIUM: "bg-yellow-100 text-yellow-700",
  LOW: "bg-blue-100 text-blue-700",
  critical: "bg-red-100 text-red-700",
  high: "bg-orange-100 text-orange-700",
  medium: "bg-yellow-100 text-yellow-700",
  low: "bg-blue-100 text-blue-700",
};

export default function SearchPage() {
  const searchParams = useSearchParams();
  const [query, setQuery] = useState(searchParams.get("q") || "");
  const [results, setResults] = useState<SearchResponse | null>(null);
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [hotVulns, setHotVulns] = useState<HotVulnerability[]>([]);
  const [loading, setLoading] = useState(false);
  const [statsLoading, setStatsLoading] = useState(true);
  const [page, setPage] = useState(() => {
    const pageParam = searchParams.get("page");
    return pageParam ? parseInt(pageParam, 10) : 1;
  });
  const [pageSize, setPageSize] = useState(() => {
    const pageSizeParam = searchParams.get("page_size");
    return pageSizeParam ? parseInt(pageSizeParam, 10) : 10;
  });
  const [showFilters, setShowFilters] = useState(false);

  const [severity, setSeverity] = useState(searchParams.get("severity") || "");
  const [vulnType, setVulnType] = useState(searchParams.get("type") || "all");
  const [hasExploit, setHasExploit] = useState<string>(() => {
    const exploitParam = searchParams.get("has_exploit");
    if (exploitParam === "true") return "yes";
    if (exploitParam === "false") return "no";
    return "";
  });
  const [startDate, setStartDate] = useState(searchParams.get("published_after") || "");
  const [endDate, setEndDate] = useState(searchParams.get("published_before") || "");
  const [sortBy] = useState("published_date");
  const [sortOrder] = useState("desc");

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

      const response = await fetch(`/api/v1/search?${params.toString()}`);
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

  const fetchStats = async () => {
    setStatsLoading(true);
    try {
      const response = await fetch(`/api/v1/stats/overview`);
      const data = await response.json();
      setStats(data);

      const hotResponse = await fetch(`/api/v1/search?sort_by=published_date&sort_order=desc&page_size=4`);
      const hotData = await hotResponse.json();
      const hotItems: HotVulnerability[] = hotData.data.slice(0, 4).map((v: Vulnerability) => ({
        id: v.id,
        title: v.title || "",
        severity: v.severity || "",
        published_date: v.published_date || "",
        source: v.source,
        vendor: "",
        product: "",
      }));
      setHotVulns(hotItems);
    } catch (error) {
      console.error("Stats fetch error:", error);
    } finally {
      setStatsLoading(false);
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
  }, [query, page, pageSize, severity, vulnType, hasExploit, startDate, endDate]);

  useEffect(() => {
    fetchStats();
  }, []);

  const fetchResults = () => {
    doFetch(query, page);
  };

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return 'N/A';
    return new Date(dateStr).toLocaleDateString("zh-CN");
  };

  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800">
      <header className="border-b bg-white/80 backdrop-blur-sm dark:bg-slate-950/80 sticky top-0 z-10">
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
        <div className="max-w-4xl mx-auto mb-8">
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
              placeholder="请输入您要查询的漏洞名称、 GHSA ID、CVE ID、CNVD ID、OSV ID..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="w-full pl-12 pr-4 py-4 bg-white dark:bg-slate-800 rounded-xl border shadow-lg text-lg focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
            />
            <button
              type="submit"
              className="absolute right-2 top-1/2 -translate-y-1/2 px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary/90 transition-colors"
            >
              搜索
            </button>
          </form>
        </div>

        {!statsLoading && stats && (
          <div className="grid grid-cols-2 md:grid-cols-6 gap-4 mb-8">
            <div className="p-6 bg-white dark:bg-slate-800 rounded-xl border shadow-sm">
              <div className="flex items-center gap-3 mb-2">
                <div className="w-10 h-10 bg-blue-100 dark:bg-blue-900 rounded-lg flex items-center justify-center">
                  <Bug className="h-5 w-5 text-blue-600 dark:text-blue-400" />
                </div>
              </div>
              <div className="text-2xl font-bold text-blue-600 dark:text-blue-400">{(stats.total_cves || 0).toLocaleString()}</div>
              <div className="text-sm text-muted-foreground mt-1">全部漏洞</div>
            </div>
            <div className="p-6 bg-white dark:bg-slate-800 rounded-xl border shadow-sm">
              <div className="flex items-center gap-3 mb-2">
                <div className="w-10 h-10 bg-red-100 dark:bg-red-900 rounded-lg flex items-center justify-center">
                  <AlertTriangle className="h-5 w-5 text-red-600 dark:text-red-400" />
                </div>
              </div>
              <div className="text-2xl font-bold text-red-600 dark:text-red-400">{(stats.high_severity_count || 0).toLocaleString()}</div>
              <div className="text-sm text-muted-foreground mt-1">高危漏洞</div>
            </div>
            <div className="p-6 bg-white dark:bg-slate-800 rounded-xl border shadow-sm">
              <div className="flex items-center gap-3 mb-2">
                <div className="w-10 h-10 bg-orange-100 dark:bg-orange-900 rounded-lg flex items-center justify-center">
                  <Flame className="h-5 w-5 text-orange-600 dark:text-orange-400" />
                </div>
              </div>
              <div className="text-2xl font-bold text-orange-600 dark:text-orange-400">{(stats.cisa_kev_count || 0).toLocaleString()}</div>
              <div className="text-sm text-muted-foreground mt-1">CISA KEV</div>
            </div>
            <div className="p-6 bg-white dark:bg-slate-800 rounded-xl border shadow-sm">
              <div className="flex items-center gap-3 mb-2">
                <div className="w-10 h-10 bg-green-100 dark:bg-green-900 rounded-lg flex items-center justify-center">
                  <FileCode className="h-5 w-5 text-green-600 dark:text-green-400" />
                </div>
              </div>
              <div className="text-2xl font-bold text-green-600 dark:text-green-400">{(stats.total_exploits || 0).toLocaleString()}</div>
              <div className="text-sm text-muted-foreground mt-1">有EXP漏洞</div>
            </div>
            <div className="p-6 bg-white dark:bg-slate-800 rounded-xl border shadow-sm">
              <div className="flex items-center gap-3 mb-2">
                <div className="w-10 h-10 bg-purple-100 dark:bg-purple-900 rounded-lg flex items-center justify-center">
                  <Star className="h-5 w-5 text-purple-600 dark:text-purple-400" />
                </div>
              </div>
              <div className="text-2xl font-bold text-purple-600 dark:text-purple-400">{(stats.cves_this_year || 0).toLocaleString()}</div>
              <div className="text-sm text-muted-foreground mt-1">今年新增</div>
            </div>
            <div className="p-6 bg-white dark:bg-slate-800 rounded-xl border shadow-sm">
              <div className="flex items-center gap-3 mb-2">
                <div className="w-10 h-10 bg-indigo-100 dark:bg-indigo-900 rounded-lg flex items-center justify-center">
                  <Shield className="h-5 w-5 text-indigo-600 dark:text-indigo-400" />
                </div>
              </div>
              <div className="text-2xl font-bold text-indigo-600 dark:text-indigo-400">{(stats.high_severity_count || 0).toLocaleString()}</div>
              <div className="text-sm text-muted-foreground mt-1">高危以上</div>
            </div>
          </div>
        )}

        {hotVulns.length > 0 && (
          <div className="mb-8">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold flex items-center gap-2">
                <Flame className="h-5 w-5 text-orange-500" />
                热门漏洞
              </h2>
              <Link href="/search" className="text-sm text-primary hover:underline flex items-center gap-1">
                查看更多
                <ChevronRight className="h-4 w-4" />
              </Link>
            </div>
            <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-4">
              {hotVulns.map((vuln) => (
                <Link
                  key={vuln.id}
                  href={`/vuln/${vuln.id}`}
                  className="block p-4 bg-white dark:bg-slate-800 rounded-xl border hover:shadow-md transition-all hover:-translate-y-0.5"
                >
                  <div className="flex items-center gap-2 mb-2">
                    <span className={`px-2 py-0.5 text-xs rounded-full font-medium ${severityBadgeColors[vuln.severity] || "bg-gray-100 text-gray-700"}`}>
                      {severityLabels[vuln.severity] || vuln.severity}
                    </span>
                    <span className="px-2 py-0.5 bg-orange-100 text-orange-700 text-xs rounded-full font-medium">
                      热点漏洞
                    </span>
                  </div>
                  <h3 className="font-medium text-sm mb-2 line-clamp-2">{vuln.title}</h3>
                  <div className="text-xs text-muted-foreground space-y-1">
                    <div className="flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      {formatDate(vuln.published_date)}
                    </div>
                    <div className="flex items-center gap-1">
                      <Building className="h-3 w-3" />
                      {vuln.source}
                    </div>
                  </div>
                </Link>
              ))}
            </div>
          </div>
        )}

        <div className="bg-white dark:bg-slate-800 rounded-xl border shadow-sm overflow-hidden">
          <div className="p-4 border-b bg-slate-50 dark:bg-slate-700/50">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-4">
                <h2 className="text-lg font-semibold">漏洞列表</h2>
                {results && (
                  <span className="text-sm text-muted-foreground">
                    共 {results.total.toLocaleString()} 条结果
                  </span>
                )}
              </div>
              <button
                onClick={() => setShowFilters(!showFilters)}
                className="flex items-center gap-2 text-sm text-muted-foreground hover:text-primary"
              >
                <Filter className="h-4 w-4" />
                筛选
                <ChevronDown className={`h-4 w-4 transition-transform ${showFilters ? "rotate-180" : ""}`} />
              </button>
            </div>

            {showFilters && (
              <div className="mt-4 pt-4 border-t grid grid-cols-2 md:grid-cols-5 gap-4">
                <div>
                  <label className="text-sm font-medium mb-2 block">漏洞类型</label>
                  <select
                    value={vulnType}
                    onChange={(e) => {
                      setVulnType(e.target.value);
                      setPage(1);
                    }}
                    className="w-full p-2 border rounded-lg bg-background focus:outline-none focus:ring-1 focus:ring-primary"
                  >
                    <option value="all">全部</option>
                    <option value="cve">CVE漏洞</option>
                    <option value="cnvd">CNVD漏洞</option>
                    <option value="osv">OSV漏洞</option>
                    <option value="github_advisory">GitHub Advisory</option>
                  </select>
                </div>
                <div>
                  <label className="text-sm font-medium mb-2 block">严重程度</label>
                  <select
                    value={severity}
                    onChange={(e) => {
                      setSeverity(e.target.value);
                      setPage(1);
                    }}
                    className="w-full p-2 border rounded-lg bg-background focus:outline-none focus:ring-1 focus:ring-primary"
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
                    onChange={(e) => {
                      setHasExploit(e.target.value);
                      setPage(1);
                    }}
                    className="w-full p-2 border rounded-lg bg-background focus:outline-none focus:ring-1 focus:ring-primary"
                  >
                    <option value="">全部</option>
                    <option value="yes">有Exploit</option>
                    <option value="no">无Exploit</option>
                  </select>
                </div>
                <div>
                  <label className="text-sm font-medium mb-2 block">开始日期</label>
                  <input
                    type="date"
                    value={startDate}
                    onChange={(e) => {
                      setStartDate(e.target.value);
                      setPage(1);
                    }}
                    className="w-full p-2 border rounded-lg bg-background focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                </div>
                <div>
                  <label className="text-sm font-medium mb-2 block">结束日期</label>
                  <input
                    type="date"
                    value={endDate}
                    onChange={(e) => {
                      setEndDate(e.target.value);
                      setPage(1);
                    }}
                    className="w-full p-2 border rounded-lg bg-background focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                </div>
                <div className="col-span-2 md:col-span-5 flex justify-end">
                  <button
                    onClick={resetFilters}
                    className="px-4 py-2 border rounded-lg bg-muted hover:bg-muted/80 text-sm"
                  >
                    重置筛选
                  </button>
                </div>
              </div>
            )}
          </div>

          {loading ? (
            <div className="text-center py-12">
              <div className="animate-spin h-8 w-8 border-2 border-primary border-t-transparent rounded-full mx-auto"></div>
              <p className="mt-4 text-muted-foreground">搜索中...</p>
            </div>
          ) : results && results.data ? (
            <div className="divide-y divide-slate-200 dark:divide-slate-700">
              {results.data.map((vuln, index) => (
                <Link
                  key={`${vuln.type}-${vuln.id}-${index}`}
                  href={`/vuln/${vuln.id}`}
                  className="block p-4 hover:bg-slate-50 dark:hover:bg-slate-700/50 transition-colors"
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-3 mb-2">
                        <span className="font-mono font-bold text-primary">{vuln.id}</span>
                        <span className={`px-2 py-0.5 text-xs rounded-full font-medium ${
                          vuln.type === 'cve'
                            ? 'bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-300'
                            : vuln.type === 'osv'
                              ? 'bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300'
                              : vuln.type === 'github_advisory'
                                ? 'bg-orange-100 dark:bg-orange-900 text-orange-700 dark:text-orange-300'
                                : 'bg-purple-100 dark:bg-purple-900 text-purple-700 dark:text-purple-300'
                        }`}>
                          {vuln.type === 'cve' ? 'CVE' : vuln.type === 'osv' ? 'OSV' : vuln.type === 'github_advisory' ? 'GHSA' : '漏洞'}
                        </span>
                        {vuln.exploits_count > 0 && (
                          <span className="px-2 py-0.5 bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300 text-xs rounded-full font-medium flex items-center gap-1">
                            <FileCode className="h-3 w-3" />
                            {vuln.exploits_count}
                          </span>
                        )}
                      </div>
                      <h3 className="font-medium mb-2 line-clamp-2">{vuln.title || "无标题"}</h3>
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
                        <span className={`px-3 py-1.5 rounded-full text-sm font-medium ${
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
          ) : (
            <div className="text-center py-12">
              <AlertTriangle className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p className="text-muted-foreground">未找到相关漏洞</p>
            </div>
          )}

          {results && results.total > results.page_size && (
            <div className="p-4 border-t bg-slate-50 dark:bg-slate-700/50">
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div className="flex items-center gap-2">
                  <label className="text-sm text-muted-foreground">每页显示：</label>
                  <select
                    value={pageSize}
                    onChange={(e) => {
                      setPageSize(Number(e.target.value));
                      setPage(1);
                    }}
                    className="px-3 py-1.5 border rounded-lg text-sm bg-white dark:bg-slate-700 focus:outline-none focus:ring-1 focus:ring-primary"
                  >
                    <option value={10}>10条</option>
                    <option value={20}>20条</option>
                    <option value={50}>50条</option>
                    <option value={100}>100条</option>
                  </select>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setPage(page - 1)}
                    disabled={page === 1}
                    className="px-4 py-2 border rounded-lg disabled:opacity-50 hover:bg-muted transition-colors"
                  >
                    上一页
                  </button>
                  <span className="px-4 py-2 text-sm">
                    第 {page} 页 / 共 {Math.ceil(results.total / results.page_size)} 页
                  </span>
                  <button
                    onClick={() => setPage(page + 1)}
                    disabled={page >= Math.ceil(results.total / results.page_size)}
                    className="px-4 py-2 border rounded-lg disabled:opacity-50 hover:bg-muted transition-colors"
                  >
                    下一页
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}