"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Search, Filter, ChevronDown, Shield, AlertTriangle, Bug, FileCode, Flame, Clock, Building, ChevronRight } from "lucide-react";

function useDebounce<T>(value: T, delay: number): T {
  const [debouncedValue, setDebouncedValue] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedValue(value), delay);
    return () => clearTimeout(timer);
  }, [value, delay]);
  return debouncedValue;
}

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
  total_vulns: number;
  total_exploits: number;
  total_vendors: number;
  total_products: number;
  total_github_advisory: number;
  cves_this_year: number;
  exploits_this_year: number;
  cisa_kev_count: number;
  high_severity_count: number;
  published_today: number;
  updated_today: number;
}

interface HotVulnerability {
  id: string;
  type: string;
  title: string;
  severity: string;
  published_date: string;
  source: string;
  view_count: number;
  exploits_count: number;
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

// 缓存数据类型
interface CacheData {
  results: SearchResponse | null;
  stats: StatsResponse;
  hotVulns: HotVulnerability[];
  timestamp: number;
}

// 缓存有效期（5分钟）
const CACHE_TTL = 5 * 60 * 1000;
const CACHE_KEY = 'search_page_cache';

export default function SearchPage() {
  const searchParams = useSearchParams();
  const [query, setQuery] = useState(searchParams.get("q") || "");
  const [results, setResults] = useState<SearchResponse | null>(null);
  const [stats, setStats] = useState<StatsResponse>({
    total_vulns: 0,
    total_exploits: 0,
    total_vendors: 0,
    total_products: 0,
    total_github_advisory: 0,
    cves_this_year: 0,
    exploits_this_year: 0,
    cisa_kev_count: 0,
    high_severity_count: 0,
    published_today: 0,
    updated_today: 0,
  });
  const [hotVulns, setHotVulns] = useState<HotVulnerability[]>([]);
  const [loading, setLoading] = useState(false);
  const [isInitialized, setIsInitialized] = useState(false);
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

  const apiUrl = '/api';

  // 从缓存读取数据
  const loadFromCache = () => {
    if (typeof window === 'undefined') return false;
    try {
      const cached = localStorage.getItem(CACHE_KEY);
      if (cached) {
        const data: CacheData = JSON.parse(cached);
        if (Date.now() - data.timestamp < CACHE_TTL) {
          setResults(data.results);
          setStats(data.stats);
          setHotVulns(data.hotVulns);
          console.log("Loaded from cache");
          return true;
        }
      }
    } catch (e) {
      console.error("Failed to load from cache:", e);
    }
    return false;
  };

  // 保存到缓存
  const saveToCache = (
    resultsData: SearchResponse | null,
    statsData: StatsResponse,
    hotVulnsData: HotVulnerability[]
  ) => {
    if (typeof window === 'undefined') return;
    try {
      const data: CacheData = {
        results: resultsData,
        stats: statsData,
        hotVulns: hotVulnsData,
        timestamp: Date.now()
      };
      localStorage.setItem(CACHE_KEY, JSON.stringify(data));
    } catch (e) {
      console.error("Failed to save to cache:", e);
    }
  };

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
      saveToCache(data, stats, hotVulns);
    } catch (error) {
      console.error("Search error:", error);
      setResults(null);
    } finally {
      setLoading(false);
    }
  };

  const fetchAllData = async () => {
    setLoading(true);
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10000);

      const [statsResponse, hotResponse, searchResponse] = await Promise.all([
        fetch(`/api/v1/stats/overview`, { signal: controller.signal }),
        fetch(`/api/v1/search/top-viewed?limit=10`, { signal: controller.signal }),
        fetch(`/api/v1/search?page=1&page_size=10`, { signal: controller.signal })
      ]);

      clearTimeout(timeout);

      let newStats = stats;
      let newHotVulns = hotVulns;
      let newResults = results;

      if (statsResponse.ok) {
        try {
          const data = await statsResponse.json();
          newStats = data;
          setStats(data);
        } catch (e) {
          console.error("Failed to parse stats JSON:", e);
        }
      } else {
        console.error(`Stats API error: ${statsResponse.status}`);
      }

      if (hotResponse.ok) {
        try {
          const hotData = await hotResponse.json();
          if (Array.isArray(hotData)) {
            const hotItems: HotVulnerability[] = hotData.map((v: any) => ({
              id: v.id,
              type: v.type || "",
              title: v.title || "",
              severity: v.severity || "",
              published_date: v.published_date || "",
              source: v.source || "",
              view_count: v.view_count || 0,
              exploits_count: v.exploits_count || 0,
            }));
            newHotVulns = hotItems;
            setHotVulns(hotItems);
          }
        } catch (e) {
          console.error("Failed to parse hot vulns JSON:", e);
        }
      } else {
        console.error(`Hot vulns API error: ${hotResponse.status}`);
      }

      if (searchResponse.ok) {
        try {
          const data = await searchResponse.json();
          newResults = data;
          setResults(data);
        } catch (e) {
          console.error("Failed to parse search JSON:", e);
        }
      } else {
        console.error(`Search API error: ${searchResponse.status}`);
      }

      saveToCache(newResults, newStats, newHotVulns);
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') {
        console.warn("Fetch timed out");
      } else {
        console.error("Fetch error:", error);
      }
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
    // 只在首次初始化时执行一次
    if (!isInitialized) {
      setIsInitialized(true);
      const loadedFromCache = loadFromCache();
      
      // 如果从缓存加载成功，不需要重新请求
      if (loadedFromCache) {
        return;
      }
      
      // 缓存不可用，从服务器获取所有数据
      fetchAllData();
      return;
    }
    
    // 只有在不是默认状态时才重新搜索
    const isDefaultState = 
      !severity && 
      vulnType === 'all' && 
      !hasExploit && 
      !startDate && 
      !endDate && 
      !query && 
      page === 1;
      
    if (isDefaultState) {
      return;
    }
    
    // 正常执行搜索
    doFetch(query, page);
  }, [query, page, pageSize, severity, vulnType, hasExploit, startDate, endDate, isInitialized]);

  const fetchResults = () => {
    doFetch(query, page);
  };

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return 'N/A';
    return new Date(dateStr).toLocaleDateString("zh-CN");
  };

  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800">
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

        {/* 统计卡片 - 无需loading，直接显示 */}
        <div className="grid grid-cols-2 md:grid-cols-6 gap-4 mb-8">
          {stats ? (
            <>
              <div className="p-6 bg-white dark:bg-slate-800 rounded-xl border shadow-sm">
                <div className="flex items-center gap-3 mb-2">
                  <div className="w-10 h-10 bg-blue-100 dark:bg-blue-900 rounded-lg flex items-center justify-center">
                    <Bug className="h-5 w-5 text-blue-600 dark:text-blue-400" />
                  </div>
                </div>
                <div className="text-2xl font-bold text-blue-600 dark:text-blue-400">{(stats.total_vulns || 0).toLocaleString()}</div>
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
                  <div className="w-10 h-10 bg-green-100 dark:bg-green-900 rounded-lg flex items-center justify-center">
                    <FileCode className="h-5 w-5 text-green-600 dark:text-green-400" />
                  </div>
                </div>
                <div className="text-2xl font-bold text-green-600 dark:text-green-400">{(stats.total_exploits || 0).toLocaleString()}</div>
                <div className="text-sm text-muted-foreground mt-1">ExPloits总数</div>
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
                  <div className="w-10 h-10 bg-purple-100 dark:bg-purple-900 rounded-lg flex items-center justify-center">
                    <Clock className="h-5 w-5 text-purple-600 dark:text-purple-400" />
                  </div>
                </div>
                <div className="text-2xl font-bold text-purple-600 dark:text-purple-400">{(stats.published_today || 0).toLocaleString()}</div>
                <div className="text-sm text-muted-foreground mt-1">今日发布</div>
              </div>
              <div className="p-6 bg-white dark:bg-slate-800 rounded-xl border shadow-sm">
                <div className="flex items-center gap-3 mb-2">
                  <div className="w-10 h-10 bg-indigo-100 dark:bg-indigo-900 rounded-lg flex items-center justify-center">
                    <Shield className="h-5 w-5 text-indigo-600 dark:text-indigo-400" />
                  </div>
                </div>
                <div className="text-2xl font-bold text-indigo-600 dark:text-indigo-400">{(stats.updated_today || 0).toLocaleString()}</div>
                <div className="text-sm text-muted-foreground mt-1">今日更新</div>
              </div>
            </>
          ) : null}
        </div>

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
            <div className="relative overflow-hidden">
              {hotVulns.length > 0 ? (
                <div className="flex gap-4 animate-marquee">
                  {[...hotVulns, ...hotVulns].map((vuln, idx) => (
                    <Link
                      key={`${vuln.id}-${idx}`}
                      href={`/vuln/${vuln.id}`}
                      className="block p-4 bg-white dark:bg-slate-800 rounded-xl border hover:shadow-md transition-all hover:-translate-y-0.5 w-64 shrink-0"
                    >
                      <div className="flex items-center gap-2 mb-2">
                        <span className={`px-2 py-0.5 text-xs rounded-full font-medium ${severityBadgeColors[vuln.severity] || "bg-gray-100 text-gray-700"}`}>
                          {severityLabels[vuln.severity] || vuln.severity}
                        </span>
                        <span className="px-2 py-0.5 bg-orange-100 text-orange-700 text-xs rounded-full font-medium flex items-center gap-1">
                          <Flame className="h-3 w-3" />
                          {vuln.view_count}
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
              ) : (
                <div className="flex gap-4">
                  {[...Array(4)].map((_, i) => (
                    <div key={i} className="w-64 shrink-0 p-4 bg-white dark:bg-slate-800 rounded-xl border shadow-sm animate-pulse">
                      <div className="flex items-center gap-2 mb-2">
                        <div className="w-16 h-5 bg-slate-200 dark:bg-slate-700 rounded"></div>
                        <div className="w-16 h-5 bg-slate-200 dark:bg-slate-700 rounded"></div>
                      </div>
                      <div className="h-4 bg-slate-200 dark:bg-slate-700 rounded mb-2"></div>
                      <div className="h-4 w-2/3 bg-slate-200 dark:bg-slate-700 rounded mb-4"></div>
                      <div className="h-3 w-1/2 bg-slate-200 dark:bg-slate-700 rounded"></div>
                    </div>
                  ))}
                </div>
              )}
            </div>
            <style jsx>{`
              @keyframes marquee {
                0% { transform: translateX(0); }
                100% { transform: translateX(-50%); }
              }
              .animate-marquee {
                animation: marquee 20s linear infinite;
              }
              .animate-marquee:hover {
                animation-play-state: paused;
              }
            `}</style>
          </div>

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
                  <label className="text-sm font-medium mb-2 block">漏洞源</label>
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