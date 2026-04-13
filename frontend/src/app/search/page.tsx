"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Search, Filter, ChevronDown, Shield, AlertTriangle, Bug, FileCode } from "lucide-react";

interface CVE {
  id: number;
  cve_id: string;
  title: string;
  title_zh?: string;
  cvss_v3_score?: number;
  cvss_v3_severity?: string;
  cvss_v4_score?: number;
  cvss_v4_severity?: string;
  epss_score?: number;
  cisa_kev: boolean;
  published_date: string;
  exploits_count: number;
  vendor_name?: string;
  product_name?: string;
}

interface SearchResponse {
  total: number;
  page: number;
  page_size: number;
  items: CVE[];
}

const severityColors: Record<string, string> = {
  CRITICAL: "bg-red-500 text-white",
  HIGH: "bg-orange-500 text-white",
  MEDIUM: "bg-yellow-500 text-black",
  LOW: "bg-blue-500 text-white",
};

const severityLabels: Record<string, string> = {
  CRITICAL: "严重",
  HIGH: "高危",
  MEDIUM: "中危",
  LOW: "低危",
};

export default function SearchPage() {
  const searchParams = useSearchParams();
  const [query, setQuery] = useState(searchParams.get("q") || "");
  const [results, setResults] = useState<SearchResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [page, setPage] = useState(1);
  const [showFilters, setShowFilters] = useState(false);
  
  // Filters
  const [severity, setSeverity] = useState("");
  const [year, setYear] = useState("");
  const [hasExploit, setHasExploit] = useState(false);
  const [cisaKev, setCisaKev] = useState(false);

  // Fetch results function
  const doFetch = async (currentQuery: string, currentPage: number) => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (currentQuery) params.set("q", currentQuery);
      if (severity) params.set("severity", severity);
      if (year) params.set("year", year);
      if (hasExploit) params.set("has_exploit", "true");
      if (cisaKev) params.set("cisa_kev", "true");
      params.set("page", currentPage.toString());
      params.set("page_size", "20");

      // Use absolute URL for API calls in browser
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8006';
      const response = await fetch(
        `${apiUrl}/api/v1/cve/?${params.toString()}`
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

  useEffect(() => {
    doFetch(query, page);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query, page, severity, year, hasExploit, cisaKev]);

  const fetchResults = () => {
    doFetch(query, page);
  };

  const getSeverity = (cve: CVE) => {
    return cve.cvss_v3_severity || cve.cvss_v4_severity || "UNKNOWN";
  };

  const getScore = (cve: CVE) => {
    return cve.cvss_v3_score || cve.cvss_v4_score || 0;
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
              placeholder="搜索 CVE ID、厂商、产品..."
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
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
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
                  <label className="text-sm font-medium mb-2 block">年份</label>
                  <select
                    value={year}
                    onChange={(e) => setYear(e.target.value)}
                    className="w-full p-2 border rounded-lg bg-background"
                  >
                    <option value="">全部</option>
                    {[...Array(10)].map((_, i) => {
                      const y = 2025 - i;
                      return <option key={y} value={y}>{y}</option>;
                    })}
                  </select>
                </div>
                <div className="flex items-end">
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={hasExploit}
                      onChange={(e) => setHasExploit(e.target.checked)}
                      className="rounded"
                    />
                    <span className="text-sm">有Exploit</span>
                  </label>
                </div>
                <div className="flex items-end">
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={cisaKev}
                      onChange={(e) => setCisaKev(e.target.checked)}
                      className="rounded"
                    />
                    <span className="text-sm">CISA KEV</span>
                  </label>
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
          ) : results && results.items ? (
            <>
              <div className="mb-4 text-sm text-muted-foreground">
                找到 {results.total} 条结果
              </div>

              <div className="space-y-4">
                {results.items.map((cve) => (
                  <Link
                    key={cve.id}
                    href={`/vuln/${cve.cve_id}`}
                    className="block p-6 bg-white dark:bg-slate-800 rounded-xl border hover:shadow-md transition-shadow"
                  >
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-3 mb-2">
                          <span className="font-mono font-bold text-lg">{cve.cve_id}</span>
                          {cve.cisa_kev && (
                            <span className="px-2 py-0.5 bg-red-100 dark:bg-red-900 text-red-700 dark:text-red-300 text-xs rounded-full font-medium">
                              CISA KEV
                            </span>
                          )}
                          {cve.exploits_count > 0 && (
                            <span className="px-2 py-0.5 bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300 text-xs rounded-full font-medium flex items-center gap-1">
                              <FileCode className="h-3 w-3" />
                              {cve.exploits_count}
                            </span>
                          )}
                        </div>
                        <h3 className="font-medium mb-2 line-clamp-2">
                          {cve.title_zh || cve.title || "无标题"}
                        </h3>
                        <div className="flex items-center gap-4 text-sm text-muted-foreground">
                          {cve.vendor_name && <span>{cve.vendor_name}</span>}
                          {cve.product_name && <span>{cve.product_name}</span>}
                          <span>{new Date(cve.published_date).toLocaleDateString("zh-CN")}</span>
                        </div>
                      </div>
                      <div className="flex flex-col items-end gap-2">
                        {getSeverity(cve) !== "UNKNOWN" && (
                          <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                            severityColors[getSeverity(cve)] || "bg-gray-500 text-white"
                          }`}>
                            {getScore(cve).toFixed(1)} {severityLabels[getSeverity(cve)]}
                          </span>
                        )}
                        {cve.epss_score !== null && cve.epss_score !== undefined && (
                          <span className="text-sm text-muted-foreground">
                            EPSS: {(cve.epss_score * 100).toFixed(1)}%
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
          ) : null}
        </div>
      </div>
    </div>
  );
}
