"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { Shield, Database, Bug, TrendingUp, AlertTriangle } from "lucide-react";

interface StatsOverview {
  total_cves: number;
  total_exploits: number;
  total_vendors: number;
  total_products: number;
  cves_this_year: number;
  exploits_this_year: number;
  cisa_kev_count: number;
  high_severity_count: number;
}

interface TrendData {
  date: string;
  count: number;
}

interface VendorRank {
  name: string;
  cve_count: number;
  exploited_count: number;
}

interface CWERank {
  cwe_id: string;
  name?: string;
  cve_count: number;
}

export default function StatsPage() {
  const [overview, setOverview] = useState<StatsOverview | null>(null);
  const [trends, setTrends] = useState<TrendData[]>([]);
  const [vendors, setVendors] = useState<VendorRank[]>([]);
  const [cwes, setCwes] = useState<CWERank[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchStats();
  }, []);

  const fetchStats = async () => {
    setLoading(true);
    try {
      const [overviewRes, trendsRes, vendorsRes, cwesRes] = await Promise.all([
        fetch(`/api/v1/stats/overview`),
        fetch(`/api/v1/stats/trends?months=12`),
        fetch(`/api/v1/stats/vendors?limit=10`),
        fetch(`/api/v1/stats/cwes?limit=10`),
      ]);

      const overviewData = await overviewRes.json();
      const trendsData = await trendsRes.json();
      const vendorsData = await vendorsRes.json();
      const cwesData = await cwesRes.json();

      setOverview(overviewData);
      setTrends(trendsData);
      setVendors(vendorsData);
      setCwes(cwesData);
    } catch (error) {
      console.error("Stats fetch error:", error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-50 dark:bg-slate-900 flex items-center justify-center">
        <div className="animate-spin h-8 w-8 border-2 border-primary border-t-transparent rounded-full"></div>
      </div>
    );
  }

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
            <Link href="/search" className="text-sm font-medium hover:text-primary">
              搜索
            </Link>
            <Link href="/stats" className="text-sm font-medium text-primary">
              统计
            </Link>
          </nav>
        </div>
      </header>

      <div className="container mx-auto px-4 py-8">
        <h1 className="text-3xl font-bold mb-8">平台统计</h1>

        {/* Overview Cards */}
        {overview && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
            <div className="p-6 bg-white dark:bg-slate-800 rounded-xl border">
              <Database className="h-8 w-8 text-primary mb-2" />
              <div className="text-2xl font-bold">{overview.total_cves.toLocaleString()}</div>
              <div className="text-sm text-muted-foreground">总 CVE 数</div>
            </div>
            <div className="p-6 bg-white dark:bg-slate-800 rounded-xl border">
              <Bug className="h-8 w-8 text-green-500 mb-2" />
              <div className="text-2xl font-bold">{overview.total_exploits.toLocaleString()}</div>
              <div className="text-sm text-muted-foreground">总 Exploit 数</div>
            </div>
            <div className="p-6 bg-white dark:bg-slate-800 rounded-xl border">
              <AlertTriangle className="h-8 w-8 text-red-500 mb-2" />
              <div className="text-2xl font-bold">{overview.cisa_kev_count.toLocaleString()}</div>
              <div className="text-sm text-muted-foreground">CISA KEV</div>
            </div>
            <div className="p-6 bg-white dark:bg-slate-800 rounded-xl border">
              <TrendingUp className="h-8 w-8 text-orange-500 mb-2" />
              <div className="text-2xl font-bold">{overview.high_severity_count.toLocaleString()}</div>
              <div className="text-sm text-muted-foreground">高危漏洞</div>
            </div>
          </div>
        )}

        <div className="grid md:grid-cols-2 gap-8">
          {/* Trends */}
          <div className="p-6 bg-white dark:bg-slate-800 rounded-xl border">
            <h2 className="text-lg font-semibold mb-4">CVE 月度趋势</h2>
            <div className="h-64 flex items-end gap-1">
              {trends.map((trend, index) => {
                const maxCount = Math.max(...trends.map(t => t.count), 1);
                const height = (trend.count / maxCount) * 100;
                return (
                  <div
                    key={trend.date}
                    className="flex-1 bg-primary/20 hover:bg-primary/40 rounded-t transition-colors relative group"
                    style={{ height: `${height}%` }}
                  >
                    <div className="absolute -top-8 left-1/2 -translate-x-1/2 bg-foreground text-background text-xs px-2 py-1 rounded opacity-0 group-hover:opacity-100 whitespace-nowrap">
                      {trend.date}: {trend.count}
                    </div>
                  </div>
                );
              })}
            </div>
            <div className="flex justify-between mt-2 text-xs text-muted-foreground">
              <span>{trends[0]?.date}</span>
              <span>{trends[trends.length - 1]?.date}</span>
            </div>
          </div>

          {/* Top Vendors */}
          <div className="p-6 bg-white dark:bg-slate-800 rounded-xl border">
            <h2 className="text-lg font-semibold mb-4">受影响厂商 Top 10</h2>
            <div className="space-y-3">
              {vendors.map((vendor, index) => (
                <div key={vendor.name} className="flex items-center gap-3">
                  <span className="w-6 text-sm text-muted-foreground">{index + 1}</span>
                  <div className="flex-1">
                    <div className="flex justify-between mb-1">
                      <span className="font-medium">{vendor.name}</span>
                      <span className="text-sm text-muted-foreground">{vendor.cve_count} CVE</span>
                    </div>
                    <div className="h-2 bg-muted rounded-full overflow-hidden">
                      <div
                        className="h-full bg-primary rounded-full"
                        style={{
                          width: `${(vendor.cve_count / (vendors[0]?.cve_count || 1)) * 100}%`,
                        }}
                      />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Top CWEs */}
          <div className="p-6 bg-white dark:bg-slate-800 rounded-xl border md:col-span-2">
            <h2 className="text-lg font-semibold mb-4">常见 CWE Top 10</h2>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
              {cwes.map((cwe, index) => (
                <div
                  key={cwe.cwe_id}
                  className="p-4 bg-muted rounded-lg"
                >
                  <div className="text-2xl font-bold text-primary mb-1">{index + 1}</div>
                  <div className="font-mono text-sm mb-1">{cwe.cwe_id}</div>
                  <div className="text-xs text-muted-foreground truncate">
                    {cwe.name || "Unknown"}
                  </div>
                  <div className="text-sm font-medium mt-2">{cwe.cve_count} CVE</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
