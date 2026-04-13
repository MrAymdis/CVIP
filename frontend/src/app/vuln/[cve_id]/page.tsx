"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { Shield, ArrowLeft, FileCode, ExternalLink, AlertTriangle } from "lucide-react";

interface Exploit {
  id: number;
  source: string;
  source_url?: string;
  title?: string;
  code?: string;
  language?: string;
  verified: boolean;
  reliability_score?: number;
  github_stars?: number;
}

interface Reference {
  id: number;
  cve_id: string;
  url: string;
  title?: string;
  ref_type?: string;
  source?: string;
  tags?: string[];
}

interface AffectedVersion {
  vendor?: string;
  product?: string;
  versions: Array<{
    version?: string;
    status?: string;
  }>;
}

interface CVE {
  id: number;
  cve_id: string;
  title?: string;
  title_zh?: string;
  description?: string;
  description_zh?: string;
  cvss_v3_score?: number;
  cvss_v3_severity?: string;
  cvss_v4_score?: number;
  cvss_v4_severity?: string;
  epss_score?: number;
  epss_percentile?: number;
  cisa_kev: boolean;
  published_date: string;
  modified_date?: string;
  cwes?: string[];
  vendor_name?: string;
  product_name?: string;
  affected_versions?: AffectedVersion[];
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

export default function CVEDetailPage() {
  const params = useParams();
  const cveId = params.cve_id as string;
  
  const [cve, setCve] = useState<CVE | null>(null);
  const [exploits, setExploits] = useState<Exploit[]>([]);
  const [references, setReferences] = useState<Reference[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<"info" | "exploits" | "references">("info");

  useEffect(() => {
    fetchCVE();
  }, [cveId]);

  const fetchCVE = async () => {
    setLoading(true);
    try {
      const [cveRes, exploitsRes, referencesRes] = await Promise.all([
        fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/v1/cve/${cveId}`),
        fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/v1/cve/${cveId}/exploits`),
        fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/v1/cve/${cveId}/references`),
      ]);
      
      const cveData = await cveRes.json();
      const exploitsData = await exploitsRes.json();
      const referencesData = await referencesRes.json();
      
      setCve(cveData);
      setExploits(exploitsData);
      setReferences(referencesData);
    } catch (error) {
      console.error("Fetch error:", error);
    } finally {
      setLoading(false);
    }
  };

  const getSeverity = () => {
    return cve?.cvss_v3_severity || cve?.cvss_v4_severity || "UNKNOWN";
  };

  const getScore = () => {
    return cve?.cvss_v3_score || cve?.cvss_v4_score || 0;
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-50 dark:bg-slate-900 flex items-center justify-center">
        <div className="animate-spin h-8 w-8 border-2 border-primary border-t-transparent rounded-full"></div>
      </div>
    );
  }

  if (!cve) {
    return (
      <div className="min-h-screen bg-slate-50 dark:bg-slate-900 flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-2xl font-bold mb-2">CVE 未找到</h1>
          <Link href="/search" className="text-primary hover:underline">
            返回搜索
          </Link>
        </div>
      </div>
    );
  }

  const renderTabContent = () => {
    if (activeTab === "info") {
      return (
        <div className="space-y-6">
          <div className="p-6 bg-white dark:bg-slate-800 rounded-xl border">
            <h3 className="font-semibold mb-3">漏洞描述</h3>
            <p className="text-muted-foreground leading-relaxed">
              {cve.description_zh || cve.description || "暂无描述"}
            </p>
          </div>

          <div className="p-6 bg-white dark:bg-slate-800 rounded-xl border">
            <h3 className="font-semibold mb-4">详细信息</h3>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <span className="text-sm text-muted-foreground">厂商</span>
                <p className="font-medium">{cve.vendor_name || "未知"}</p>
              </div>
              <div>
                <span className="text-sm text-muted-foreground">产品</span>
                <p className="font-medium">{cve.product_name || "未知"}</p>
              </div>
              <div>
                <span className="text-sm text-muted-foreground">发布日期</span>
                <p className="font-medium">
                  {new Date(cve.published_date).toLocaleDateString("zh-CN")}
                </p>
              </div>
              <div>
                <span className="text-sm text-muted-foreground">修改日期</span>
                <p className="font-medium">
                  {cve.modified_date
                    ? new Date(cve.modified_date).toLocaleDateString("zh-CN")
                    : "-"}
                </p>
              </div>
              {cve.cwes && cve.cwes.length > 0 && (
                <div className="col-span-2">
                  <span className="text-sm text-muted-foreground">CWE</span>
                  <div className="flex flex-wrap gap-2 mt-1">
                    {cve.cwes.map((cwe) => (
                      <span
                        key={cwe}
                        className="px-2 py-1 bg-muted rounded text-sm font-mono"
                      >
                        {cwe}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>

          {cve.affected_versions && cve.affected_versions.length > 0 && (
            <div className="p-6 bg-white dark:bg-slate-800 rounded-xl border">
              <h3 className="font-semibold mb-4">受影响版本</h3>
              <div className="space-y-4">
                {cve.affected_versions.map((affected, index) => (
                  <div key={index} className="p-4 bg-slate-50 dark:bg-slate-900 rounded-lg">
                    {affected.vendor && (
                      <div className="mb-2">
                        <span className="text-sm text-muted-foreground">厂商：</span>
                        <span className="font-medium">{affected.vendor}</span>
                      </div>
                    )}
                    {affected.product && (
                      <div className="mb-2">
                        <span className="text-sm text-muted-foreground">产品：</span>
                        <span className="font-medium">{affected.product}</span>
                      </div>
                    )}
                    {affected.versions && affected.versions.length > 0 && (
                      <div>
                        <span className="text-sm text-muted-foreground">版本：</span>
                        <div className="flex flex-wrap gap-2 mt-1">
                          {affected.versions.map((v, vIndex) => (
                            <span
                              key={vIndex}
                              className={`px-2 py-1 rounded text-sm font-mono ${
                                v.status === 'affected'
                                  ? 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300'
                                  : 'bg-muted'
                              }`}
                            >
                              {v.version || v.status}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      );
    }

    if (activeTab === "exploits") {
      return (
        <div className="space-y-4">
          {exploits.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">
              <FileCode className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>暂无 Exploit 数据</p>
            </div>
          ) : (
            exploits.map((exploit) => (
              <div
                key={exploit.id}
                className="p-6 bg-white dark:bg-slate-800 rounded-xl border"
              >
                <div className="flex items-start justify-between mb-4">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-medium">{exploit.source}</span>
                      {exploit.verified && (
                        <span className="px-2 py-0.5 bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300 text-xs rounded-full">
                          已验证
                        </span>
                      )}
                    </div>
                    {exploit.title && (
                      <p className="text-sm text-muted-foreground">{exploit.title}</p>
                    )}
                  </div>
                  {exploit.source_url && (
                    <a
                      href={exploit.source_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-1 text-sm text-primary hover:underline"
                    >
                      查看来源
                      <ExternalLink className="h-4 w-4" />
                    </a>
                  )}
                </div>
                
                {exploit.code && (
                  <pre className="p-4 bg-slate-100 dark:bg-slate-900 rounded-lg overflow-x-auto text-sm">
                    <code>{exploit.code.slice(0, 500)}{exploit.code.length > 500 ? "..." : ""}</code>
                  </pre>
                )}
                
                <div className="flex items-center gap-4 mt-4 text-sm text-muted-foreground">
                  {exploit.language && <span>语言: {exploit.language}</span>}
                  {exploit.reliability_score !== null && exploit.reliability_score !== undefined && (
                    <span>可靠性: {exploit.reliability_score.toFixed(1)}/10</span>
                  )}
                  {exploit.github_stars !== null && exploit.github_stars !== undefined && (
                    <span>⭐ {exploit.github_stars}</span>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      );
    }

    if (activeTab === "references") {
      return (
        <div className="space-y-4">
          {references.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">
              <ExternalLink className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>暂无参考链接</p>
            </div>
          ) : (
            references.map((ref) => (
              <div
                key={ref.id}
                className="p-6 bg-white dark:bg-slate-800 rounded-xl border"
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    {ref.title && (
                      <h4 className="font-medium mb-2 truncate">{ref.title}</h4>
                    )}
                    <a
                      href={ref.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-primary hover:underline truncate block text-sm"
                    >
                      {ref.url}
                    </a>
                  </div>
                  <a
                    href={ref.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1 text-sm text-muted-foreground hover:text-primary shrink-0"
                  >
                    <ExternalLink className="h-4 w-4" />
                  </a>
                </div>
                
                {(ref.tags && ref.tags.length > 0) || ref.source ? (
                  <div className="flex flex-wrap gap-2 mt-4">
                    {ref.source && (
                      <span className="px-2 py-1 bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300 rounded text-xs">
                        {ref.source}
                      </span>
                    )}
                    {ref.tags && ref.tags.map((tag, index) => (
                      <span
                        key={index}
                        className="px-2 py-1 bg-muted rounded text-xs"
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                ) : null}
              </div>
            ))
          )}
        </div>
      );
    }

    return null;
  };

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-900">
      <header className="border-b bg-white dark:bg-slate-950 sticky top-0 z-10">
        <div className="container mx-auto px-4 h-16 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Link href="/search" className="flex items-center gap-2 text-muted-foreground hover:text-primary">
              <ArrowLeft className="h-5 w-5" />
              返回
            </Link>
            <Link href="/" className="flex items-center gap-2">
              <Shield className="h-8 w-8 text-primary" />
              <span className="text-xl font-bold">漏洞情报平台</span>
            </Link>
          </div>
        </div>
      </header>

      <div className="container mx-auto px-4 py-8">
        <div className="max-w-4xl mx-auto">
          <div className="mb-8">
            <div className="flex items-center gap-4 mb-4">
              <h1 className="text-3xl font-bold font-mono">{cve.cve_id}</h1>
              {cve.cisa_kev && (
                <span className="px-3 py-1 bg-red-100 dark:bg-red-900 text-red-700 dark:text-red-300 rounded-full font-medium flex items-center gap-1">
                  <AlertTriangle className="h-4 w-4" />
                  CISA KEV
                </span>
              )}
            </div>
            
            <h2 className="text-xl text-muted-foreground mb-4">
              {cve.title_zh || cve.title || "无标题"}
            </h2>

            <div className="flex flex-wrap gap-4">
              {getSeverity() !== "UNKNOWN" && (
                <div className={`px-4 py-2 rounded-lg ${severityColors[getSeverity()]}`}>
                  <div className="text-sm opacity-90">CVSS {getScore().toFixed(1)}</div>
                  <div className="font-bold">{severityLabels[getSeverity()]}</div>
                </div>
              )}
              
              {cve.epss_score !== undefined && cve.epss_score !== null && (
                <div className="px-4 py-2 bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-300 rounded-lg">
                  <div className="text-sm opacity-90">EPSS</div>
                  <div className="font-bold">{(cve.epss_score * 100).toFixed(1)}%</div>
                </div>
              )}

              {exploits.length > 0 && (
                <div className="px-4 py-2 bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300 rounded-lg">
                  <div className="text-sm opacity-90">Exploit</div>
                  <div className="font-bold">{exploits.length} 个</div>
                </div>
              )}
            </div>
          </div>

          <div className="flex gap-4 border-b mb-6">
            <button
              onClick={() => setActiveTab("info")}
              className={`pb-2 px-1 font-medium ${
                activeTab === "info"
                  ? "text-primary border-b-2 border-primary"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              基本信息
            </button>
            <button
              onClick={() => setActiveTab("exploits")}
              className={`pb-2 px-1 font-medium ${
                activeTab === "exploits"
                  ? "text-primary border-b-2 border-primary"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              Exploit ({exploits.length})
            </button>
            <button
              onClick={() => setActiveTab("references")}
              className={`pb-2 px-1 font-medium ${
                activeTab === "references"
                  ? "text-primary border-b-2 border-primary"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              参考链接 ({references.length})
            </button>
          </div>

          {renderTabContent()}
        </div>
      </div>
    </div>
  );
}
