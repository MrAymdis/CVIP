'use client';

import { useState, useEffect, use } from 'react';
import { useRouter } from 'next/navigation';
import { ExternalLink, Clock, Tag, Link2, ArrowLeft, Database } from 'lucide-react';

interface AffectedPackage {
  package: {
    name: string;
    ecosystem: string;
    purl?: string;
  };
  ranges?: {
    type: string;
    events: Array<{
      introduced?: string;
      fixed?: string;
    }>;
  }[];
  versions?: string[];
  database_specific?: Record<string, unknown>;
}

interface OSVDetail {
  id: number;
  osv_id: string;
  schema_version: string | null;
  published: string | null;
  modified: string | null;
  withdrawn: string | null;
  aliases: string[] | null;
  related: string[] | null;
  summary: string | null;
  details: string | null;
  affected: AffectedPackage[] | null;
  references: Array<{
    type?: string;
    url: string;
  }> | null;
  severity: Array<{
    type: string;
    score: string;
  }> | null;
  database_specific: Record<string, unknown> | null;
  created_at: string | null;
  updated_at: string | null;
}

export default function OSVDetailPage({ params }: { params: Promise<{ osv_id: string }> }) {
  const router = useRouter();
  const resolvedParams = use(params);
  const osv_id = resolvedParams?.osv_id;
  
  const [data, setData] = useState<OSVDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [notFoundError, setNotFoundError] = useState(false);
  
  if (!osv_id) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-2xl font-bold mb-2">404</h1>
          <p className="text-muted-foreground">页面未找到</p>
        </div>
      </div>
    );
  }
  
  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      setNotFoundError(false);
      try {
        const response = await fetch(`/api/v1/osv/${osv_id}`);
        if (!response.ok) {
          setNotFoundError(true);
          return;
        }
        const result = await response.json();
        setData(result);
      } catch (error) {
        console.error('Error fetching OSV data:', error);
        setNotFoundError(true);
      } finally {
        setLoading(false);
      }
    };
    
    fetchData();
  }, [osv_id]);
  
  const goBack = () => {
    router.back();
  };
  
  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="animate-spin h-8 w-8 border-2 border-primary border-t-transparent rounded-full"></div>
      </div>
    );
  }
  
  if (notFoundError || !data) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-2xl font-bold mb-2">404</h1>
          <p className="text-muted-foreground">未找到OSV漏洞信息</p>
          <button
            onClick={goBack}
            className="mt-4 px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary/90"
          >
            返回上一页
          </button>
        </div>
      </div>
    );
  }
  
  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return 'N/A';
    const date = new Date(dateStr);
    return date.toLocaleDateString('zh-CN', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const severityColors: Record<string, string> = {
    CRITICAL: 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300',
    HIGH: 'bg-orange-100 text-orange-700 dark:bg-orange-900 dark:text-orange-300',
    MEDIUM: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300',
    LOW: 'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300',
    MODERATE: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300',
    critical: 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300',
    high: 'bg-orange-100 text-orange-700 dark:bg-orange-900 dark:text-orange-300',
    medium: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300',
    low: 'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300',
    moderate: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300',
  };

  const dbSeverity = data.database_specific?.['severity'] as string | undefined;
  const dbCweIds = data.database_specific?.['cwe_ids'] as string[] | undefined;

  return (
    <div className="min-h-screen bg-background">
      <div className="max-w-6xl mx-auto px-4 py-8">
        <button
          onClick={goBack}
          className="flex items-center gap-2 text-sm text-muted-foreground hover:text-primary mb-6 transition-colors"
        >
          <ArrowLeft className="h-4 w-4" />
          返回上一页
        </button>

        <div className="mb-8">
          <div className="flex items-center gap-4 mb-4 flex-wrap">
            <span className="px-3 py-1 bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300 rounded-full text-sm font-medium">
              OSV
            </span>
            {dbSeverity && (
              <span className={`px-3 py-1 rounded-full text-sm font-medium ${severityColors[dbSeverity] || 'bg-gray-100 text-gray-700'}`}>
                {dbSeverity.toUpperCase()}
              </span>
            )}
            {data.withdrawn && (
              <span className="px-3 py-1 bg-gray-100 text-gray-700 dark:bg-gray-900 dark:text-gray-300 rounded-full text-sm font-medium">
                已撤回
              </span>
            )}
          </div>
          
          <h1 className="text-2xl font-bold mb-2">{data.summary || data.osv_id}</h1>
          <div className="flex items-center gap-2 text-muted-foreground">
            <code className="font-mono text-lg">{data.osv_id}</code>
            <span className="text-sm">来源: OSV</span>
          </div>
        </div>

        <div className="bg-card border rounded-xl p-6 mb-6">
          <h2 className="text-lg font-semibold mb-4">漏洞详情</h2>
          <p className="text-muted-foreground whitespace-pre-wrap">{data.details || '暂无详情'}</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
          <div className="bg-card border rounded-xl p-6">
            <div className="flex items-center gap-2 mb-4">
              <Clock className="h-5 w-5" />
              <h2 className="text-lg font-semibold">时间信息</h2>
            </div>
            <div className="space-y-3">
              <div className="flex justify-between">
                <span className="text-muted-foreground">发布日期</span>
                <span>{formatDate(data.published)}</span>
              </div>
              {data.modified && (
                <div className="flex justify-between">
                  <span className="text-muted-foreground">修改日期</span>
                  <span>{formatDate(data.modified)}</span>
                </div>
              )}
              {data.withdrawn && (
                <div className="flex justify-between">
                  <span className="text-muted-foreground">撤回日期</span>
                  <span className="text-red-500">{formatDate(data.withdrawn)}</span>
                </div>
              )}
            </div>
          </div>

          <div className="bg-card border rounded-xl p-6">
            <div className="flex items-center gap-2 mb-4">
              <Database className="h-5 w-5" />
              <h2 className="text-lg font-semibold">元数据</h2>
            </div>
            <div className="space-y-3">
              {data.schema_version && (
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Schema版本</span>
                  <span>{data.schema_version}</span>
                </div>
              )}
              {data.aliases && data.aliases.length > 0 && (
                <div>
                  <span className="text-muted-foreground block mb-2">别名 (Aliases)</span>
                  <div className="flex flex-wrap gap-2">
                    {data.aliases.map((alias, index) => (
                      <span 
                        key={index}
                        className="px-2 py-1 bg-muted rounded text-sm"
                      >
                        {alias}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {dbCweIds && dbCweIds.length > 0 && (
                <div>
                  <span className="text-muted-foreground block mb-2">CWE IDs</span>
                  <div className="flex flex-wrap gap-2">
                    {dbCweIds.map((cwe, index) => (
                      <span 
                        key={index}
                        className="px-2 py-1 bg-muted rounded text-sm"
                      >
                        {cwe}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        {data.related && data.related.length > 0 && (
          <div className="bg-card border rounded-xl p-6 mb-6">
            <div className="flex items-center gap-2 mb-4">
              <Tag className="h-5 w-5" />
              <h2 className="text-lg font-semibold">相关漏洞</h2>
            </div>
            <div className="flex flex-wrap gap-2">
              {data.related.map((related_id, index) => (
                <span 
                  key={index}
                  className="px-2 py-1 bg-muted rounded text-sm"
                >
                  {related_id}
                </span>
              ))}
            </div>
          </div>
        )}

        {data.severity && data.severity.length > 0 && (
          <div className="bg-card border rounded-xl p-6 mb-6">
            <h2 className="text-lg font-semibold mb-4">严重程度</h2>
            <div className="space-y-3">
              {data.severity.map((sev, index) => (
                <div key={index} className="flex justify-between items-center">
                  <span className="text-muted-foreground">{sev.type}</span>
                  <span className="font-medium">{sev.score}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {data.affected && data.affected.length > 0 && (
          <div className="bg-card border rounded-xl p-6 mb-6">
            <h2 className="text-lg font-semibold mb-4">受影响的包</h2>
            <div className="space-y-4">
              {data.affected.map((pkg, index) => (
                <div key={index} className="border-t pt-4 first:border-t-0">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="font-medium">{pkg.package.name}</span>
                    <span className="px-2 py-0.5 bg-muted rounded text-xs">{pkg.package.ecosystem}</span>
                  </div>
                  {pkg.package.purl && (
                    <div className="text-sm text-muted-foreground mb-2">
                      <code>{pkg.package.purl}</code>
                    </div>
                  )}
                  {pkg.versions && pkg.versions.length > 0 && (
                    <div>
                      <span className="text-sm text-muted-foreground block mb-1">受影响版本:</span>
                      <div className="flex flex-wrap gap-2">
                        {pkg.versions.slice(0, 10).map((version, vIndex) => (
                          <span key={vIndex} className="px-2 py-1 bg-muted rounded text-sm">
                            {version}
                          </span>
                        ))}
                        {pkg.versions.length > 10 && (
                          <span className="px-2 py-1 bg-muted rounded text-sm text-muted-foreground">
                            +{pkg.versions.length - 10} more
                          </span>
                        )}
                      </div>
                    </div>
                  )}
                  {pkg.ranges && pkg.ranges.length > 0 && (
                    <div className="mt-2">
                      <span className="text-sm text-muted-foreground block mb-1">版本范围:</span>
                      <div className="space-y-1">
                        {pkg.ranges.map((range, rIndex) => (
                          <div key={rIndex} className="text-sm">
                            {range.events.map((event, eIndex) => (
                              <span key={eIndex} className="mr-2">
                                {event.introduced && `引入: ${event.introduced}`}
                                {event.fixed && `修复: ${event.fixed}`}
                              </span>
                            ))}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {data.references && data.references.length > 0 && (
          <div className="bg-card border rounded-xl p-6">
            <div className="flex items-center gap-2 mb-4">
              <Link2 className="h-5 w-5" />
              <h2 className="text-lg font-semibold">参考链接</h2>
            </div>
            <ul className="space-y-2">
              {data.references.map((ref, index) => (
                <li key={index} className="flex items-center gap-2">
                  <ExternalLink className="h-4 w-4 text-muted-foreground" />
                  <a
                    href={ref.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-primary hover:underline break-all"
                  >
                    {ref.type && <span className="text-muted-foreground mr-2">[{ref.type}]</span>}
                    {ref.url}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}