'use client';

import { useState, useEffect } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { ExternalLink, Clock, AlertTriangle, Tag, Link2, Shield, FileCode, ArrowLeft } from 'lucide-react';

interface AffectedVersion {
  vendor: string;
  product: string;
  versions: { version: string; status: string }[];
}

interface VulnerabilityDetail {
  vuln_id: string;
  title: string;
  description: string;
  source: string;
  severity: string;
  cvss_v3_score: number | null;
  cvss_v3_severity: string | null;
  cvss_v4_score: number | null;
  cvss_v4_severity: string | null;
  published_date: string | null;
  modified_date: string | null;
  cwe_ids: string[] | null;
  related_cve_ids: string[] | null;
  references: { url: string }[] | null;
  tags: string[] | null;
  data_sources: string[] | null;
  affected_versions: AffectedVersion[] | null;
  exploits_count: number | null;
  vendor_name: string | null;
  product_name: string | null;
}

interface CVEReference {
  id: number;
  url: string;
  title: string;
  source: string;
  tags: string[];
}

interface Exploit {
  id: number;
  cve_id: string;
  source: string;
  source_id: string;
  source_url: string;
  title: string;
  code: string | null;
  language: string | null;
  author: string | null;
  platform: string | null;
  exploit_type: string | null;
  verified: boolean;
  reliability_score: number | null;
  published_date: string | null;
}

interface Component {
  id: number;
  name: string;
  component_id: string;
  vendor_name: string | null;
  category: string;
  product_version: string | null;
  ecosystem: string | null;
  vuln_count: number;
}

function parseCVSSVector(vector: string): { score: number; severity: string; version: string } | null {
  try {
    const match = vector.match(/^CVSS:(\d+\.\d+)\/(.*)$/);
    if (!match) return null;
    
    const version = match[1];
    const metrics = match[2].split('/');
    const metricMap: Record<string, string> = {};
    
    metrics.forEach(m => {
      const [key, value] = m.split(':');
      metricMap[key] = value;
    });
    
    const versionNum = parseFloat(version);
    let baseScore: number;
    
    if (versionNum >= 4.0) {
      const avMap: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.20 };
      const acMap: Record<string, number> = { L: 0.77, H: 0.44 };
      const prMap: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
      const uiMap: Record<string, number> = { N: 0.85, R: 0.62 };
      const maMap: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.20, X: 0.85 };
      const crMap: Record<string, number> = { H: 0.56, L: 0.22, N: 0.00, X: 0.22 };
      const irMap: Record<string, number> = { H: 0.56, L: 0.22, N: 0.00, X: 0.22 };
      const arMap: Record<string, number> = { H: 0.56, L: 0.22, N: 0.00, X: 0.22 };
      
      const av = avMap[metricMap['AV']] || 0;
      const ac = acMap[metricMap['AC']] || 0;
      const pr = prMap[metricMap['PR']] || 0;
      const ui = uiMap[metricMap['UI']] || 0;
      const ma = maMap[metricMap['MA'] || 'X'] || 0.85;
      const cr = crMap[metricMap['CR'] || 'X'] || 0.22;
      const ir = irMap[metricMap['IR'] || 'X'] || 0.22;
      const ar = arMap[metricMap['AR'] || 'X'] || 0.22;
      
      const exploitabilityScore = 8.22 * av * ac * pr * ui;
      const modifiedExploitabilityScore = 8.22 * ma * ac * pr * ui;
      const impactScore = 1.0 * (1 - (1 - cr) * (1 - ir) * (1 - ar));
      
      const adjustedImpactScore = Math.min(7.52 * impactScore - 3.25 * Math.pow(impactScore, 15), 6.42);
      
      if (metricMap['S'] === 'C') {
        baseScore = Math.round((modifiedExploitabilityScore + adjustedImpactScore) * 10) / 10;
      } else {
        baseScore = Math.round((exploitabilityScore + adjustedImpactScore) * 10) / 10;
      }
    } else {
      const avMap: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.20 };
      const acMap: Record<string, number> = { L: 0.77, H: 0.44 };
      const prMap: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
      const uiMap: Record<string, number> = { N: 0.85, R: 0.62 };
      const cilMap: Record<string, number> = { H: 0.56, L: 0.22, N: 0.00 };
      
      const av = avMap[metricMap['AV']] || 0;
      const ac = acMap[metricMap['AC']] || 0;
      const pr = prMap[metricMap['PR']] || 0;
      const ui = uiMap[metricMap['UI']] || 0;
      const c = cilMap[metricMap['C']] || 0;
      const i = cilMap[metricMap['I']] || 0;
      const a = cilMap[metricMap['A']] || 0;
      const s = metricMap['S'] || 'U';
      
      let exploitabilityScore: number;
      let impactScore: number;
      
      if (s === 'C') {
        const impactSubScore = 1 - (1 - c) * (1 - i) * (1 - a);
        impactScore = Math.min(7.52 * impactSubScore - 3.25 * Math.pow(impactSubScore, 15), 6.42);
        exploitabilityScore = 8.22 * av * ac * pr * ui;
      } else {
        const impactSubScore = 1 - (1 - c) * (1 - i) * (1 - a);
        impactScore = 6.42 * impactSubScore;
        exploitabilityScore = 8.22 * av * ac * pr * ui;
      }
      
      baseScore = Math.round((exploitabilityScore + impactScore) * 10) / 10;
    }
    
    let severity: string;
    if (baseScore >= 9.0) severity = 'CRITICAL';
    else if (baseScore >= 7.0) severity = 'HIGH';
    else if (baseScore >= 4.0) severity = 'MEDIUM';
    else if (baseScore >= 0.1) severity = 'LOW';
    else severity = 'NONE';
    
    return { score: baseScore, severity, version };
  } catch {
    return null;
  }
}

export default function VulnerabilityDetailPage() {
  const router = useRouter();
  const params = useParams<{ vuln_id: string }>();
  const vuln_id = params?.vuln_id;
  
  const [data, setData] = useState<VulnerabilityDetail | null>(null);
  const [references, setReferences] = useState<CVEReference[]>([]);
  const [exploits, setExploits] = useState<Exploit[]>([]);
  const [components, setComponents] = useState<Component[]>([]);
  const [loading, setLoading] = useState(true);
  const [notFoundError, setNotFoundError] = useState(false);
  
  if (!vuln_id) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-2xl font-bold mb-2">404</h1>
          <p className="text-muted-foreground">页面未找到</p>
        </div>
      </div>
    );
  }
  
  const isCVE = vuln_id.startsWith('CVE-');
    const isCNVD = vuln_id.startsWith('CNVD-');
    const isGHSA = vuln_id.startsWith('GHSA-');
  
  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      setNotFoundError(false);
      try {
        const response = await fetch('/api/v1/search/' + vuln_id);
        if (!response.ok) {
          setNotFoundError(true);
          return;
        }
        const unifiedData = await response.json();
        
        if (unifiedData.error) {
          setNotFoundError(true);
          return;
        }
        
        // 对于 CVE 类型，还要获取 references 和 exploits
        if (isCVE) {
          const refResponse = await fetch('/api/v1/cve/' + vuln_id + '/references');
          let refs: CVEReference[] = [];
          if (refResponse.ok) {
            refs = await refResponse.json();
          }
          setReferences(refs);
          
          const exploitResponse = await fetch('/api/v1/cve/' + vuln_id + '/exploits');
          let exps: Exploit[] = [];
          if (exploitResponse.ok) {
            exps = await exploitResponse.json();
          }
          setExploits(exps);
        }
        
        // 获取关联的组件信息
        const componentResponse = await fetch('/api/v1/components/list?keyword=' + encodeURIComponent(unifiedData.title || unifiedData.id));
        if (componentResponse.ok) {
          const componentData = await componentResponse.json();
          setComponents(componentData.data || []);
        }
        
        // 转换受影响版本格式 - 支持 CVE, CNVD, OSV, GHSA 四种格式
        let affectedVersions: AffectedVersion[] | null = null;
        if (unifiedData.affected && Array.isArray(unifiedData.affected)) {
          affectedVersions = (unifiedData.affected || []).map((a: any) => {
            const versions: { version: string; status: string }[] = [];
            
            // CVE 格式: {vendor, product, versions: [{version, status}]}
            if (a.vendor && a.product) {
              (a.versions || []).forEach((v: any) => {
                versions.push({
                  version: v.version || 'n/a',
                  status: v.status || 'affected'
                });
              });
              return {
                vendor: a.vendor,
                product: a.product,
                versions
              };
            }
            
            // CNVD 格式: 字符串数组 ['product1', 'product2']
            if (typeof a === 'string') {
              return {
                vendor: '未知厂商',
                product: a,
                versions: [{ version: '未知版本', status: 'affected' }]
              };
            }
            
            // OSV/GHSA 格式: {package: {name, ecosystem}, ranges: [{type, events: [{introduced, fixed}]}]}
            const packageInfo = a.package || {};
            (a.ranges || []).forEach((range: any) => {
              (range.events || []).forEach((event: any) => {
                if (event.introduced) {
                  versions.push({ version: event.introduced, status: 'affected' });
                }
                if (event.fixed) {
                  versions.push({ version: event.fixed, status: 'fixed' });
                }
                if (event.last_affected) {
                  versions.push({ version: event.last_affected, status: 'affected' });
                }
              });
            });
            
            // 从 database_specific 或 ecosystem 获取厂商信息
            const vendor = packageInfo.ecosystem || a.database_specific?.ecosystem || '未知厂商';
            const product = packageInfo.name || a.database_specific?.name || '未知产品';
            
            return {
              vendor,
              product,
              versions
            };
          }).filter((v: AffectedVersion) => v.product || v.vendor);
          
          if (affectedVersions && affectedVersions.length === 0) {
            affectedVersions = null;
          }
        }
        
        setData({
          vuln_id: unifiedData.id,
          title: unifiedData.title || unifiedData.id,
          description: unifiedData.description || '',
          source: unifiedData.source || 'Unknown',
          severity: unifiedData.severity || '',
          cvss_v3_score: unifiedData.cvss_v3_score,
          cvss_v3_severity: unifiedData.cvss_v3_severity || unifiedData.severity,
          cvss_v4_score: unifiedData.cvss_v4_score,
          cvss_v4_severity: unifiedData.cvss_v4_severity,
          published_date: unifiedData.published_date,
          modified_date: unifiedData.modified_date,
          cwe_ids: unifiedData.cwes || [],
          related_cve_ids: unifiedData.related_cve_ids || [],
          references: (unifiedData.references || []).map((r: any) => ({ url: r.url })),
          tags: unifiedData.tags || [],
          data_sources: unifiedData.data_sources || [],
          affected_versions: affectedVersions,
          exploits_count: unifiedData.exploits_count || 0,
          vendor_name: null,
          product_name: null
        });
        
      } catch (error) {
        console.error('Error fetching data:', error);
        setNotFoundError(true);
      } finally {
        setLoading(false);
      }
    };
    
    fetchData();
  }, [vuln_id, isCVE, isCNVD, isGHSA]);

  useEffect(() => {
    if (!vuln_id) return;
    
    const typeParam = isCVE ? 'cve' : isCNVD ? 'cnvd' : isGHSA ? 'github_advisory' : 'osv';
    
    fetch('/api/v1/search/' + vuln_id + '/view?type=' + typeParam, { method: 'POST' })
      .catch(err => console.error('Failed to increment view count:', err));
  }, [vuln_id, isCVE, isCNVD, isGHSA]);
  
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
          <p className="text-muted-foreground">未找到漏洞信息</p>
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
  
  const severityColors: Record<string, string> = {
    critical: 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300',
    high: 'bg-orange-100 text-orange-700 dark:bg-orange-900 dark:text-orange-300',
    medium: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300',
    low: 'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300',
    info: 'bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300',
    moderate: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300',
    CRITICAL: 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300',
    HIGH: 'bg-orange-100 text-orange-700 dark:bg-orange-900 dark:text-orange-300',
    MEDIUM: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300',
    LOW: 'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300',
    INFO: 'bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300',
    MODERATE: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300',
  };

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

  const hasCVSSv3 = typeof data.cvss_v3_score === 'number';
  const hasCVSSv4 = typeof data.cvss_v4_score === 'number';
  const cvssScore = hasCVSSv3 ? data.cvss_v3_score : (hasCVSSv4 ? data.cvss_v4_score : null);
  const cvssVersion = hasCVSSv3 ? 'v3' : 'v4';

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
            <span className={`px-3 py-1 rounded-full text-sm font-medium ${severityColors[data.severity] || 'bg-gray-100 text-gray-700'}`}>
              {data.severity?.toUpperCase() || 'UNKNOWN'}
            </span>
            <span className={`px-3 py-1 rounded-full text-sm ${
              isCVE 
                ? 'bg-purple-100 dark:bg-purple-900 text-purple-700 dark:text-purple-300'
                : isGHSA
                  ? 'bg-orange-100 dark:bg-orange-900 text-orange-700 dark:text-orange-300'
                  : isCNVD
                    ? 'bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300'
                    : 'bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-300'
            }`}>
              {isCVE ? 'CVE' : isGHSA ? 'GHSA' : isCNVD ? 'CNVD' : 'OSV'}
            </span>
            {data.exploits_count && data.exploits_count > 0 && (
              <span className="px-3 py-1 bg-red-100 dark:bg-red-900 text-red-700 dark:text-red-300 rounded-full text-sm font-medium flex items-center gap-1">
                <FileCode className="h-4 w-4" />
                有Exploit ({data.exploits_count})
              </span>
            )}
          </div>
          
          <h1 className="text-2xl font-bold mb-2">{data.title}</h1>
          <div className="flex items-center gap-2 text-muted-foreground">
            <code className="font-mono text-lg">{data.vuln_id}</code>
            {data.source && (
              <span className="text-sm">来源: {data.source}</span>
            )}
          </div>
        </div>

        {cvssScore !== null && (
          <div className="bg-card border rounded-xl p-6 mb-6">
            <div className="flex items-center gap-6">
              <div className="text-center">
                <div className={`text-5xl font-bold ${
                  cvssScore >= 9 ? 'text-red-500' :
                  cvssScore >= 7 ? 'text-orange-500' :
                  cvssScore >= 4 ? 'text-yellow-500' : 'text-green-500'
                }`}>
                  {cvssScore}
                </div>
                <div className="text-sm text-muted-foreground mt-1">CVSS {cvssVersion} Score</div>
              </div>
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-2">
                  <AlertTriangle className="h-5 w-5" />
                  <span className="font-medium">严重程度评估</span>
                </div>
                <div className="w-full bg-muted rounded-full h-3">
                  <div 
                    className={`h-3 rounded-full transition-all ${
                      cvssScore >= 9 ? 'bg-red-500' :
                      cvssScore >= 7 ? 'bg-orange-500' :
                      cvssScore >= 4 ? 'bg-yellow-500' : 'bg-green-500'
                    }`}
                    style={{ width: `${(cvssScore / 10) * 100}%` }}
                  />
                </div>
                <div className="flex justify-between text-xs text-muted-foreground mt-2">
                  <span>0</span>
                  <span>LOW</span>
                  <span>MEDIUM</span>
                  <span>HIGH</span>
                  <span>CRITICAL</span>
                  <span>10</span>
                </div>
              </div>
            </div>
          </div>
        )}

        <div className="bg-card border rounded-xl p-6 mb-6">
          <h2 className="text-lg font-semibold mb-4">漏洞描述</h2>
          <p className="text-muted-foreground whitespace-pre-wrap">{data.description || '暂无描述'}</p>
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
                <span>{formatDate(data.published_date)}</span>
              </div>
              {data.modified_date && (
                <div className="flex justify-between">
                  <span className="text-muted-foreground">修改日期</span>
                  <span>{formatDate(data.modified_date)}</span>
                </div>
              )}
            </div>
          </div>

          <div className="bg-card border rounded-xl p-6">
            <div className="flex items-center gap-2 mb-4">
              <Tag className="h-5 w-5" />
              <h2 className="text-lg font-semibold">分类信息</h2>
            </div>
            <div className="space-y-3">
              {data.cwe_ids && data.cwe_ids.length > 0 && (
                <div>
                  <span className="text-muted-foreground block mb-2">CWE ID</span>
                  <div className="flex flex-wrap gap-2">
                    {data.cwe_ids.map((cwe, index) => (
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
              {data.tags && data.tags.length > 0 && (
                <div>
                  <span className="text-muted-foreground block mb-2">标签</span>
                  <div className="flex flex-wrap gap-2">
                    {data.tags.map((tag, index) => (
                      <span 
                        key={index}
                        className="px-2 py-1 bg-muted rounded text-sm"
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        {(data.affected_versions && data.affected_versions.length > 0) || (data.vendor_name && data.product_name) || (isCNVD && data.tags && data.tags.length > 0) ? (
          <div className="bg-card border rounded-xl p-6 mb-6">
            <div className="flex items-center gap-2 mb-4">
              <Shield className="h-5 w-5" />
              <h2 className="text-lg font-semibold">受影响产品</h2>
            </div>
            <div className="space-y-4">
              {data.vendor_name && data.product_name && (
                <div className="flex items-center gap-2 text-muted-foreground">
                  <span className="font-medium">厂商:</span>
                  <span>{data.vendor_name}</span>
                  <span className="mx-2">|</span>
                  <span className="font-medium">产品:</span>
                  <span>{data.product_name}</span>
                </div>
              )}
              {isCNVD && data.tags && data.tags.length > 0 && (
                <div>
                  <span className="text-muted-foreground block mb-2">受影响产品:</span>
                  <div className="flex flex-wrap gap-2">
                    {data.tags.map((tag, index) => (
                      <span 
                        key={index}
                        className="px-3 py-1 bg-muted rounded-lg text-sm"
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {data.affected_versions && data.affected_versions.length > 0 && (
                <div>
                  <span className="text-muted-foreground block mb-2">受影响版本:</span>
                  <div className="space-y-3">
                    {data.affected_versions.map((item, index) => (
                      <div key={index} className="bg-muted rounded-lg p-3">
                        <div className="flex items-center gap-2 mb-2">
                          <span className="font-medium">{item.vendor}</span>
                          <span className="text-muted-foreground">/</span>
                          <span className="font-medium">{item.product}</span>
                        </div>
                        <div className="flex flex-wrap gap-2">
                          {item.versions.map((v, vIndex) => (
                            <span 
                              key={vIndex}
                              className={`px-2 py-1 rounded text-sm ${
                                v.status === 'affected' ? 'bg-red-100 dark:bg-red-900 text-red-700 dark:text-red-300' :
                                v.status === 'fixed' ? 'bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300' :
                                'bg-gray-100 dark:bg-gray-900 text-gray-700 dark:text-gray-300'
                              }`}
                            >
                              {v.version}
                              {v.status && v.status !== 'affected' && ` (${v.status})`}
                            </span>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        ) : null}

        {data.related_cve_ids && data.related_cve_ids.length > 0 && (
          <div className="bg-card border rounded-xl p-6 mb-6">
            <h2 className="text-lg font-semibold mb-4">关联CVE</h2>
            <div className="flex flex-wrap gap-2">
              {data.related_cve_ids.map((cve_id, index) => (
                <a
                  key={index}
                  href={'/vuln/' + cve_id}
                  className="px-3 py-1 bg-muted rounded-full text-sm hover:bg-accent transition-colors"
                >
                  {cve_id}
                </a>
              ))}
            </div>
          </div>
        )}

        {components.length > 0 && (
          <div className="bg-card border rounded-xl p-6 mb-6">
            <h2 className="text-lg font-semibold mb-4">相关组件</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {components.map((component) => (
                <div
                  key={component.id}
                  className="bg-muted rounded-lg p-4 hover:bg-accent transition-colors"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <h3 className="font-medium">{component.name}</h3>
                      {component.vendor_name && (
                        <div className="text-sm text-muted-foreground mt-1">
                          厂商: {component.vendor_name}
                        </div>
                      )}
                      <div className="flex flex-wrap gap-2 mt-2">
                        <span className="px-2 py-0.5 bg-background rounded text-xs">
                          {component.category}
                        </span>
                        {component.ecosystem && (
                          <span className="px-2 py-0.5 bg-background rounded text-xs">
                            {component.ecosystem}
                          </span>
                        )}
                        {component.product_version && (
                          <span className="px-2 py-0.5 bg-background rounded text-xs">
                            版本: {component.product_version}
                          </span>
                        )}
                      </div>
                    </div>
                    {component.vuln_count > 0 && (
                      <span className="shrink-0 px-2 py-1 bg-red-100 dark:bg-red-900 text-red-700 dark:text-red-300 rounded text-xs font-medium">
                        {component.vuln_count} 漏洞
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {exploits.length > 0 && (
          <div className="bg-card border rounded-xl p-6 mb-6">
            <div className="flex items-center gap-2 mb-4">
              <FileCode className="h-5 w-5 text-green-500" />
              <h2 className="text-lg font-semibold">Exploit 信息</h2>
              <span className="ml-auto text-sm text-muted-foreground">{exploits.length} 个可用</span>
            </div>
            <div className="space-y-4">
              {exploits.map((exploit) => (
                <div key={exploit.id} className="bg-muted rounded-lg p-4">
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1 min-w-0">
                      <h3 className="font-medium mb-2">{exploit.title}</h3>
                      <div className="flex flex-wrap gap-2 text-sm text-muted-foreground">
                        {exploit.platform && (
                          <span className="px-2 py-0.5 bg-background rounded">平台: {exploit.platform}</span>
                        )}
                        {exploit.exploit_type && (
                          <span className="px-2 py-0.5 bg-background rounded">类型: {exploit.exploit_type}</span>
                        )}
                        {exploit.author && (
                          <span className="px-2 py-0.5 bg-background rounded">作者: {exploit.author}</span>
                        )}
                        {exploit.source && (
                          <span className="px-2 py-0.5 bg-background rounded">来源: {exploit.source}</span>
                        )}
                        {exploit.verified && (
                          <span className="px-2 py-0.5 bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300 rounded">已验证</span>
                        )}
                      </div>
                      {exploit.reliability_score !== null && (
                        <div className="mt-2 text-sm">
                          <span className="text-muted-foreground">可信度评分: </span>
                          <span className="font-medium">{exploit.reliability_score}/10</span>
                        </div>
                      )}
                      {exploit.published_date && (
                        <div className="mt-2 text-sm text-muted-foreground">
                          发布日期: {formatDate(exploit.published_date)}
                        </div>
                      )}
                    </div>
                    {exploit.source_url && (
                      <a
                        href={exploit.source_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="shrink-0 px-3 py-2 bg-primary text-white rounded-lg hover:bg-primary/90 text-sm flex items-center gap-2"
                      >
                        <ExternalLink className="h-4 w-4" />
                        查看详情
                      </a>
                    )}
                  </div>
                  {exploit.code && (
                    <div className="mt-4">
                      <div className="text-sm font-medium mb-2">漏洞代码:</div>
                      <pre className="bg-background rounded-lg p-4 overflow-x-auto text-sm">
                        <code>{exploit.code}</code>
                      </pre>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {(data.references && data.references.length > 0) || references.length > 0 ? (
          <div className="bg-card border rounded-xl p-6">
            <div className="flex items-center gap-2 mb-4">
              <Link2 className="h-5 w-5" />
              <h2 className="text-lg font-semibold">参考链接</h2>
            </div>
            <div className="space-y-3">
              {isCVE ? (
                references.map((ref) => (
                  <a
                    key={ref.id}
                    href={ref.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-start gap-4 p-3 bg-muted rounded-lg hover:bg-accent transition-colors"
                  >
                    <ExternalLink className="h-4 w-4 mt-0.5 shrink-0" />
                    <div className="flex-1 min-w-0">
                      {ref.title && <div className="font-medium truncate">{ref.title}</div>}
                      <div className="text-sm text-muted-foreground truncate">{ref.url}</div>
                      {ref.tags && ref.tags.length > 0 && (
                        <div className="flex flex-wrap gap-1 mt-2">
                          {ref.tags.map((tag, index) => (
                            <span key={index} className="px-1.5 py-0.5 bg-background rounded text-xs">
                              {tag}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </a>
                ))
              ) : (
                data.references!.map((ref, index) => (
                  <a
                    key={index}
                    href={ref.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-3 p-3 bg-muted rounded-lg hover:bg-accent transition-colors"
                  >
                    <ExternalLink className="h-4 w-4 shrink-0" />
                    <span className="flex-1 truncate">{ref.url}</span>
                  </a>
                ))
              )}
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}
