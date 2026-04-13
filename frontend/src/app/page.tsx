import Link from "next/link";
import { Search, Shield, Database, TrendingUp, FileCode, AlertTriangle } from "lucide-react";

export default function Home() {
  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800">
      {/* Header */}
      <header className="border-b bg-white/80 backdrop-blur-sm dark:bg-slate-950/80">
        <div className="container mx-auto px-4 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="h-8 w-8 text-primary" />
            <span className="text-xl font-bold">漏洞情报平台</span>
          </div>
          <nav className="flex items-center gap-6">
            <Link href="/search" className="text-sm font-medium hover:text-primary">
              搜索
            </Link>
            <Link href="/stats" className="text-sm font-medium hover:text-primary">
              统计
            </Link>
            <Link href="/about" className="text-sm font-medium hover:text-primary">
              关于
            </Link>
          </nav>
        </div>
      </header>

      {/* Hero Section */}
      <section className="container mx-auto px-4 py-20 text-center">
        <h1 className="text-4xl md:text-6xl font-bold mb-6 bg-gradient-to-r from-primary to-primary/70 bg-clip-text text-transparent">
          网络安全漏洞情报平台
        </h1>
        <p className="text-xl text-muted-foreground max-w-2xl mx-auto mb-10">
          聚合14+数据源，为安全研究人员和运维人员提供全面的CVE漏洞查询、
          Exploit代码检索和漏洞统计分析服务
        </p>
        
        {/* Search Box */}
        <div className="max-w-2xl mx-auto mb-16">
          <Link
            href="/search"
            className="flex items-center gap-3 w-full px-6 py-4 bg-white dark:bg-slate-800 rounded-xl shadow-lg border hover:shadow-xl transition-shadow"
          >
            <Search className="h-5 w-5 text-muted-foreground" />
            <span className="text-muted-foreground">搜索 CVE、厂商、产品...</span>
          </Link>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 max-w-4xl mx-auto mb-20">
          <div className="p-6 bg-white dark:bg-slate-800 rounded-xl shadow-sm border">
            <Database className="h-8 w-8 text-primary mx-auto mb-2" />
            <div className="text-2xl font-bold">14+</div>
            <div className="text-sm text-muted-foreground">数据源</div>
          </div>
          <div className="p-6 bg-white dark:bg-slate-800 rounded-xl shadow-sm border">
            <AlertTriangle className="h-8 w-8 text-orange-500 mx-auto mb-2" />
            <div className="text-2xl font-bold">300K+</div>
            <div className="text-sm text-muted-foreground">CVE条目</div>
          </div>
          <div className="p-6 bg-white dark:bg-slate-800 rounded-xl shadow-sm border">
            <FileCode className="h-8 w-8 text-green-500 mx-auto mb-2" />
            <div className="text-2xl font-bold">100K+</div>
            <div className="text-sm text-muted-foreground">Exploit</div>
          </div>
          <div className="p-6 bg-white dark:bg-slate-800 rounded-xl shadow-sm border">
            <TrendingUp className="h-8 w-8 text-blue-500 mx-auto mb-2" />
            <div className="text-2xl font-bold">实时</div>
            <div className="text-sm text-muted-foreground">数据更新</div>
          </div>
        </div>

        {/* Features */}
        <div className="grid md:grid-cols-3 gap-8 max-w-5xl mx-auto">
          <div className="p-6 text-left">
            <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center mb-4">
              <Search className="h-6 w-6 text-primary" />
            </div>
            <h3 className="text-lg font-semibold mb-2">全文搜索</h3>
            <p className="text-muted-foreground">
              支持CVE ID、厂商、产品、描述等多维度搜索，快速定位目标漏洞
            </p>
          </div>
          <div className="p-6 text-left">
            <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center mb-4">
              <Shield className="h-6 w-6 text-primary" />
            </div>
            <h3 className="text-lg font-semibold mb-2">多源聚合</h3>
            <p className="text-muted-foreground">
              整合NVD、ExploitDB、GitHub、CISA KEV等14+权威数据源
            </p>
          </div>
          <div className="p-6 text-left">
            <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center mb-4">
              <TrendingUp className="h-6 w-6 text-primary" />
            </div>
            <h3 className="text-lg font-semibold mb-2">统计分析</h3>
            <p className="text-muted-foreground">
              提供CVE趋势、厂商排名、CWE分布等多维度可视化统计
            </p>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t bg-white dark:bg-slate-950 py-8">
        <div className="container mx-auto px-4 text-center text-sm text-muted-foreground">
          <p>© 2024 网络安全漏洞情报平台 | 数据来源: NVD, ExploitDB, GitHub, CISA KEV 等</p>
        </div>
      </footer>
    </div>
  );
}
