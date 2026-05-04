import Link from "next/link";
import { Search, Shield, ArrowRight, Zap, Lock } from "lucide-react";

export default function Home() {
  return (
    <section className="min-h-[calc(100vh-120px)] w-full flex flex-col justify-center items-center relative overflow-hidden">
      <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-primary/10 dark:from-primary/10 dark:via-transparent dark:to-primary/5" />
      <div className="absolute top-20 left-10 w-72 h-72 bg-primary/20 rounded-full blur-3xl" />
      <div className="absolute bottom-10 right-10 w-96 h-96 bg-blue-500/10 rounded-full blur-3xl" />

      <div className="relative container mx-auto px-4 py-8">
        <div className="text-center max-w-4xl mx-auto">
          <div className="inline-flex items-center gap-2 px-4 py-2 bg-primary/10 rounded-full mb-6">
            <Zap className="h-4 w-4 text-primary" />
            <span className="text-sm font-medium text-primary">14+ 权威数据源实时同步</span>
          </div>

          <div className="flex justify-center mb-6">
            <div className="relative">
              <div className="absolute inset-0 bg-primary/20 rounded-full blur-xl animate-pulse" />
              <Shield className="h-14 w-14 text-primary relative" />
            </div>
          </div>

          <h1 className="text-2xl md:text-4xl font-bold mb-4 tracking-tight">
            <span className="bg-gradient-to-r from-slate-900 via-slate-800 to-slate-700 dark:from-white dark:via-slate-200 dark:to-slate-300 bg-clip-text">
              网络安全漏洞情报平台
            </span>
          </h1>

          <p className="text-sm md:text-base text-slate-600 dark:text-slate-400 max-w-xl mx-auto mb-6 leading-relaxed">
            聚合 NVD、ExploitDB、GitHub Advisory、CISA KEV 等权威数据源，
            为安全研究人员和运维人员提供全面的漏洞查询、Exploit 检索和统计分析服务
          </p>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
            <Link
              href="/search"
              className="group inline-flex items-center gap-2 px-5 py-2.5 bg-slate-900 dark:bg-white text-white dark:text-slate-900 font-semibold rounded-lg shadow-lg hover:shadow-xl hover:-translate-y-0.5 transition-all"
            >
              <Search className="h-4 w-4" />
              开始搜索
              <ArrowRight className="h-4 w-4 group-hover:translate-x-1 transition-transform" />
            </Link>
            <Link
              href="/components"
              className="inline-flex items-center gap-2 px-5 py-2.5 bg-white dark:bg-slate-800 text-slate-900 dark:text-white font-semibold rounded-lg shadow hover:shadow-lg hover:-translate-y-0.5 transition-all border border-slate-200 dark:border-slate-700"
            >
              <Lock className="h-4 w-4" />
              组件漏洞查询
            </Link>
          </div>
        </div>
      </div>
    </section>
  );
}