import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import Header from "@/components/Header";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "漏洞情报平台",
  description: "综合漏洞情报平台，支持CVE、CNVD、OSV、GitHub Advisory等多数据源",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="zh-CN">
      <body className={inter.className}>
        <div className="min-h-screen flex flex-col">
          <Header />
          <main className="flex-1 min-h-0 bg-slate-50 dark:bg-slate-900">{children}</main>
          <footer className="border-t border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 py-3">
            <div className="container mx-auto px-4 text-center">
              <p className="text-xs text-slate-500 dark:text-slate-400">
                © 2026 网络安全漏洞情报平台 | 数据来源: NVD, ExploitDB, GitHub, CISA KEV 等
              </p>
            </div>
          </footer>
        </div>
      </body>
    </html>
  );
}
