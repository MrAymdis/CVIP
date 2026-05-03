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
        <Header />
        {children}
      </body>
    </html>
  );
}
