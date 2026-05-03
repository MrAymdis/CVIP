'use client';

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Shield } from "lucide-react";

export default function Header() {
  const pathname = usePathname();

  const navItems = [
    { href: "/search", label: "搜索" },
    { href: "/components", label: "组件信息" },
    { href: "/stats", label: "统计" },
    { href: "/about", label: "关于" },
  ];

  return (
    <header className="border-b bg-white/80 backdrop-blur-sm dark:bg-slate-950/80 sticky top-0 z-50">
      <div className="container mx-auto px-4 h-16 flex items-center justify-between">
        <Link href="/" className="flex items-center gap-2">
          <Shield className="h-8 w-8 text-primary" />
          <span className="text-xl font-bold">漏洞情报平台</span>
        </Link>
        <nav className="flex items-center gap-6">
          {navItems.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              className={`text-sm font-medium transition-colors ${
                pathname === item.href || pathname.startsWith(item.href + "/")
                  ? "text-primary"
                  : "hover:text-primary"
              }`}
            >
              {item.label}
            </Link>
          ))}
        </nav>
      </div>
    </header>
  );
}
