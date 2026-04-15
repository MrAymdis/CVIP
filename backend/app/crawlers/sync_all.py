"""
统一数据同步脚本
按顺序同步所有漏洞数据源
"""
import asyncio
import sys
from typing import Dict, Any, List
from app.crawlers import (
    ExploitDBCrawler,
    MetasploitCrawler,
    PacketStormCrawler,
    CISAKEVCrawler,
    EPSSCrawler,
    GitHubCrawler,
    TenableCrawler,
)


class DataSource:
    """数据源配置"""
    
    def __init__(
        self,
        name: str,
        crawler_class: Any,
        enabled: bool = True,
        default_limit: int = 100,
        description: str = "",
    ):
        self.name = name
        self.crawler_class = crawler_class
        self.enabled = enabled
        self.default_limit = default_limit
        self.description = description


# 数据源配置
DATA_SOURCES = [
    DataSource(
        name="cisa_kev",
        crawler_class=CISAKEVCrawler,
        enabled=True,
        default_limit=None,
        description="CISA Known Exploited Vulnerabilities",
    ),
    DataSource(
        name="epss",
        crawler_class=EPSSCrawler,
        enabled=True,
        default_limit=None,
        description="Exploit Prediction Scoring System",
    ),
    DataSource(
        name="exploitdb",
        crawler_class=ExploitDBCrawler,
        enabled=True,
        default_limit=200,
        description="Exploit-DB 漏洞利用数据库",
    ),
    DataSource(
        name="metasploit",
        crawler_class=MetasploitCrawler,
        enabled=False,
        default_limit=100,
        description="Metasploit 漏洞利用模块（需要 GitHub Token）",
    ),
    DataSource(
        name="packetstorm",
        crawler_class=PacketStormCrawler,
        enabled=True,
        default_limit=100,
        description="Packet Storm Security 漏洞公告",
    ),
    DataSource(
        name="github",
        crawler_class=GitHubCrawler,
        enabled=False,
        default_limit=50,
        description="GitHub PoC 仓库",
    ),
    DataSource(
        name="tenable",
        crawler_class=TenableCrawler,
        enabled=True,
        default_limit=100,
        description="Tenable 漏洞数据库",
    ),
]


class SyncManager:
    """同步管理器"""
    
    def __init__(self, limits: Dict[str, int] = None):
        self.limits = limits or {}
        self.results = {}
    
    def get_limit(self, source_name: str, default: int) -> int:
        """获取数据源的限制数量"""
        return self.limits.get(source_name, default)
    
    async def sync_source(self, source: DataSource) -> Dict[str, Any]:
        """同步单个数据源"""
        print(f"\n{'=' * 60}")
        print(f"开始同步: {source.name}")
        print(f"描述: {source.description}")
        print(f"{'=' * 60}")
        
        result = {
            "name": source.name,
            "success": False,
            "added": 0,
            "error": None,
        }
        
        try:
            crawler = source.crawler_class()
            
            # 检查是否有 sync 方法
            if hasattr(crawler, "sync"):
                limit = self.get_limit(source.name, source.default_limit)
                
                if limit:
                    print(f"使用限制: {limit} 条记录")
                    added = await crawler.sync(limit=limit)
                else:
                    added = await crawler.sync()
                
                result["added"] = added
                result["success"] = True
                print(f"\n✅ {source.name} 同步完成，新增 {added} 条记录")
            
            elif hasattr(crawler, "sync_recent"):
                added = await crawler.sync_recent()
                result["added"] = added
                result["success"] = True
                print(f"\n✅ {source.name} 同步完成，新增 {added} 条记录")
            
            else:
                raise AttributeError(f"Crawler {source.name} 没有 sync 或 sync_recent 方法")
        
        except Exception as e:
            result["error"] = str(e)
            print(f"\n❌ {source.name} 同步失败: {e}")
            import traceback
            traceback.print_exc()
        
        return result
    
    async def sync_all(self) -> Dict[str, Any]:
        """同步所有启用的数据源"""
        print("\n" + "=" * 60)
        print("统一数据同步脚本")
        print("=" * 60)
        
        enabled_sources = [s for s in DATA_SOURCES if s.enabled]
        print(f"\n启用的数据源: {len(enabled_sources)}/{len(DATA_SOURCES)}")
        
        for source in enabled_sources:
            print(f"  - {source.name}: {source.description}")
        
        results = {}
        for source in enabled_sources:
            result = await self.sync_source(source)
            results[source.name] = result
            
            # 数据源之间的延迟
            if source != enabled_sources[-1]:
                await asyncio.sleep(1)
        
        # 打印汇总
        print("\n" + "=" * 60)
        print("同步汇总")
        print("=" * 60)
        
        total_added = 0
        success_count = 0
        
        for name, result in results.items():
            status = "✅ 成功" if result["success"] else "❌ 失败"
            added = result["added"]
            print(f"\n{name}: {status}")
            if result["success"]:
                print(f"  新增记录: {added}")
                total_added += added
                success_count += 1
            else:
                print(f"  错误: {result['error']}")
        
        print("\n" + "=" * 60)
        print(f"总计: {success_count}/{len(enabled_sources)} 成功, 新增 {total_added} 条记录")
        print("=" * 60)
        
        return {
            "results": results,
            "total_added": total_added,
            "success_count": success_count,
            "total_sources": len(enabled_sources),
        }


def parse_limits(args: List[str]) -> Dict[str, int]:
    """解析命令行参数中的限制"""
    limits = {}
    for arg in args:
        if "=" in arg:
            name, value = arg.split("=", 1)
            try:
                limits[name] = int(value)
            except ValueError:
                print(f"警告: 无效的限制值 {arg}")
    return limits


async def main():
    """主函数"""
    limits = parse_limits(sys.argv[1:])
    
    manager = SyncManager(limits=limits)
    await manager.sync_all()


if __name__ == "__main__":
    asyncio.run(main())
