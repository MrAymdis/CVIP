#!/usr/bin/env python3
"""
全量导入 cvelistV5 数据到数据库
"""
import sys
from pathlib import Path

# 添加 backend 目录到路径
backend_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(backend_dir))

from app.crawlers.cvelistv5_crawler_v2 import CVEListV5CrawlerV2
from app.database import SessionLocal


def import_all_cves():
    """导入所有年份的CVE数据"""
    crawler = CVEListV5CrawlerV2()
    
    # 获取所有可用年份
    years = crawler.get_available_years()
    print(f"Available years: {years}")
    
    if not years:
        print("No CVE data found in repository")
        return 0
    
    # 导入所有年份
    db = SessionLocal()
    try:
        print(f"Starting full import of {len(years)} years...")
        count = crawler.import_years(db, years, batch_size=2000)
        print(f"\n✅ Full import completed: {count} CVEs imported")
        return count
    finally:
        db.close()


if __name__ == "__main__":
    import_all_cves()
