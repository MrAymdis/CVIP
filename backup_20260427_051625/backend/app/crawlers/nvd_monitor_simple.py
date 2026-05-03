#!/usr/bin/env python3
"""
简化版 NVD CVE 小时级别监控脚本
使用简单的while循环实现
"""
import json
import time
import requests
from datetime import datetime, timedelta, timezone
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.database import SessionLocal
from app.crawlers.cvelistv5_crawler_v2 import CVEListV5CrawlerV2


def get_nvd_recent_changes(hours: int = 1) -> list:
    """获取最近 N 小时内发布或更新的 CVE ID"""
    nvd_api_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    now = datetime.now(timezone.utc)
    start_time = now - timedelta(hours=hours)
    
    start_str = start_time.strftime("%Y-%m-%dT%H:%M:%S.000")
    end_str = now.strftime("%Y-%m-%dT%H:%M:%S.000")
    
    params = {
        "lastModStartDate": start_str,
        "lastModEndDate": end_str,
        "resultsPerPage": 1000,
        "startIndex": 0
    }
    
    try:
        response = requests.get(nvd_api_base, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        cve_ids = []
        for item in data.get("vulnerabilities", []):
            cve_id = item.get("cve", {}).get("id")
            if cve_id:
                cve_ids.append(cve_id)
        
        print(f"Found {len(cve_ids)} recently modified CVEs from NVD")
        return cve_ids
        
    except Exception as e:
        print(f"Error fetching from NVD API: {e}")
        return []


def fetch_cve_from_cveawg(cve_id: str):
    """从 cveawg.mitre.org 获取 CVE 详情"""
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return None


def fetch_cve_from_github(cve_id: str):
    """从 GitHub cvelistV5 获取 CVE 详情"""
    parts = cve_id.split("-")
    if len(parts) != 3:
        return None
    
    year = parts[1]
    cve_num = parts[2]
    prefix = cve_num[:4] if len(cve_num) >= 4 else "0000"
    
    url = f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{prefix}/{cve_id}.json"
    
    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return None


def sync_cve_to_db(cve_id: str):
    """将 CVE 同步到数据库"""
    crawler = CVEListV5CrawlerV2()
    
    cve_data = fetch_cve_from_cveawg(cve_id)
    if not cve_data:
        cve_data = fetch_cve_from_github(cve_id)
    
    if not cve_data:
        print(f"Failed to fetch data for {cve_id}")
        return False
    
    db = SessionLocal()
    try:
        parsed = crawler.parse_cve_json(cve_data)
        if parsed:
            if crawler.save_cve_to_db(parsed, db):
                db.commit()
                print(f"✅ Successfully synced {cve_id}")
                return True
        return False
    except Exception as e:
        print(f"Error saving {cve_id} to DB: {e}")
        db.rollback()
        return False
    finally:
        db.close()


def run_hourly_check():
    """执行一次小时检查"""
    print(f"\n=== Hourly NVD Check at {datetime.now()} ===")
    
    cve_ids = get_nvd_recent_changes(hours=1)
    
    if not cve_ids:
        print("No recent CVE changes found")
        return
    
    success_count = 0
    fail_count = 0
    
    for cve_id in cve_ids:
        if sync_cve_to_db(cve_id):
            success_count += 1
        else:
            fail_count += 1
        time.sleep(0.5)
    
    print(f"Sync completed: {success_count} succeeded, {fail_count} failed")


def main():
    """主函数"""
    print("Starting NVD hourly monitor...")
    
    while True:
        run_hourly_check()
        
        now = datetime.now()
        next_run = (now + timedelta(hours=1)).replace(minute=0, second=0, microsecond=0)
        wait_seconds = (next_run - now).total_seconds()
        
        print(f"Waiting {wait_seconds/3600:.1f} hours until next check...")
        time.sleep(wait_seconds)


if __name__ == "__main__":
    main()
