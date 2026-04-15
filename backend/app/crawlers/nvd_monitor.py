#!/usr/bin/env python3
"""
NVD CVE 小时级别监控脚本
监控 NVD API 获取最新发布/变更的 CVE，然后从 cveawg.mitre.org 或 GitHub 获取详细信息
"""
import json
import time
import requests
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.database import SessionLocal
from app.crawlers.cvelistv5_crawler_v2 import CVEListV5CrawlerV2


class NVDMonitor:
    """NVD CVE 监控器"""
    
    def __init__(self):
        self.nvd_api_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cveawg_api_base = "https://cveawg.mitre.org/api/cve"
        self.github_raw_base = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
        
        self.crawler = CVEListV5CrawlerV2()
        
    def get_nvd_recent_changes(self, hours: int = 1) -> List[str]:
        """获取最近 N 小时内发布或更新的 CVE ID"""
        # 计算时间范围
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(hours=hours)
        
        # NVD API 参数格式: yyyy-MM-ddTHH:mm:ss.SSS
        start_str = start_time.strftime("%Y-%m-%dT%H:%M:%S.000")
        end_str = now.strftime("%Y-%m-%dT%H:%M:%S.000")
        
        params = {
            "lastModStartDate": start_str,
            "lastModEndDate": end_str,
            "resultsPerPage": 1000,
            "startIndex": 0
        }
        
        cve_ids = []
        
        try:
            response = requests.get(self.nvd_api_base, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            for item in data.get("vulnerabilities", []):
                cve_id = item.get("cve", {}).get("id")
                if cve_id:
                    cve_ids.append(cve_id)
            
            print(f"Found {len(cve_ids)} recently modified CVEs from NVD")
            return cve_ids
            
        except Exception as e:
            print(f"Error fetching from NVD API: {e}")
            return []
    
    def fetch_cve_from_cveawg(self, cve_id: str) -> Optional[Dict]:
        """从 cveawg.mitre.org 获取 CVE 详情"""
        url = f"{self.cveawg_api_base}/{cve_id}"
        
        try:
            response = requests.get(url, timeout=30)
            if response.status_code == 404:
                return None
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Error fetching {cve_id} from CVEAWG: {e}")
            return None
    
    def fetch_cve_from_github(self, cve_id: str) -> Optional[Dict]:
        """从 GitHub cvelistV5 获取 CVE 详情"""
        # 解析 CVE ID: CVE-YYYY-NNNNN
        parts = cve_id.split("-")
        if len(parts) != 3:
            return None
        
        year = parts[1]
        cve_num = parts[2]
        
        # GitHub 路径格式: cves/YYYY/XXXX/CVE-YYYY-XXXX.json
        # XXXX 是前4位数字
        prefix = cve_num[:4] if len(cve_num) >= 4 else "0000"
        
        url = f"{self.github_raw_base}/{year}/{prefix}/{cve_id}.json"
        
        try:
            response = requests.get(url, timeout=30)
            if response.status_code == 404:
                return None
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Error fetching {cve_id} from GitHub: {e}")
            return None
    
    def sync_cve_to_db(self, cve_id: str) -> bool:
        """将 CVE 同步到数据库"""
        # 首先尝试从 cveawg 获取
        cve_data = self.fetch_cve_from_cveawg(cve_id)
        
        # 如果失败，尝试从 GitHub 获取
        if not cve_data:
            cve_data = self.fetch_cve_from_github(cve_id)
        
        if not cve_data:
            print(f"Failed to fetch data for {cve_id}")
            return False
        
        # 使用爬虫解析并保存
        db = SessionLocal()
        try:
            parsed = self.crawler.parse_cve_json(cve_data)
            if parsed:
                if self.crawler.save_cve_to_db(parsed, db):
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
    
    def run_hourly_check(self):
        """执行一次小时检查"""
        print(f"\n=== Hourly NVD Check at {datetime.now()} ===")
        
        # 获取最近1小时的变更
        cve_ids = self.get_nvd_recent_changes(hours=1)
        
        if not cve_ids:
            print("No recent CVE changes found")
            return
        
        # 同步每个 CVE
        success_count = 0
        fail_count = 0
        
        for cve_id in cve_ids:
            if self.sync_cve_to_db(cve_id):
                success_count += 1
            else:
                fail_count += 1
            
            # 添加延迟，避免 API 限流
            time.sleep(0.5)
        
        print(f"\nSync completed: {success_count} succeeded, {fail_count} failed")
    
    def start_continuous_monitoring(self, interval_hours: int = 1):
        """启动持续监控"""
        print(f"Starting NVD hourly monitor (interval: {interval_hours} hours)")
        print("Press Ctrl+C to stop")
        
        try:
            while True:
                self.run_hourly_check()
                
                # 等待到下一个小时
                now = datetime.now()
                next_run = (now + timedelta(hours=interval_hours)).replace(
                    minute=0, second=0, microsecond=0
                )
                wait_seconds = (next_run - now).total_seconds()
                
                print(f"\nWaiting {wait_seconds/3600:.1f} hours until next check...")
                time.sleep(wait_seconds)
                
        except KeyboardInterrupt:
            print("\nMonitoring stopped by user")


def main():
    monitor = NVDMonitor()
    
    # 检查是否有参数传入
    if len(sys.argv) > 1 and sys.argv[1] == "--continuous":
        # 持续监控模式
        monitor.start_continuous_monitoring()
    else:
        # 单次运行模式（用于测试或手动触发）
        monitor.run_hourly_check()


if __name__ == "__main__":
    main()
