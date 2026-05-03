#!/usr/bin/env python3
"""
OSV (Open Source Vulnerability) 小时级别监控脚本
通过GCS存储桶的modified_id.csv文件获取增量漏洞，实现每小时监控
"""
import time
import requests
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.database import SessionLocal
from app.models import OSVVulnerability
from app.services.unified_writer import save_to_unified, osv_to_unified_format


class OSVMonitor:
    """OSV漏洞监控器"""
    
    def __init__(self):
        self.osv_api_base = "https://api.osv.dev/v1"
        self.osv_gcs_base = "https://storage.googleapis.com/osv-vulnerabilities"
        self.last_modified_file = "modified_id.csv"
        self._setup_logging()
    
    def _setup_logging(self):
        """设置日志记录"""
        log_dir = Path(__file__).parent.parent.parent / "logs"
        log_dir.mkdir(exist_ok=True)
        
        log_file = log_dir / f"osv_monitor_{datetime.now().strftime('%Y%m%d')}.log"
        
        self.logger = logging.getLogger('osv_monitor')
        self.logger.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # 控制台处理器
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # 文件处理器
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
    
    def get_modified_vulns(self, hours: int = 1) -> List[Tuple[str, str]]:
        """获取最近N小时内修改的OSV漏洞列表"""
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(hours=hours)
        
        url = f"{self.osv_gcs_base}/{self.last_modified_file}"
        
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            lines = response.text.strip().split('\n')
            modified_vulns = []
            
            for line in lines:
                if not line.strip():
                    continue
                
                parts = line.split(',', 1)
                if len(parts) != 2:
                    continue
                
                modified_str, vuln_path = parts
                try:
                    modified_time = datetime.fromisoformat(modified_str.replace('Z', '+00:00'))
                    
                    if modified_time >= start_time:
                        ecosystem_dir, vuln_id = vuln_path.split('/', 1)
                        modified_vulns.append((vuln_id, ecosystem_dir))
                except Exception:
                    continue
            
            msg = f"Found {len(modified_vulns)} recently modified OSV vulnerabilities"
            print(msg)
            self.logger.info(msg)
            return modified_vulns
            
        except Exception as e:
            msg = f"Error fetching modified vulnerabilities: {e}"
            print(msg)
            self.logger.error(msg)
            return []
    
    def get_vuln_by_id(self, vuln_id: str) -> Optional[Dict]:
        """通过OSV漏洞ID获取详细信息"""
        url = f"{self.osv_api_base}/vulns/{vuln_id}"
        
        try:
            response = requests.get(url, timeout=30)
            if response.status_code == 404:
                return None
            response.raise_for_status()
            return response.json()
        except Exception as e:
            msg = f"Error fetching OSV vuln {vuln_id}: {e}"
            print(msg)
            self.logger.error(msg)
            return None
    
    def parse_osv_vulnerability(self, vuln_data: Dict) -> Dict:
        """解析OSV漏洞数据"""
        return {
            "osv_id": vuln_data.get("id", ""),
            "schema_version": vuln_data.get("schema_version", ""),
            "published": self.parse_datetime(vuln_data.get("published")),
            "modified": self.parse_datetime(vuln_data.get("modified")),
            "withdrawn": self.parse_datetime(vuln_data.get("withdrawn")),
            "aliases": vuln_data.get("aliases"),
            "related": vuln_data.get("related"),
            "upstream": vuln_data.get("upstream"),
            "summary": vuln_data.get("summary", ""),
            "details": vuln_data.get("details", ""),
            "affected": vuln_data.get("affected"),
            "references": vuln_data.get("references"),
            "severity": vuln_data.get("severity"),
            "database_specific": vuln_data.get("database_specific"),
        }
    
    def parse_datetime(self, datetime_str: Optional[str]) -> Optional[datetime]:
        """解析ISO 8601格式的时间字符串"""
        if not datetime_str:
            return None
        
        try:
            return datetime.fromisoformat(datetime_str.replace("Z", "+00:00"))
        except Exception:
            return None
    
    def save_osv_to_db(self, vuln_data: Dict) -> bool:
        """将OSV漏洞保存到数据库"""
        db = SessionLocal()
        try:
            osv_id = vuln_data["osv_id"]
            
            existing = db.query(OSVVulnerability).filter(
                OSVVulnerability.osv_id == osv_id
            ).first()
            
            if existing:
                existing.schema_version = vuln_data["schema_version"]
                existing.published = vuln_data["published"]
                existing.modified = vuln_data["modified"]
                existing.withdrawn = vuln_data["withdrawn"]
                existing.aliases = vuln_data["aliases"]
                existing.related = vuln_data["related"]
                existing.upstream = vuln_data["upstream"]
                existing.summary = vuln_data["summary"]
                existing.details = vuln_data["details"]
                existing.affected = vuln_data["affected"]
                existing.references = vuln_data["references"]
                existing.severity = vuln_data["severity"]
                existing.database_specific = vuln_data["database_specific"]
            else:
                new_vuln = OSVVulnerability(
                    osv_id=vuln_data["osv_id"],
                    schema_version=vuln_data["schema_version"],
                    published=vuln_data["published"],
                    modified=vuln_data["modified"],
                    withdrawn=vuln_data["withdrawn"],
                    aliases=vuln_data["aliases"],
                    related=vuln_data["related"],
                    upstream=vuln_data["upstream"],
                    summary=vuln_data["summary"],
                    details=vuln_data["details"],
                    affected=vuln_data["affected"],
                    references=vuln_data["references"],
                    severity=vuln_data["severity"],
                    database_specific=vuln_data["database_specific"],
                )
                db.add(new_vuln)

            db.commit()

            unified_data = osv_to_unified_format(vuln_data)
            save_to_unified(db, unified_data, "osv")

            return True
            
        except Exception as e:
            msg = f"Error saving {osv_id} to DB: {e}"
            print(msg)
            self.logger.error(msg)
            db.rollback()
            return False
        finally:
            db.close()
    
    def sync_osv_vulnerability(self, vuln_id: str) -> bool:
        """同步单个OSV漏洞到数据库"""
        vuln_data = self.get_vuln_by_id(vuln_id)
        
        if not vuln_data:
            return False
        
        try:
            parsed = self.parse_osv_vulnerability(vuln_data)
            if parsed and parsed["osv_id"]:
                if self.save_osv_to_db(parsed):
                    msg = f"✅ Successfully synced OSV:{parsed['osv_id']}"
                    print(msg)
                    self.logger.info(msg)
                    return True
            return False
        except Exception as e:
            msg = f"Error syncing {vuln_id}: {e}"
            print(msg)
            self.logger.error(msg)
            return False
    
    def run_hourly_check(self, hours: int = 1):
        """执行一次小时检查"""
        msg = f"\n=== OSV Check at {datetime.now()} (last {hours} hours) ==="
        print(msg)
        self.logger.info(msg)
        
        modified_vulns = self.get_modified_vulns(hours=hours)
        
        if not modified_vulns:
            msg = "No recent OSV vulnerability changes found"
            print(msg)
            self.logger.info(msg)
            return
        
        success_count = 0
        fail_count = 0
        
        for vuln_id, ecosystem in modified_vulns:
            if self.sync_osv_vulnerability(vuln_id):
                success_count += 1
            else:
                fail_count += 1
            
            time.sleep(0.2)
        
        msg = f"\nSync completed: {success_count} succeeded, {fail_count} failed"
        print(msg)
        self.logger.info(msg)
    
    def start_continuous_monitoring(self, interval_hours: int = 1):
        """启动持续监控"""
        msg = f"Starting OSV hourly monitor (interval: {interval_hours} hours)"
        print(msg)
        self.logger.info(msg)
        print("Press Ctrl+C to stop")
        
        try:
            while True:
                self.run_hourly_check()
                
                now = datetime.now()
                next_run = (now + timedelta(hours=interval_hours)).replace(
                    minute=0, second=0, microsecond=0
                )
                wait_seconds = (next_run - now).total_seconds()
                
                msg = f"\nWaiting {wait_seconds/3600:.1f} hours until next check..."
                print(msg)
                self.logger.info(msg)
                time.sleep(wait_seconds)
                
        except KeyboardInterrupt:
            msg = "\nMonitoring stopped by user"
            print(msg)
            self.logger.info(msg)


def main():
    monitor = OSVMonitor()
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "--continuous":
            monitor.start_continuous_monitoring()
        elif sys.argv[1] == "--hours":
            if len(sys.argv) > 2:
                try:
                    hours = int(sys.argv[2])
                    monitor.run_hourly_check(hours=hours)
                except ValueError:
                    print("Usage: python osv_monitor.py --hours <number>")
            else:
                print("Usage: python osv_monitor.py --hours <number>")
        else:
            print("Usage:")
            print("  python osv_monitor.py                 # 同步最近1小时")
            print("  python osv_monitor.py --continuous    # 持续监控模式")
            print("  python osv_monitor.py --hours <n>     # 同步最近n小时")
    else:
        monitor.run_hourly_check()


if __name__ == "__main__":
    main()
