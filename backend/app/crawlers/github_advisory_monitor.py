#!/usr/bin/env python3
"""
GitHub Advisory Database 小时级别监控脚本
通过 GitHub REST API 获取增量漏洞，实现每小时监控
支持实时同步增量漏洞数据
"""
import time
import requests
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.database import SessionLocal
from app.models import GitHubAdvisory, CVE
from app.config import settings


class GitHubAdvisoryMonitor:
    """GitHub Advisory Database 监控器"""
    
    def __init__(self, token: Optional[str] = None):
        self.api_base = "https://api.github.com"
        self.token = token or settings.GITHUB_TOKEN
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
        }
        if self.token:
            self.headers["Authorization"] = f"token {self.token}"
            print(f"🔑 Using GitHub token (rate limit: 5000/hour)")
        else:
            print(f"ℹ️  No GitHub token provided (rate limit: 60/hour)")
        
        self._setup_logging()
    
    def _setup_logging(self):
        """设置日志记录"""
        log_dir = Path(__file__).parent.parent.parent / "logs"
        log_dir.mkdir(exist_ok=True)
        
        log_file = log_dir / f"github_advisory_monitor_{datetime.now().strftime('%Y%m%d')}.log"
        
        self.logger = logging.getLogger('github_advisory_monitor')
        self.logger.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
    
    def get_recent_advisories(self, hours: int = 1) -> List[Dict]:
        """获取最近N小时内更新的GitHub Advisory列表"""
        now = datetime.now(timezone.utc)
        since_time = now - timedelta(hours=hours)
        
        url = f"{self.api_base}/advisories"
        params = {
            "since": since_time.isoformat(),
            "per_page": 100,
            "direction": "desc",
            "sort": "updated"
        }
        
        all_advisories = []
        page = 1
        max_pages = 10  # 限制最大页数，避免无限循环
        
        try:
            print(f"Fetching advisories updated since {since_time}...")
            self.logger.info(f"Fetching advisories updated since {since_time}")
            
            while page <= max_pages:
                params["page"] = page
                print(f"Fetching page {page}...")
                
                response = requests.get(url, params=params, headers=self.headers, timeout=30)
                response.raise_for_status()
                
                data = response.json()
                if not data:
                    print("No more data, breaking")
                    break
                
                all_advisories.extend(data)
                print(f"Page {page} completed, total so far: {len(all_advisories)}")
                
                if len(data) < 100:
                    print("Less than 100 items, breaking")
                    break
                
                page += 1
                time.sleep(0.5)
            
            msg = f"Found {len(all_advisories)} recently updated GitHub advisories"
            print(msg)
            self.logger.info(msg)
            return all_advisories
            
        except Exception as e:
            msg = f"Error fetching GitHub advisories: {e}"
            print(msg)
            self.logger.error(msg)
            return []
    
    def parse_advisory(self, advisory_data: Dict) -> Optional[Dict]:
        """解析GitHub Advisory数据"""
        try:
            ghsa_id = advisory_data.get("ghsa_id")
            if not ghsa_id:
                return None
            
            # 提取aliases信息
            aliases = advisory_data.get("aliases", [])
            if not isinstance(aliases, list):
                aliases = []
            
            # 从aliases中提取第一个CVE ID（保持向后兼容）
            cve_id = advisory_data.get("cve_id")
            if not cve_id and aliases:
                for alias in aliases:
                    if alias.startswith("CVE-"):
                        cve_id = alias
                        break
            
            # 提取CVSS信息
            cvss_score = None
            cvss_vector = None
            cvss = advisory_data.get("cvss", {})
            if isinstance(cvss, dict):
                cvss_score = cvss.get("score")
                cvss_vector = cvss.get("vector_string")
            
            # 提取CWE信息
            cwe_ids = []
            cwes = advisory_data.get("cwes", [])
            for cwe in cwes:
                cwe_id = cwe.get("cwe_id")
                if cwe_id:
                    cwe_ids.append(cwe_id)
            
            # 提取受影响的包信息
            affected_packages = []
            vulnerabilities = advisory_data.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                package = vuln.get("package", {})
                affected_packages.append({
                    "name": package.get("name"),
                    "ecosystem": package.get("ecosystem"),
                    "versions": vuln.get("versions", []),
                    "first_patched_version": vuln.get("first_patched_version"),
                })
            
            # 提取引用链接
            references = []
            refs = advisory_data.get("references", [])
            for ref in refs:
                if isinstance(ref, dict):
                    references.append({
                        "url": ref.get("url"),
                        "type": ref.get("type"),
                    })
                elif isinstance(ref, str):
                    references.append({
                        "url": ref,
                        "type": None,
                    })
            
            # 提取修复版本信息
            patched_versions = []
            unaffected_versions = []
            for vuln in vulnerabilities:
                first_patched = vuln.get("first_patched_version")
                if first_patched:
                    patched_versions.append(first_patched)
                for version in vuln.get("versions", []):
                    if version.get("status") == "unaffected":
                        unaffected_versions.append(version.get("version"))
            
            return {
                "ghsa_id": ghsa_id,
                "cve_id": cve_id,
                "aliases": aliases,
                "summary": advisory_data.get("summary"),
                "description": advisory_data.get("description"),
                "severity": advisory_data.get("severity"),
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "cwe_ids": cwe_ids,
                "affected_packages": affected_packages,
                "patched_versions": patched_versions,
                "unaffected_versions": unaffected_versions,
                "references": references,
                "github_url": advisory_data.get("html_url"),
                "repository_url": advisory_data.get("source_code_location"),
                "published_at": self.parse_datetime(advisory_data.get("published_at")),
                "updated_at": self.parse_datetime(advisory_data.get("updated_at")),
                "withdrawn_at": self.parse_datetime(advisory_data.get("withdrawn_at")),
                "severity_updated_at": self.parse_datetime(advisory_data.get("github_reviewed_at")),
                "data_sources": ["github_advisory"],
            }
        except Exception as e:
            msg = f"Error parsing advisory {advisory_data.get('ghsa_id')}: {e}"
            print(msg)
            self.logger.error(msg)
            return None
    
    def parse_datetime(self, datetime_str: Optional[str]) -> Optional[datetime]:
        """解析ISO 8601格式的时间字符串"""
        if not datetime_str:
            return None
        
        try:
            return datetime.fromisoformat(datetime_str.replace("Z", "+00:00"))
        except Exception:
            return None
    
    def save_advisory_to_db(self, advisory_data: Dict) -> bool:
        """将GitHub Advisory保存到数据库"""
        db = SessionLocal()
        try:
            ghsa_id = advisory_data["ghsa_id"]
            
            existing = db.query(GitHubAdvisory).filter(
                GitHubAdvisory.ghsa_id == ghsa_id
            ).first()
            
            if existing:
                existing.cve_id = advisory_data["cve_id"]
                existing.aliases = advisory_data["aliases"]
                existing.summary = advisory_data["summary"]
                existing.description = advisory_data["description"]
                existing.severity = advisory_data["severity"]
                existing.cvss_score = advisory_data["cvss_score"]
                existing.cvss_vector = advisory_data["cvss_vector"]
                existing.cwe_ids = advisory_data["cwe_ids"]
                existing.affected_packages = advisory_data["affected_packages"]
                existing.patched_versions = advisory_data["patched_versions"]
                existing.unaffected_versions = advisory_data["unaffected_versions"]
                existing.references = advisory_data["references"]
                existing.github_url = advisory_data["github_url"]
                existing.repository_url = advisory_data["repository_url"]
                existing.published_at = advisory_data["published_at"]
                existing.updated_at = advisory_data["updated_at"]
                existing.withdrawn_at = advisory_data["withdrawn_at"]
                existing.severity_updated_at = advisory_data["severity_updated_at"]
                existing.data_sources = advisory_data["data_sources"]
            else:
                new_advisory = GitHubAdvisory(
                    ghsa_id=advisory_data["ghsa_id"],
                    cve_id=advisory_data["cve_id"],
                    aliases=advisory_data["aliases"],
                    summary=advisory_data["summary"],
                    description=advisory_data["description"],
                    severity=advisory_data["severity"],
                    cvss_score=advisory_data["cvss_score"],
                    cvss_vector=advisory_data["cvss_vector"],
                    cwe_ids=advisory_data["cwe_ids"],
                    affected_packages=advisory_data["affected_packages"],
                    patched_versions=advisory_data["patched_versions"],
                    unaffected_versions=advisory_data["unaffected_versions"],
                    references=advisory_data["references"],
                    github_url=advisory_data["github_url"],
                    repository_url=advisory_data["repository_url"],
                    published_at=advisory_data["published_at"],
                    updated_at=advisory_data["updated_at"],
                    withdrawn_at=advisory_data["withdrawn_at"],
                    severity_updated_at=advisory_data["severity_updated_at"],
                    data_sources=advisory_data["data_sources"],
                )
                db.add(new_advisory)
            
            db.commit()
            
            if advisory_data["cve_id"]:
                self._update_cve_severity(advisory_data["cve_id"], advisory_data["severity"], advisory_data["cvss_score"], db)
            
            return True
            
        except Exception as e:
            msg = f"Error saving {ghsa_id} to DB: {e}"
            print(msg)
            self.logger.error(msg)
            db.rollback()
            return False
        finally:
            db.close()
    
    def _update_cve_severity(self, cve_id: str, severity: str, cvss_score: float, db):
        """更新关联CVE的严重级别"""
        cve = db.query(CVE).filter(CVE.cve_id == cve_id).first()
        if cve:
            if severity and not cve.cvss_v3_severity:
                cve.cvss_v3_severity = severity
            if cvss_score and not cve.cvss_v3_score:
                cve.cvss_v3_score = cvss_score
            if "github_advisory" not in (cve.data_sources or []):
                current_sources = cve.data_sources or []
                current_sources.append("github_advisory")
                cve.data_sources = current_sources
    
    def sync_advisory(self, advisory_data: Dict) -> bool:
        """同步单个GitHub Advisory到数据库"""
        parsed = self.parse_advisory(advisory_data)
        
        if not parsed:
            return False
        
        if self.save_advisory_to_db(parsed):
            msg = f"✅ Successfully synced GHSA:{parsed['ghsa_id']}"
            if parsed['cve_id']:
                msg += f" (CVE:{parsed['cve_id']})"
            print(msg)
            self.logger.info(msg)
            return True
        
        return False
    
    def run_hourly_check(self, hours: int = 1):
        """执行一次小时检查"""
        msg = f"\n=== GitHub Advisory Check at {datetime.now()} (last {hours} hours) ==="
        print(msg)
        self.logger.info(msg)
        
        advisories = self.get_recent_advisories(hours=hours)
        
        if not advisories:
            msg = "No recent GitHub Advisory changes found"
            print(msg)
            self.logger.info(msg)
            return
        
        success_count = 0
        fail_count = 0
        
        for advisory in advisories:
            if self.sync_advisory(advisory):
                success_count += 1
            else:
                fail_count += 1
            
            time.sleep(0.3)
        
        msg = f"\nSync completed: {success_count} succeeded, {fail_count} failed"
        print(msg)
        self.logger.info(msg)
    
    def start_continuous_monitoring(self, interval_hours: int = 1):
        """启动持续监控"""
        msg = f"Starting GitHub Advisory hourly monitor (interval: {interval_hours} hours)"
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
    
    def full_sync(self, limit: int = None):
        """执行全量同步"""
        msg = "\n=== GitHub Advisory Full Sync ==="
        print(msg)
        self.logger.info(msg)
        
        url = f"{self.api_base}/advisories"
        params = {
            "per_page": 100,
            "direction": "desc",
            "sort": "updated"
        }
        
        page = 1
        total_added = 0
        total_updated = 0
        
        try:
            while True:
                params["page"] = page
                response = requests.get(url, params=params, headers=self.headers, timeout=30)
                response.raise_for_status()
                
                data = response.json()
                if not data:
                    break
                
                for advisory in data:
                    parsed = self.parse_advisory(advisory)
                    if parsed:
                        db = SessionLocal()
                        try:
                            existing = db.query(GitHubAdvisory).filter(
                                GitHubAdvisory.ghsa_id == parsed["ghsa_id"]
                            ).first()
                            
                            if existing:
                                total_updated += 1
                            else:
                                total_added += 1
                            
                            self.save_advisory_to_db(parsed)
                        finally:
                            db.close()
                
                if limit and (total_added + total_updated) >= limit:
                    break
                
                if len(data) < 100:
                    break
                
                page += 1
                time.sleep(0.5)
            
            msg = f"\nFull sync completed: {total_added} added, {total_updated} updated"
            print(msg)
            self.logger.info(msg)
            
        except Exception as e:
            msg = f"Error during full sync: {e}"
            print(msg)
            self.logger.error(msg)


def main():
    token = os.getenv("GITHUB_TOKEN")
    monitor = GitHubAdvisoryMonitor(token=token)
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "--continuous":
            monitor.start_continuous_monitoring()
        elif sys.argv[1] == "--hours":
            if len(sys.argv) > 2:
                try:
                    hours = int(sys.argv[2])
                    monitor.run_hourly_check(hours=hours)
                except ValueError:
                    print("Usage: python github_advisory_monitor.py --hours <number>")
            else:
                print("Usage: python github_advisory_monitor.py --hours <number>")
        elif sys.argv[1] == "--full":
            if len(sys.argv) > 2:
                try:
                    limit = int(sys.argv[2])
                    monitor.full_sync(limit=limit)
                except ValueError:
                    print("Usage: python github_advisory_monitor.py --full <limit>")
            else:
                monitor.full_sync()
        else:
            print("Usage:")
            print("  python github_advisory_monitor.py                 # 同步最近1小时")
            print("  python github_advisory_monitor.py --continuous    # 持续监控模式")
            print("  python github_advisory_monitor.py --hours <n>     # 同步最近n小时")
            print("  python github_advisory_monitor.py --full [limit]  # 全量同步")
    else:
        monitor.run_hourly_check()


if __name__ == "__main__":
    main()