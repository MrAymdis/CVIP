"""
CNNVD (中国国家信息安全漏洞库) Crawler
Fetches CVE data from CNNVD
"""
import httpx
import asyncio
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models import CVE

CNNVD_API_BASE = "https://www.cnnvd.org.cn/web/homePage/cnnvdVulList"


class CNNVDCrawler:
    def __init__(self):
        self.headers = {
            "Content-Type": "application/json;charset=UTF-8",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Referer": "https://www.cnnvd.org.cn/web/vulnerability/queryLds.tag",
            "Origin": "https://www.cnnvd.org.cn",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        }

    async def fetch_vulnerabilities(
        self,
        page_index: int = 1,
        page_size: int = 20
    ) -> List[Dict[str, Any]]:
        """Fetch vulnerabilities from CNNVD API."""
        all_vulns = []
        
        async with httpx.AsyncClient() as client:
            payload = {
                "pageIndex": page_index,
                "pageSize": page_size,
                "keyword": "",
                "hazardLevel": "",
                "vulType": "",
                "vendor": "",
            }
            
            try:
                response = await client.post(
                    CNNVD_API_BASE,
                    json=payload,
                    headers=self.headers,
                    timeout=60.0
                )
                response.raise_for_status()
                data = response.json()
                
                if data.get("code") == 200:
                    all_vulns = data.get("data", {}).get("records", [])
                    
            except httpx.HTTPError as e:
                print(f"HTTP error fetching vulnerabilities: {e}")
            except Exception as e:
                print(f"Error fetching vulnerabilities: {e}")
        
        return all_vulns

    async def fetch_and_parse_batch(
        self,
        max_pages: int = 10,
        page_size: int = 20
    ) -> List[Dict[str, Any]]:
        """Fetch and parse multiple pages of vulnerabilities."""
        all_vulnerabilities = []
        
        for page in range(1, max_pages + 1):
            print(f"Fetching page {page}/{max_pages}")
            vulns = await self.fetch_vulnerabilities(page_index=page, page_size=page_size)
            
            if not vulns:
                break
            
            for vuln in vulns:
                cnnvd_id = vuln.get("cnnvdCode", "")
                cve_id = vuln.get("cveCode", "")
                title_zh = vuln.get("vulName", "")
                
                if cnnvd_id and cve_id:
                    vulnerability = {
                        "cnnvd_id": cnnvd_id,
                        "cve_id": cve_id,
                        "title_zh": title_zh,
                        "description_zh": "",
                    }
                    all_vulnerabilities.append(vulnerability)
            
            await asyncio.sleep(0.5)
        
        return all_vulnerabilities

    def update_cve_in_db(self, vulnerabilities: List[Dict[str, Any]], db: Session):
        """Update CVE records in database with Chinese information."""
        updated_count = 0
        
        for vuln in vulnerabilities:
            cve_id = vuln.get("cve_id")
            if not cve_id:
                continue
            
            existing_cve = db.query(CVE).filter(CVE.cve_id == cve_id).first()
            
            if existing_cve:
                title_zh = vuln.get("title_zh", "")
                description_zh = vuln.get("description_zh", "")
                
                if title_zh:
                    existing_cve.title_zh = title_zh[:500]
                
                if description_zh:
                    existing_cve.description_zh = description_zh
                
                data_sources = existing_cve.data_sources or []
                if "cnnvd" not in data_sources:
                    data_sources.append("cnnvd")
                    existing_cve.data_sources = data_sources
                
                updated_count += 1
        
        db.commit()
        return updated_count

    async def sync_cnnvd_data(self, max_records: int = 100):
        """Sync CNNVD data to update CVE Chinese information."""
        page_size = 20
        max_pages = (max_records + page_size - 1) // page_size
        
        print(f"Fetching CNNVD data, targeting {max_records} records...")
        vulnerabilities = await self.fetch_and_parse_batch(max_pages=max_pages, page_size=page_size)
        
        print(f"Fetched {len(vulnerabilities)} vulnerabilities with CVE IDs from CNNVD")
        
        if vulnerabilities:
            db = SessionLocal()
            try:
                updated_count = self.update_cve_in_db(vulnerabilities, db)
                print(f"Updated {updated_count} CVE records in database")
                return updated_count
            finally:
                db.close()
        
        return 0


if __name__ == "__main__":
    crawler = CNNVDCrawler()
    asyncio.run(crawler.sync_cnnvd_data(max_records=100))
