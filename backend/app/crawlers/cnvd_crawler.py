"""
CNVD (China National Vulnerability Database) Crawler
Fetches vulnerability data from CNVD website
"""
import httpx
import asyncio
import re
from datetime import datetime
from typing import List, Dict, Any, Optional
from bs4 import BeautifulSoup
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models import CVE

CNVD_BASE_URL = "https://www.cnvd.org.cn"
CNVD_VULN_LIST_URL = "https://www.cnvd.org.cn/flaw/list.htm"


class CNVDCrawler:
    def __init__(self):
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Referer": CNVD_BASE_URL,
        }
    
    async def fetch_vulnerability_list(
        self,
        page: int = 1,
        max_pages: int = 10
    ) -> List[Dict[str, Any]]:
        """Fetch vulnerability list from CNVD."""
        all_vulns = []
        
        async with httpx.AsyncClient(follow_redirects=True) as client:
            for current_page in range(page, page + max_pages):
                print(f"Fetching page {current_page}...")
                
                try:
                    params = {
                        "page": current_page
                    }
                    
                    response = await client.get(
                        CNVD_VULN_LIST_URL,
                        params=params,
                        headers=self.headers,
                        timeout=30.0
                    )
                    
                    if response.status_code != 200:
                        print(f"Failed to fetch page {current_page}, status code: {response.status_code}")
                        break
                    
                    vulns = self.parse_vulnerability_list(response.text)
                    
                    if not vulns:
                        print(f"No vulnerabilities found on page {current_page}")
                        break
                    
                    all_vulns.extend(vulns)
                    print(f"Found {len(vulns)} vulnerabilities on page {current_page}")
                    
                    await asyncio.sleep(2)
                    
                except httpx.HTTPError as e:
                    print(f"HTTP error fetching page {current_page}: {e}")
                    break
                except Exception as e:
                    print(f"Error fetching page {current_page}: {e}")
                    break
        
        return all_vulns
    
    def parse_vulnerability_list(self, html: str) -> List[Dict[str, Any]]:
        """Parse vulnerability list from HTML."""
        vulns = []
        soup = BeautifulSoup(html, 'html.parser')
        
        table = soup.find('table', class_='tlist')
        if not table:
            return vulns
        
        rows = table.find_all('tr')[1:]  # Skip header row
        
        for row in rows:
            cols = row.find_all('td')
            if len(cols) < 4:
                continue
            
            # Extract CNVD ID and title
            title_link = cols[0].find('a')
            if title_link:
                cnvd_id = title_link.get_text(strip=True)
                title = title_link.get('title', cnvd_id)
                detail_url = title_link.get('href', '')
                if detail_url and not detail_url.startswith('http'):
                    detail_url = CNVD_BASE_URL + detail_url
            else:
                continue
            
            # Extract severity
            severity_span = cols[1].find('span')
            severity = severity_span.get_text(strip=True) if severity_span else ''
            
            # Extract publish date
            date_str = cols[3].get_text(strip=True)
            
            vulns.append({
                'cnvd_id': cnvd_id,
                'title_zh': title,
                'severity': severity,
                'publish_date_str': date_str,
                'detail_url': detail_url
            })
        
        return vulns
    
    async def fetch_vulnerability_detail(self, url: str) -> Optional[Dict[str, Any]]:
        """Fetch and parse vulnerability detail page."""
        async with httpx.AsyncClient(follow_redirects=True) as client:
            try:
                response = await client.get(
                    url,
                    headers=self.headers,
                    timeout=30.0
                )
                
                if response.status_code != 200:
                    print(f"Failed to fetch detail page {url}, status code: {response.status_code}")
                    return None
                
                return self.parse_vulnerability_detail(response.text)
                
            except httpx.HTTPError as e:
                print(f"HTTP error fetching detail {url}: {e}")
                return None
            except Exception as e:
                print(f"Error fetching detail {url}: {e}")
                return None
    
    def parse_vulnerability_detail(self, html: str) -> Dict[str, Any]:
        """Parse vulnerability detail from HTML."""
        result = {
            'description_zh': '',
            'cve_ids': []
        }
        
        soup = BeautifulSoup(html, 'html.parser')
        
        # Extract description
        desc_div = soup.find('div', class_='blkContainer')
        if desc_div:
            desc_text = desc_div.get_text(strip=True)
            result['description_zh'] = desc_text
        
        # Extract CVE IDs
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cve_ids = re.findall(cve_pattern, html, re.IGNORECASE)
        result['cve_ids'] = list(set([cve.upper() for cve in cve_ids]))
        
        return result
    
    def parse_date(self, date_str: str) -> Optional[datetime]:
        """Parse date string to datetime."""
        if not date_str:
            return None
        try:
            return datetime.strptime(date_str, "%Y-%m-%d")
        except ValueError:
            pass
        return None
    
    def update_cve_chinese_info(self, cve: CVE, title_zh: str, description_zh: str):
        """Update CVE's Chinese information."""
        if title_zh and not cve.title_zh:
            cve.title_zh = title_zh[:500]
        
        if description_zh and not cve.description_zh:
            cve.description_zh = description_zh
        
        if 'cnvd' not in cve.data_sources:
            cve.data_sources = list(cve.data_sources) + ['cnvd'] if cve.data_sources else ['cnvd']
    
    async def sync(self, limit: int = 100, max_pages: int = 10):
        """Sync CNVD vulnerability data."""
        print(f"Starting CNVD crawler, limit: {limit}")
        
        all_vulns = await self.fetch_vulnerability_list(page=1, max_pages=max_pages)
        print(f"Total {len(all_vulns)} vulnerabilities found in list")
        
        updated_count = 0
        if all_vulns:
            db = SessionLocal()
            try:
                for i, vuln in enumerate(all_vulns):
                    if updated_count >= limit:
                        break
                    
                    print(f"Processing {i+1}/{len(all_vulns)}: {vuln['cnvd_id']}")
                    
                    detail = await self.fetch_vulnerability_detail(vuln['detail_url'])
                    
                    if detail and detail['cve_ids']:
                        for cve_id in detail['cve_ids']:
                            cve = db.query(CVE).filter(CVE.cve_id == cve_id).first()
                            
                            if cve:
                                self.update_cve_chinese_info(
                                    cve,
                                    vuln['title_zh'],
                                    detail['description_zh']
                                )
                                updated_count += 1
                                print(f"  Updated CVE {cve_id}")
                            
                            await asyncio.sleep(1)
                    
                    await asyncio.sleep(1)
                
                db.commit()
                print(f"Updated {updated_count} CVE records from CNVD")
                
            except Exception as e:
                db.rollback()
                print(f"Error syncing CNVD data: {e}")
            finally:
                db.close()
        
        return updated_count


if __name__ == "__main__":
    crawler = CNVDCrawler()
    asyncio.run(crawler.sync(limit=100))
