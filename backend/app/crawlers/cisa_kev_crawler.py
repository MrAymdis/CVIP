"""
CISA KEV (Known Exploited Vulnerabilities) Catalog Crawler
Fetches CISA KEV data from official JSON feed
"""
import httpx
import asyncio
from datetime import datetime
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models import CVE

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CISAKEVCrawler:
    def __init__(self):
        pass
    
    async def fetch_kev_catalog(self) -> Dict[str, Any]:
        """Fetch CISA KEV catalog."""
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    CISA_KEV_URL,
                    timeout=60.0
                )
                response.raise_for_status()
                return response.json()
            except httpx.HTTPError as e:
                print(f"HTTP error fetching CISA KEV: {e}")
                return {}
            except Exception as e:
                print(f"Error fetching CISA KEV: {e}")
                return {}
    
    def parse_date(self, date_str: str) -> datetime:
        """Parse date string to datetime."""
        try:
            # Try different date formats
            for fmt in ["%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y"]:
                try:
                    return datetime.strptime(date_str, fmt)
                except ValueError:
                    continue
        except Exception:
            pass
        return None
    
    def save_to_db(self, vulnerabilities: List[Dict[str, Any]], db: Session):
        """Save CISA KEV data to database."""
        updated = 0
        
        for vuln in vulnerabilities:
            cve_id = vuln.get("cveID")
            if not cve_id or not cve_id.startswith("CVE-"):
                continue
            
            # Find CVE
            cve = db.query(CVE).filter(CVE.cve_id == cve_id).first()
            if cve:
                cve.cisa_kev = True
                cve.cisa_kev_date_added = self.parse_date(vuln.get("dateAdded", ""))
                cve.cisa_due_date = self.parse_date(vuln.get("dueDate", ""))
                cve.cisa_required_action = vuln.get("requiredAction", "")
                updated += 1
            else:
                # Create CVE if not exists
                cve = CVE(
                    cve_id=cve_id,
                    title=vuln.get("vulnerabilityName", ""),
                    description=vuln.get("shortDescription", ""),
                    cisa_kev=True,
                    cisa_kev_date_added=self.parse_date(vuln.get("dateAdded", "")),
                    cisa_due_date=self.parse_date(vuln.get("dueDate", "")),
                    cisa_required_action=vuln.get("requiredAction", ""),
                    published_date=self.parse_date(vuln.get("dateAdded", "")),
                    data_sources=["cisa_kev"],
                )
                db.add(cve)
                updated += 1
        
        db.commit()
        return updated
    
    async def sync(self):
        """Sync CISA KEV catalog."""
        print("Fetching CISA KEV catalog")
        data = await self.fetch_kev_catalog()
        
        vulnerabilities = data.get("vulnerabilities", [])
        print(f"Fetched {len(vulnerabilities)} KEV entries")
        
        if vulnerabilities:
            db = SessionLocal()
            try:
                updated = self.save_to_db(vulnerabilities, db)
                print(f"Updated {updated} CVEs with CISA KEV data")
            finally:
                db.close()
        
        return len(vulnerabilities)


if __name__ == "__main__":
    crawler = CISAKEVCrawler()
    asyncio.run(crawler.sync())
