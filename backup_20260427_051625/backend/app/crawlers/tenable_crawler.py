"""
Tenable Crawler
Fetches vulnerability data from Tenable's public vulnerability database.

Tenable provides comprehensive vulnerability intelligence including:
- CVE information
- CVSS scores
- vulnerability descriptions
- affected products
"""
import httpx
import asyncio
import re
from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models import CVE, Reference


class TenableCrawler:
    def __init__(self):
        self.base_url = "https://www.tenable.com"
        self.vuln_search_url = "https://www.tenable.com/cve"
    
    async def check_plugins(self, cve_id: str) -> Optional[str]:
        """Check if CVE has Tenable plugins and return the URL if found."""
        plugins_url = f"{self.vuln_search_url}/{cve_id}/plugins"
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    plugins_url,
                    timeout=30.0,
                    follow_redirects=True,
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
                    }
                )
                response.raise_for_status()
                html = response.text
                
                # Check if plugins exist (not "No plugins found")
                if "No plugins found for this CVE" not in html:
                    return plugins_url
                else:
                    return None
            except httpx.HTTPError as e:
                print(f"HTTP error checking plugins for {cve_id}: {e}")
                return None
            except Exception as e:
                print(f"Error checking plugins for {cve_id}: {e}")
                return None
    
    async def fetch_vulnerability_page(self, cve_id: str) -> str:
        """Fetch Tenable vulnerability page for a specific CVE."""
        url = f"{self.vuln_search_url}/{cve_id}"
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    url,
                    timeout=30.0,
                    follow_redirects=True,
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
                    }
                )
                response.raise_for_status()
                return response.text
            except httpx.HTTPError as e:
                print(f"HTTP error fetching Tenable CVE {cve_id}: {e}")
                return ""
            except Exception as e:
                print(f"Error fetching Tenable CVE {cve_id}: {e}")
                return ""
    
    def parse_vulnerability_page(self, html_content: str, cve_id: str) -> Optional[Dict[str, Any]]:
        """Parse Tenable vulnerability page HTML."""
        if not html_content:
            return None
        
        try:
            data = {
                "cve_id": cve_id,
                "title": "",
                "description": "",
                "cvss_v3_score": None,
                "cvss_v3_severity": None,
                "references": []
            }
            
            # Extract title
            title_match = re.search(
                r'<h1[^>]*class="[^"]*title[^"]*"[^>]*>([^<]+)</h1>',
                html_content,
                re.DOTALL
            )
            if title_match:
                data["title"] = title_match.group(1).strip()
            
            # Extract description
            desc_match = re.search(
                r'<div[^>]*class="[^"]*description[^"]*"[^>]*>(.*?)</div>',
                html_content,
                re.DOTALL
            )
            if desc_match:
                # Clean HTML tags
                description = re.sub(r'<[^>]+>', '', desc_match.group(1))
                data["description"] = description.strip()
            
            # Extract CVSS score
            cvss_match = re.search(
                r'CVSS:3\.[01] ([0-9.]+)',
                html_content
            )
            if cvss_match:
                try:
                    data["cvss_v3_score"] = float(cvss_match.group(1))
                except ValueError:
                    pass
            
            # Extract severity
            severity_match = re.search(
                r'<span[^>]*class="[^"]*severity[^"]*"[^>]*>([^<]+)</span>',
                html_content,
                re.IGNORECASE
            )
            if severity_match:
                severity = severity_match.group(1).strip().upper()
                data["cvss_v3_severity"] = severity
            
            # Extract references
            ref_pattern = r'<a[^>]*href="([^"]+)"[^>]*class="[^"]*reference[^"]*"[^>]*>([^<]+)</a>'
            references = re.findall(ref_pattern, html_content)
            for url, name in references:
                if url and url.startswith(('http://', 'https://')):
                    data["references"].append({
                        "url": url,
                        "title": name.strip()
                    })
            
            return data
        except Exception as e:
            print(f"Error parsing Tenable page: {e}")
            return None
    
    async def fetch_recent_cves(self, limit: int = 100) -> List[str]:
        """Fetch recent CVE IDs from Tenable."""
        url = "https://www.tenable.com/research"
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    url,
                    timeout=30.0,
                    follow_redirects=True,
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                    }
                )
                response.raise_for_status()
                html = response.text
                
                # Extract CVE IDs from the page
                cve_pattern = r'CVE-\d{4}-\d{4,7}'
                cve_ids = re.findall(cve_pattern, html)
                
                # Remove duplicates and limit
                unique_cves = list(set(cve_ids))[:limit]
                return unique_cves
            except Exception as e:
                print(f"Error fetching recent CVEs from Tenable: {e}")
                return []
    
    def save_to_db(self, vuln_data: Dict[str, Any], db: Session, plugins_url: Optional[str] = None) -> int:
        """Save vulnerability data to database."""
        cve_id = vuln_data.get("cve_id")
        if not cve_id:
            return 0
        
        added = 0
        
        try:
            # Find or create CVE
            cve = db.query(CVE).filter(CVE.cve_id == cve_id).first()
            
            if cve:
                # Update existing CVE if we have better data
                if vuln_data.get("title") and not cve.title:
                    cve.title = vuln_data["title"]
                if vuln_data.get("description") and not cve.description:
                    cve.description = vuln_data["description"]
                if vuln_data.get("cvss_v3_score") and not cve.cvss_v3_score:
                    cve.cvss_v3_score = vuln_data["cvss_v3_score"]
                if vuln_data.get("cvss_v3_severity") and not cve.cvss_v3_severity:
                    cve.cvss_v3_severity = vuln_data["cvss_v3_severity"]
            else:
                # Create new CVE
                cve = CVE(
                    cve_id=cve_id,
                    title=vuln_data.get("title"),
                    description=vuln_data.get("description"),
                    cvss_v3_score=vuln_data.get("cvss_v3_score"),
                    cvss_v3_severity=vuln_data.get("cvss_v3_severity"),
                    data_sources=["tenable"]
                )
                db.add(cve)
                added += 1
            
            # Save references from vulnerability page
            for ref in vuln_data.get("references", []):
                existing_ref = db.query(Reference).filter(
                    Reference.cve_id == cve_id,
                    Reference.url == ref["url"]
                ).first()
                if not existing_ref:
                    reference = Reference(
                        cve_id=cve_id,
                        url=ref["url"],
                        title=ref.get("title"),
                        source="tenable"
                    )
                    db.add(reference)
                    added += 1
            
            # Save plugins URL as reference if it exists
            if plugins_url:
                existing_plugin_ref = db.query(Reference).filter(
                    Reference.cve_id == cve_id,
                    Reference.url == plugins_url
                ).first()
                if not existing_plugin_ref:
                    reference = Reference(
                        cve_id=cve_id,
                        url=plugins_url,
                        title="Tenable Detection Plugins",
                        source="tenable",
                        ref_type="plugin"
                    )
                    db.add(reference)
                    added += 1
                    print(f"  Added Tenable plugins reference: {plugins_url}")
            
            db.commit()
            return added
        except Exception as e:
            db.rollback()
            print(f"Error saving Tenable data for {cve_id}: {e}")
            return 0
    
    async def sync(self, limit: int = 100) -> int:
        """Sync Tenable vulnerability data."""
        print("=" * 80)
        print("Tenable Crawler - Starting sync")
        print("=" * 80)
        
        total_added = 0
        
        # Get recent CVE IDs
        print("Fetching recent CVE IDs from Tenable...")
        cve_ids = await self.fetch_recent_cves(limit=limit)
        print(f"Found {len(cve_ids)} CVE IDs")
        
        if not cve_ids:
            print("No CVE IDs found")
            return 0
        
        # Fetch and save each CVE
        db = SessionLocal()
        try:
            for i, cve_id in enumerate(cve_ids, 1):
                print(f"\nProcessing {i}/{len(cve_ids)}: {cve_id}")
                
                # Check for Tenable plugins
                plugins_url = await self.check_plugins(cve_id)
                if plugins_url:
                    print(f"  Found Tenable plugins: {plugins_url}")
                else:
                    print(f"  No Tenable plugins found")
                
                html = await self.fetch_vulnerability_page(cve_id)
                if html:
                    vuln_data = self.parse_vulnerability_page(html, cve_id)
                    if vuln_data:
                        added = self.save_to_db(vuln_data, db, plugins_url)
                        total_added += added
                        if added > 0:
                            print(f"  Added {added} records")
                        else:
                            print(f"  No new records (already exists or no data)")
                else:
                    print(f"  Failed to fetch data")
                
                # Add delay to avoid rate limiting
                await asyncio.sleep(1)
            
            db.commit()
        finally:
            db.close()
        
        print("\n" + "=" * 80)
        print(f"Tenable sync completed. Total added: {total_added}")
        print("=" * 80)
        
        return total_added


if __name__ == "__main__":
    crawler = TenableCrawler()
    asyncio.run(crawler.sync(limit=50))