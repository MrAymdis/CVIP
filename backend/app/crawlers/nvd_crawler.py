"""
NVD (National Vulnerability Database) Crawler
Fetches CVE data from NVD API 2.0
"""
import httpx
import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models import CVE, Vendor, Product

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDCrawler:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.headers = {}
        if api_key:
            self.headers["apiKey"] = api_key
    
    async def fetch_cves(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        results_per_page: int = 2000
    ) -> List[Dict[str, Any]]:
        """Fetch CVEs from NVD API."""
        all_cves = []
        start_index = 0
        
        async with httpx.AsyncClient() as client:
            while True:
                params = {
                    "resultsPerPage": results_per_page,
                    "startIndex": start_index,
                }
                
                if start_date:
                    params["pubStartDate"] = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
                if end_date:
                    params["pubEndDate"] = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
                
                try:
                    response = await client.get(
                        NVD_API_BASE,
                        params=params,
                        headers=self.headers,
                        timeout=60.0
                    )
                    response.raise_for_status()
                    data = response.json()
                    
                    vulnerabilities = data.get("vulnerabilities", [])
                    if not vulnerabilities:
                        break
                    
                    all_cves.extend(vulnerabilities)
                    
                    # Check if we've fetched all results
                    total_results = data.get("totalResults", 0)
                    if start_index + len(vulnerabilities) >= total_results:
                        break
                    
                    start_index += results_per_page
                    
                    # Rate limiting - NVD allows 5 requests per 30 seconds without API key
                    if not self.api_key:
                        await asyncio.sleep(6)
                    else:
                        await asyncio.sleep(0.1)
                        
                except httpx.HTTPError as e:
                    print(f"HTTP error fetching CVEs: {e}")
                    break
                except Exception as e:
                    print(f"Error fetching CVEs: {e}")
                    break
        
        return all_cves
    
    def parse_cvss(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse CVSS scores from CVE data."""
        metrics = cve_data.get("metrics", {})
        result = {
            "cvss_v3_score": None,
            "cvss_v3_severity": None,
            "cvss_v3_vector": None,
            "cvss_v4_score": None,
            "cvss_v4_severity": None,
            "cvss_v4_vector": None,
        }
        
        # CVSS v3
        cvss_v3 = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
        if cvss_v3:
            cvss_data = cvss_v3[0].get("cvssData", {})
            result["cvss_v3_score"] = cvss_data.get("baseScore")
            result["cvss_v3_severity"] = cvss_data.get("baseSeverity")
            result["cvss_v3_vector"] = cvss_data.get("vectorString")
        
        # CVSS v4
        cvss_v4 = metrics.get("cvssMetricV40", [])
        if cvss_v4:
            cvss_data = cvss_v4[0].get("cvssData", {})
            result["cvss_v4_score"] = cvss_data.get("baseScore")
            result["cvss_v4_severity"] = cvss_data.get("baseSeverity")
            result["cvss_v4_vector"] = cvss_data.get("vectorString")
        
        return result
    
    def parse_cwe(self, cve_data: Dict[str, Any]) -> List[str]:
        """Parse CWE IDs from CVE data."""
        weaknesses = cve_data.get("weaknesses", [])
        cwes = []
        for weakness in weaknesses:
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en" and desc.get("value", "").startswith("CWE-"):
                    cwes.append(desc["value"])
        return list(set(cwes))
    
    def parse_vendor_product(self, cve_data: Dict[str, Any]) -> tuple:
        """Parse vendor and product from CVE data."""
        configurations = cve_data.get("configurations", [])
        vendors = set()
        products = set()
        
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable"):
                        criteria = cpe_match.get("criteria", "")
                        # Parse CPE URI: cpe:2.3:a:vendor:product:version...
                        parts = criteria.split(":")
                        if len(parts) >= 5:
                            vendors.add(parts[3])
                            products.add(parts[4])
        
        return list(vendors), list(products)
    
    def save_to_db(self, cves: List[Dict[str, Any]], db: Session):
        """Save CVEs to database."""
        for vuln in cves:
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "")
            
            # Check if CVE already exists
            existing = db.query(CVE).filter(CVE.cve_id == cve_id).first()
            if existing:
                continue
            
            # Parse CVSS
            cvss_data = self.parse_cvss(cve_data)
            
            # Parse CWEs
            cwes = self.parse_cwe(cve_data)
            
            # Parse vendor/product
            vendors, products = self.parse_vendor_product(cve_data)
            vendor_name = vendors[0] if vendors else None
            product_name = products[0] if products else None
            
            # Get or create vendor
            vendor = None
            if vendor_name:
                vendor = db.query(Vendor).filter(Vendor.name == vendor_name).first()
                if not vendor:
                    vendor = Vendor(name=vendor_name)
                    db.add(vendor)
                    db.flush()
            
            # Get or create product
            product = None
            if product_name:
                product = db.query(Product).filter(
                    Product.name == product_name,
                    Product.vendor_id == vendor.id if vendor else None
                ).first()
                if not product:
                    product = Product(name=product_name, vendor_id=vendor.id if vendor else None)
                    db.add(product)
                    db.flush()
            
            # Parse dates
            published = cve_data.get("published")
            modified = cve_data.get("lastModified")
            
            # Create CVE
            cve = CVE(
                cve_id=cve_id,
                title=cve_data.get("descriptions", [{}])[0].get("value", "")[:500],
                description=cve_data.get("descriptions", [{}])[0].get("value", ""),
                **cvss_data,
                cwes=cwes,
                vendor_id=vendor.id if vendor else None,
                product_id=product.id if product else None,
                published_date=datetime.fromisoformat(published.replace("Z", "+00:00")) if published else None,
                modified_date=datetime.fromisoformat(modified.replace("Z", "+00:00")) if modified else None,
                data_sources=["nvd"],
            )
            db.add(cve)
        
        db.commit()
    
    async def sync_recent(self, days: int = 7):
        """Sync recent CVEs."""
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        print(f"Fetching CVEs from {start_date} to {end_date}")
        cves = await self.fetch_cves(start_date, end_date)
        print(f"Fetched {len(cves)} CVEs")
        
        if cves:
            db = SessionLocal()
            try:
                self.save_to_db(cves, db)
                print(f"Saved CVEs to database")
            finally:
                db.close()
        
        return len(cves)


if __name__ == "__main__":
    crawler = NVDCrawler()
    asyncio.run(crawler.sync_recent(days=30))
