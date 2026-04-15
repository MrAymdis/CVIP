"""
CVEProject/cvelistV5 Crawler V2
适配 CVE JSON 5.1 格式，支持选择性导入特定年份数据
"""
import json
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models import CVE, Vendor, Product, Reference, Exploit


class CVEListV5CrawlerV2:
    """改进版 Crawler for CVEProject/cvelistV5 repository"""

    def __init__(self, repo_path: Optional[str] = None):
        """
        Initialize crawler

        Args:
            repo_path: Path to cvelistV5 repository. If None, will use default path.
        """
        if repo_path is None:
            backend_dir = Path(__file__).parent.parent.parent
            self.repo_path = backend_dir / "cvelistV5"
        else:
            self.repo_path = Path(repo_path)

        self.cves_dir = self.repo_path / "cves"
        self.delta_file = self.cves_dir / "delta.json"

    def get_available_years(self) -> List[int]:
        """获取可用的年份列表"""
        if not self.cves_dir.exists():
            return []

        years = []
        for d in self.cves_dir.iterdir():
            if d.is_dir() and d.name.isdigit():
                years.append(int(d.name))
        return sorted(years, reverse=True)

    def parse_cvss(self, metrics: List[Dict]) -> Dict[str, Any]:
        """Parse CVSS scores from metrics - 适配 CVE JSON 5.1 格式"""
        result = {
            "cvss_v3_score": None,
            "cvss_v3_severity": None,
            "cvss_v3_vector": None,
            "cvss_v4_score": None,
            "cvss_v4_severity": None,
            "cvss_v4_vector": None,
        }

        if not metrics:
            return result

        for metric in metrics:
            # 处理 cvssV3_1
            if "cvssV3_1" in metric:
                cvss_data = metric["cvssV3_1"]
                result["cvss_v3_score"] = cvss_data.get("baseScore")
                result["cvss_v3_severity"] = cvss_data.get("baseSeverity")
                vector = cvss_data.get("vectorString", "")
                result["cvss_v3_vector"] = vector[:200] if len(vector) > 200 else vector

            # 处理 cvssV3_0
            elif "cvssV3_0" in metric:
                cvss_data = metric["cvssV3_0"]
                result["cvss_v3_score"] = cvss_data.get("baseScore")
                result["cvss_v3_severity"] = cvss_data.get("baseSeverity")
                vector = cvss_data.get("vectorString", "")
                result["cvss_v3_vector"] = vector[:200] if len(vector) > 200 else vector

            # 处理 cvssV4_0
            elif "cvssV4_0" in metric:
                cvss_data = metric["cvssV4_0"]
                result["cvss_v4_score"] = cvss_data.get("baseScore")
                result["cvss_v4_severity"] = cvss_data.get("baseSeverity")
                vector = cvss_data.get("vectorString", "")
                result["cvss_v4_vector"] = vector[:200] if len(vector) > 200 else vector

        return result

    def parse_cwe(self, problem_types: List[Dict]) -> List[str]:
        """Parse CWE IDs from problem types"""
        cwes = []
        if not problem_types:
            return cwes

        for pt in problem_types:
            descriptions = pt.get("descriptions", [])
            for desc in descriptions:
                cwe_id = desc.get("cweId", "")
                if cwe_id and cwe_id.startswith("CWE-"):
                    cwes.append(cwe_id)
        return list(set(cwes))

    def parse_affected_versions(self, affected: List[Dict]) -> List[Dict]:
        """Parse affected versions from affected list"""
        result = []

        if not affected:
            return result

        for item in affected:
            vendor = item.get("vendor")
            product = item.get("product")
            versions = item.get("versions", [])
            
            # Parse versions
            version_list = []
            for v in versions:
                version_list.append({
                    "version": v.get("version"),
                    "status": v.get("status", "affected")
                })
            
            if vendor or product:
                result.append({
                    "vendor": vendor,
                    "product": product,
                    "versions": version_list
                })

        return result

    def parse_references(self, references: List[Dict]) -> List[Dict]:
        """Parse references from CNA container"""
        result = []
        if not references:
            return result
        
        for ref in references:
            ref_url = ref.get("url") or ref.get("name")
            if not ref_url:
                continue
                
            ref_item = {
                "url": ref_url,
                "title": ref.get("name"),
                "tags": ref.get("tags", []),
                "source": "cvelistv5"
            }
            result.append(ref_item)
        
        return result

    def save_references_to_db(self, cve_id: str, references: List[Dict], db: Session) -> bool:
        """Save references to database"""
        try:
            # Delete existing references for this CVE
            db.query(Reference).filter(Reference.cve_id == cve_id).delete()
            
            # Add new references
            for ref in references:
                reference = Reference(
                    cve_id=cve_id,
                    url=ref.get("url")[:500] if ref.get("url") else "",
                    title=ref.get("title")[:500] if ref.get("title") else None,
                    tags=ref.get("tags", []),
                    source=ref.get("source", "cvelistv5"),
                )
                db.add(reference)
            
            return True
        except Exception as e:
            print(f"Error saving references for {cve_id}: {e}")
            db.rollback()
            return False

    def parse_vendor_product(self, affected: List[Dict]) -> Tuple[Optional[str], Optional[str]]:
        """Parse vendor and product from affected list"""
        vendors = set()
        products = set()

        if not affected:
            return None, None

        for item in affected:
            vendor = item.get("vendor")
            product = item.get("product")

            if vendor:
                vendors.add(vendor)
            if product:
                products.add(product)

        # Return first vendor and product
        vendor = list(vendors)[0] if vendors else None
        product = list(products)[0] if products else None

        return vendor, product

    def parse_cve_json(self, cve_data: Dict) -> Optional[Dict[str, Any]]:
        """Parse CVE JSON 5.1 format and extract relevant fields"""
        try:
            cve_metadata = cve_data.get("cveMetadata", {})
            containers = cve_data.get("containers", {})
            cna_container = containers.get("cna", {})

            cve_id = cve_metadata.get("cveId")
            if not cve_id:
                return None
            
            # Skip REJECTED CVEs
            cve_state = cve_metadata.get("state")
            if cve_state == "REJECTED":
                return None

            # Parse dates
            date_published = cve_metadata.get("datePublished")
            date_updated = cve_metadata.get("dateUpdated")

            # Parse title (可能不存在，使用描述前500字符作为标题)
            title = cna_container.get("title", "")

            # Parse description
            descriptions = cna_container.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # 如果没有标题，使用描述的前500字符
            if not title and description:
                title = description[:500]

            # Parse CVSS
            metrics = cna_container.get("metrics", [])
            cvss_data = self.parse_cvss(metrics)

            # Parse CWEs
            problem_types = cna_container.get("problemTypes", [])
            cwes = self.parse_cwe(problem_types)

            # Parse vendor and product
            affected = cna_container.get("affected", [])
            vendor, product = self.parse_vendor_product(affected)

            # Parse affected versions
            affected_versions = self.parse_affected_versions(affected)

            # Parse references
            references = cna_container.get("references", [])
            references_count = len(references)
            parsed_references = self.parse_references(references)
            
            # Parse exploits from CNA and ADP containers
            adp_containers = containers.get("adp", [])
            parsed_exploits = self.parse_exploits_from_containers(cna_container, adp_containers)

            return {
                "cve_id": cve_id,
                "title": title[:500] if title else "",
                "description": description,
                "published_date": datetime.fromisoformat(date_published.replace("Z", "+00:00")) if date_published else None,
                "modified_date": datetime.fromisoformat(date_updated.replace("Z", "+00:00")) if date_updated else None,
                "vendor_name": vendor,
                "product_name": product,
                "cwes": cwes,
                "references_count": references_count,
                "affected_versions": affected_versions,
                "references": parsed_references,
                "exploits": parsed_exploits,
                **cvss_data,
                "data_sources": ["cvelistv5"],
            }
        except Exception as e:
            print(f"Error parsing CVE JSON: {e}")
            return None

    def save_cve_to_db(self, cve_dict: Dict, db: Session) -> bool:
        """Save a single CVE to database"""
        try:
            cve_id = cve_dict["cve_id"]

            # Check if CVE already exists
            existing = db.query(CVE).filter(CVE.cve_id == cve_id).first()
            if existing:
                # Update existing CVE - only update actual database columns, not relations
                for key, value in cve_dict.items():
                    if key not in ["vendor_name", "product_name", "references", "exploits"] and value is not None:
                        setattr(existing, key, value)
                
                # Update references
                refs = cve_dict.get("references", [])
                if refs:
                    self.save_references_to_db(cve_id, refs, db)
                
                # Update exploits
                exploits = cve_dict.get("exploits", [])
                if exploits:
                    self.save_exploits_to_db(cve_id, exploits, db)
                    existing.exploits_count = len(exploits)
                
                return True

            # Get or create vendor
            vendor = None
            vendor_name = cve_dict.get("vendor_name")
            if vendor_name:
                # Truncate vendor name if too long
                vendor_name = vendor_name[:500] if len(vendor_name) > 500 else vendor_name
                try:
                    vendor = db.query(Vendor).filter(Vendor.name == vendor_name).first()
                    if not vendor:
                        vendor = Vendor(name=vendor_name)
                        db.add(vendor)
                        db.flush()
                except Exception:
                    db.rollback()
                    vendor = db.query(Vendor).filter(Vendor.name == vendor_name).first()

            # Get or create product
            product = None
            product_name = cve_dict.get("product_name")
            if product_name:
                # Truncate product name if too long
                product_name = product_name[:500] if len(product_name) > 500 else product_name
                try:
                    product = db.query(Product).filter(
                        Product.name == product_name,
                        Product.vendor_id == vendor.id if vendor else None
                    ).first()
                    if not product:
                        product = Product(name=product_name, vendor_id=vendor.id if vendor else None)
                        db.add(product)
                        db.flush()
                except Exception:
                    db.rollback()
                    product = db.query(Product).filter(
                        Product.name == product_name,
                        Product.vendor_id == vendor.id if vendor else None
                    ).first()

            # Create new CVE
            cve = CVE(
                cve_id=cve_id,
                title=cve_dict.get("title", ""),
                description=cve_dict.get("description", ""),
                published_date=cve_dict.get("published_date"),
                modified_date=cve_dict.get("modified_date"),
                cvss_v3_score=cve_dict.get("cvss_v3_score"),
                cvss_v3_severity=cve_dict.get("cvss_v3_severity"),
                cvss_v3_vector=cve_dict.get("cvss_v3_vector"),
                cvss_v4_score=cve_dict.get("cvss_v4_score"),
                cvss_v4_severity=cve_dict.get("cvss_v4_severity"),
                cvss_v4_vector=cve_dict.get("cvss_v4_vector"),
                cwes=cve_dict.get("cwes", []),
                references_count=cve_dict.get("references_count", 0),
                vendor_id=vendor.id if vendor else None,
                product_id=product.id if product else None,
                data_sources=cve_dict.get("data_sources", ["cvelistv5"]),
                affected_versions=cve_dict.get("affected_versions", []),
            )
            db.add(cve)
            db.flush()  # Ensure CVE is in session before adding related data
            
            # Save references
            refs = cve_dict.get("references", [])
            if refs:
                self.save_references_to_db(cve_id, refs, db)
            
            # Save exploits
            exploits = cve_dict.get("exploits", [])
            if exploits:
                self.save_exploits_to_db(cve_id, exploits, db)
                cve.exploits_count = len(exploits)
            
            return True

        except Exception as e:
            print(f"Error saving CVE {cve_dict.get('cve_id')}: {e}")
            db.rollback()
            return False

    def parse_exploits_from_containers(self, cna_container: Dict, adp_containers: List[Dict]) -> List[Dict]:
        """Parse exploit references from CNA and ADP containers"""
        exploits = []
        
        # Check CNA container references for exploit tags
        cna_references = cna_container.get("references", [])
        for ref in cna_references:
            tags = ref.get("tags", [])
            if "exploit" in tags or "x_refsource_EXPLOIT-DB" in tags or "x_refsource_EXPLOIT" in tags:
                url = ref.get("url") or ref.get("name")
                if url:
                    exploits.append({
                        "source": "cvelistv5",
                        "source_url": url,
                        "title": ref.get("name"),
                        "verified": False,
                        "reliability_score": None,
                    })
        
        # Check ADP containers for exploit references
        for adp in adp_containers:
            adp_references = adp.get("references", [])
            for ref in adp_references:
                tags = ref.get("tags", [])
                if "exploit" in tags:
                    url = ref.get("url") or ref.get("name")
                    if url:
                        # Check if we already have this exploit
                        existing = next((e for e in exploits if e.get("source_url") == url), None)
                        if not existing:
                            exploits.append({
                                "source": "cvelistv5-adp",
                                "source_url": url,
                                "title": ref.get("name"),
                                "verified": False,
                                "reliability_score": None,
                            })
        
        return exploits

    def save_exploits_to_db(self, cve_id: str, exploits: List[Dict], db: Session) -> bool:
        """Save exploits to database"""
        try:
            # Delete existing exploits for this CVE
            db.query(Exploit).filter(Exploit.cve_id == cve_id).delete()
            
            # Add new exploits
            for exp in exploits:
                exploit = Exploit(
                    cve_id=cve_id,
                    source=exp.get("source", "cvelistv5"),
                    source_url=exp.get("source_url")[:500] if exp.get("source_url") else None,
                    title=exp.get("title")[:500] if exp.get("title") else None,
                    verified=exp.get("verified", False),
                    reliability_score=exp.get("reliability_score"),
                )
                db.add(exploit)
            
            return True
        except Exception as e:
            print(f"Error saving exploits for {cve_id}: {e}")
            db.rollback()
            return False

    def import_years(self, db: Session, years: List[int], batch_size: int = 1000) -> int:
        """Import CVEs for specific years"""
        total_imported = 0
        total_errors = 0

        for year in years:
            year_dir = self.cves_dir / str(year)
            if not year_dir.exists():
                print(f"Year directory not found: {year}")
                continue

            print(f"\nProcessing year: {year}")
            year_count = 0

            # Get all subdirectories (e.g., 0xxx, 1xxx, etc.)
            subdirs = sorted([d for d in year_dir.iterdir() if d.is_dir()])

            for subdir in subdirs:
                # Get all JSON files in subdirectory
                json_files = list(subdir.glob("*.json"))

                for json_file in json_files:
                    try:
                        with open(json_file, 'r', encoding='utf-8') as f:
                            cve_data = json.load(f)

                        parsed = self.parse_cve_json(cve_data)
                        if parsed:
                            if self.save_cve_to_db(parsed, db):
                                total_imported += 1
                                year_count += 1

                                # Commit in batches
                                if total_imported % batch_size == 0:
                                    db.commit()
                                    print(f"  Imported {total_imported} CVEs...")
                            else:
                                total_errors += 1

                    except Exception as e:
                        print(f"Error processing {json_file}: {e}")
                        total_errors += 1

            print(f"  Year {year}: {year_count} CVEs imported")

        # Final commit
        db.commit()
        print(f"\nTotal imported: {total_imported}, Errors: {total_errors}")
        return total_imported

    def sync_recent_years(self, year_count: int = 2) -> int:
        """导入最近 N 年的 CVE 数据"""
        # Get available years
        available_years = self.get_available_years()
        if not available_years:
            print("No CVE data found")
            return 0

        print(f"Available years: {available_years}")

        # Select recent years
        years_to_import = available_years[:year_count]
        print(f"Will import years: {years_to_import}")

        # Import data
        db = SessionLocal()
        try:
            count = self.import_years(db, years_to_import)
            return count
        finally:
            db.close()


if __name__ == "__main__":
    crawler = CVEListV5CrawlerV2()

    # 显示可用年份
    years = crawler.get_available_years()
    print(f"Available years: {years}")

    # 导入最近2年
    count = crawler.sync_recent_years(year_count=2)
    print(f"\nSuccessfully imported {count} CVEs from cvelistV5")
