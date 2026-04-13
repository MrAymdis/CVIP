"""
CVEProject/cvelistV5 Crawler
Fetches CVE data from official CVE List in CVE JSON 5 format
"""
import json
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models import CVE, Vendor, Product


class CVEListV5Crawler:
    """Crawler for CVEProject/cvelistV5 repository"""
    
    def __init__(self, repo_path: Optional[str] = None):
        """
        Initialize crawler
        
        Args:
            repo_path: Path to cvelistV5 repository. If None, will use default path.
        """
        if repo_path is None:
            # Default path relative to backend directory
            backend_dir = Path(__file__).parent.parent.parent
            self.repo_path = backend_dir / "cvelistV5"
        else:
            self.repo_path = Path(repo_path)
        
        self.cves_dir = self.repo_path / "cves"
        self.delta_file = self.cves_dir / "delta.json"
    
    def clone_repository(self) -> bool:
        """Clone cvelistV5 repository"""
        if self.repo_path.exists():
            print(f"Repository already exists at {self.repo_path}")
            return True
        
        print("Cloning cvelistV5 repository...")
        try:
            # Clone with shallow depth for faster download
            result = subprocess.run(
                [
                    "git", "clone", "--depth", "1",
                    "https://github.com/CVEProject/cvelistV5.git",
                    str(self.repo_path)
                ],
                capture_output=True,
                text=True,
                check=True
            )
            print("Repository cloned successfully")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error cloning repository: {e}")
            print(f"stderr: {e.stderr}")
            return False
    
    def pull_updates(self) -> bool:
        """Pull latest updates from repository"""
        if not self.repo_path.exists():
            print("Repository does not exist. Please clone first.")
            return False
        
        print("Pulling latest updates...")
        try:
            result = subprocess.run(
                ["git", "-C", str(self.repo_path), "pull"],
                capture_output=True,
                text=True,
                check=True
            )
            print("Updates pulled successfully")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error pulling updates: {e}")
            return False
    
    def parse_cvss(self, metrics: List[Dict]) -> Dict[str, Any]:
        """Parse CVSS scores from metrics"""
        result = {
            "cvss_v3_score": None,
            "cvss_v3_severity": None,
            "cvss_v3_vector": None,
            "cvss_v4_score": None,
            "cvss_v4_severity": None,
            "cvss_v4_vector": None,
        }

        for metric in metrics:
            # CVSS v3.1
            if "cvssV3_1" in metric:
                cvss_data = metric["cvssV3_1"]
                result["cvss_v3_score"] = cvss_data.get("baseScore")
                result["cvss_v3_severity"] = cvss_data.get("baseSeverity")
                vector = cvss_data.get("vectorString", "")
                result["cvss_v3_vector"] = vector[:200] if len(vector) > 200 else vector
            # CVSS v3.0
            elif "cvssV3_0" in metric:
                cvss_data = metric["cvssV3_0"]
                result["cvss_v3_score"] = cvss_data.get("baseScore")
                result["cvss_v3_severity"] = cvss_data.get("baseSeverity")
                vector = cvss_data.get("vectorString", "")
                result["cvss_v3_vector"] = vector[:200] if len(vector) > 200 else vector
            # CVSS v4.0
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
        for pt in problem_types:
            for desc in pt.get("descriptions", []):
                cwe_id = desc.get("cweId", "")
                if cwe_id.startswith("CWE-"):
                    cwes.append(cwe_id)
        return list(set(cwes))
    
    def parse_vendor_product(self, affected: List[Dict]) -> Tuple[Optional[str], Optional[str]]:
        """Parse vendor and product from affected list"""
        vendors = set()
        products = set()
        
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
        """Parse CVE JSON 5 format and extract relevant fields"""
        try:
            cve_metadata = cve_data.get("cveMetadata", {})
            cna_container = cve_data.get("containers", {}).get("cna", {})
            
            cve_id = cve_metadata.get("cveId")
            if not cve_id:
                return None
            
            # Parse dates
            date_published = cve_metadata.get("datePublished")
            date_updated = cve_metadata.get("dateUpdated")
            
            # Parse title
            title = cna_container.get("title", "")
            
            # Parse description
            descriptions = cna_container.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # Parse CVSS
            metrics = cna_container.get("metrics", [])
            cvss_data = self.parse_cvss(metrics)
            
            # Parse CWEs
            problem_types = cna_container.get("problemTypes", [])
            cwes = self.parse_cwe(problem_types)
            
            # Parse vendor and product
            affected = cna_container.get("affected", [])
            vendor, product = self.parse_vendor_product(affected)
            
            return {
                "cve_id": cve_id,
                "title": title[:500] if title else description[:500],
                "description": description,
                "published_date": datetime.fromisoformat(date_published.replace("Z", "+00:00")) if date_published else None,
                "modified_date": datetime.fromisoformat(date_updated.replace("Z", "+00:00")) if date_updated else None,
                "vendor_name": vendor,
                "product_name": product,
                "cwes": cwes,
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
                # Update existing CVE
                for key, value in cve_dict.items():
                    if key not in ["vendor_name", "product_name"] and value is not None:
                        setattr(existing, key, value)
                return True
            
            # Get or create vendor
            vendor = None
            vendor_name = cve_dict.get("vendor_name")
            if vendor_name:
                # Truncate vendor name if too long
                vendor_name = vendor_name[:500] if len(vendor_name) > 500 else vendor_name
                vendor = db.query(Vendor).filter(Vendor.name == vendor_name).first()
                if not vendor:
                    vendor = Vendor(name=vendor_name)
                    db.add(vendor)
                    db.flush()
            
            # Get or create product
            product = None
            product_name = cve_dict.get("product_name")
            if product_name:
                # Truncate product name if too long
                product_name = product_name[:500] if len(product_name) > 500 else product_name
                product = db.query(Product).filter(
                    Product.name == product_name,
                    Product.vendor_id == vendor.id if vendor else None
                ).first()
                if not product:
                    product = Product(name=product_name, vendor_id=vendor.id if vendor else None)
                    db.add(product)
                    db.flush()
            
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
                vendor_id=vendor.id if vendor else None,
                product_id=product.id if product else None,
                data_sources=cve_dict.get("data_sources", ["cvelistv5"]),
            )
            db.add(cve)
            return True
            
        except Exception as e:
            print(f"Error saving CVE {cve_dict.get('cve_id')}: {e}")
            return False
    
    def import_all_cves(self, db: Session, batch_size: int = 1000) -> int:
        """Import all CVEs from repository"""
        if not self.cves_dir.exists():
            print(f"CVEs directory not found: {self.cves_dir}")
            return 0
        
        total_imported = 0
        total_errors = 0
        
        # Get all year directories
        year_dirs = sorted([d for d in self.cves_dir.iterdir() if d.is_dir() and d.name.isdigit()])
        
        print(f"Found {len(year_dirs)} year directories")
        
        for year_dir in year_dirs:
            print(f"\nProcessing year: {year_dir.name}")
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
            
            print(f"  Year {year_dir.name}: {year_count} CVEs imported")
        
        # Final commit
        db.commit()
        print(f"\nTotal imported: {total_imported}, Errors: {total_errors}")
        return total_imported
    
    def sync(self) -> int:
        """Main sync method - clone/pull and import"""
        # Clone or pull repository if git is available
        if not self.repo_path.exists():
            try:
                if not self.clone_repository():
                    print("Git not available or clone failed, checking for existing data...")
            except Exception as e:
                print(f"Git clone failed: {e}, checking for existing data...")
        else:
            try:
                self.pull_updates()
            except Exception as e:
                print(f"Git pull failed: {e}, using existing data...")
        
        # Import data
        db = SessionLocal()
        try:
            count = self.import_all_cves(db)
            return count
        finally:
            db.close()


if __name__ == "__main__":
    crawler = CVEListV5Crawler()
    count = crawler.sync()
    print(f"\nSuccessfully imported {count} CVEs from cvelistV5")
