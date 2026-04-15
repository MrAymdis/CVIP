"""
Metasploit Crawler
Fetches exploit modules from Metasploit Framework GitHub repository
"""
import httpx
import asyncio
import re
import base64
from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models import CVE, Exploit
from app.config import settings

GITHUB_API_BASE = "https://api.github.com"
METASPLOIT_REPO_OWNER = "rapid7"
METASPLOIT_REPO_NAME = "metasploit-framework"
METASPLOIT_MODULES_PATH = "modules/exploits"


class MetasploitCrawler:
    def __init__(self, token: Optional[str] = None):
        self.token = token or settings.GITHUB_TOKEN
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
        }
        if self.token:
            self.headers["Authorization"] = f"token {self.token}"
    
    async def get_directory_contents(
        self,
        path: str,
        per_page: int = 100
    ) -> List[Dict[str, Any]]:
        """Get directory contents from GitHub repo."""
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    f"{GITHUB_API_BASE}/repos/{METASPLOIT_REPO_OWNER}/{METASPLOIT_REPO_NAME}/contents/{path}",
                    params={"per_page": per_page},
                    headers=self.headers,
                    timeout=60.0
                )
                if response.status_code == 404:
                    return []
                response.raise_for_status()
                return response.json()
            except httpx.HTTPError as e:
                print(f"HTTP error fetching directory {path}: {e}")
                return []
            except Exception as e:
                print(f"Error fetching directory {path}: {e}")
                return []
    
    async def get_file_content(
        self,
        path: str
    ) -> str:
        """Get file content from GitHub repo."""
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    f"{GITHUB_API_BASE}/repos/{METASPLOIT_REPO_OWNER}/{METASPLOIT_REPO_NAME}/contents/{path}",
                    headers=self.headers,
                    timeout=60.0
                )
                if response.status_code == 404:
                    return ""
                response.raise_for_status()
                data = response.json()
                content = base64.b64decode(data.get("content", "")).decode("utf-8", errors="ignore")
                return content
            except httpx.HTTPError as e:
                print(f"HTTP error fetching file {path}: {e}")
                return ""
            except Exception as e:
                print(f"Error fetching file {path}: {e}")
                return ""
    
    async def get_all_exploit_modules(
        self,
        max_depth: int = 5
    ) -> List[Dict[str, Any]]:
        """Recursively get all exploit modules."""
        all_modules = []
        directories_to_check = [(METASPLOIT_MODULES_PATH, 0)]
        
        while directories_to_check:
            current_path, depth = directories_to_check.pop(0)
            if depth > max_depth:
                continue
            
            contents = await self.get_directory_contents(current_path)
            
            for item in contents:
                if item.get("type") == "dir":
                    directories_to_check.append((item.get("path"), depth + 1))
                elif item.get("type") == "file" and item.get("name", "").endswith(".rb"):
                    all_modules.append(item)
        
        return all_modules
    
    def extract_cve_ids(self, content: str) -> List[str]:
        """Extract CVE IDs from module content."""
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cve_ids = re.findall(cve_pattern, content, re.IGNORECASE)
        return list(set([cve.upper() for cve in cve_ids]))
    
    def extract_metadata(self, content: str) -> Dict[str, Any]:
        """Extract metadata from Metasploit module."""
        metadata = {}
        
        name_match = re.search(r"'Name'\s*=>\s*['\"](.+?)['\"]", content)
        if name_match:
            metadata["name"] = name_match.group(1)
        
        desc_match = re.search(r"'Description'\s*=>\s*%q\{(.+?)\}", content, re.DOTALL)
        if not desc_match:
            desc_match = re.search(r"'Description'\s*=>\s*['\"](.+?)['\"]", content, re.DOTALL)
        if desc_match:
            metadata["description"] = desc_match.group(1)
        
        author_match = re.search(r"'Author'\s*=>\s*\[(.+?)\]", content, re.DOTALL)
        if author_match:
            authors = re.findall(r"['\"](.+?)['\"]", author_match.group(1))
            metadata["author"] = ", ".join(authors)
        
        platform_match = re.search(r"'Platform'\s*=>\s*['\"](.+?)['\"]", content)
        if not platform_match:
            platform_match = re.search(r"'Platform'\s*=>\s*\[(.+?)\]", content, re.DOTALL)
            if platform_match:
                platforms = re.findall(r"['\"](.+?)['\"]", platform_match.group(1))
                metadata["platform"] = ", ".join(platforms)
        else:
            metadata["platform"] = platform_match.group(1)
        
        rank_match = re.search(r'Rank\s*=\s*(\w+Ranking)', content)
        if rank_match:
            rank_name = rank_match.group(1).replace('Ranking', '')
            metadata["rank"] = rank_name
        
        disclosure_date_match = re.search(r"'DisclosureDate'\s*=>\s*['\"](.+?)['\"]", content)
        if disclosure_date_match:
            metadata["disclosure_date"] = disclosure_date_match.group(1)
        
        return metadata
    
    def parse_date(self, date_str: str) -> Optional[datetime]:
        """Parse date string to datetime."""
        if not date_str:
            return None
        try:
            return datetime.strptime(date_str, "%b %d %Y")
        except ValueError:
            pass
        try:
            return datetime.strptime(date_str, "%Y-%m-%d")
        except ValueError:
            pass
        try:
            return datetime.strptime(date_str, "%Y/%m/%d")
        except ValueError:
            pass
        return None
    
    def calculate_reliability(self, rank: Optional[str]) -> float:
        """Calculate reliability score based on module rank."""
        rank_scores = {
            "Excellent": 10.0,
            "Great": 9.0,
            "Good": 8.0,
            "Normal": 6.0,
            "Average": 5.0,
            "Low": 3.0,
            "Manual": 2.0,
        }
        return rank_scores.get(rank or "", 5.0)
    
    async def process_module(
        self,
        module_item: Dict[str, Any],
        db: Session
    ) -> int:
        """Process a single module and save to database."""
        path = module_item.get("path", "")
        module_name = module_item.get("name", "")
        source_id = path.replace("modules/exploits/", "").replace(".rb", "")
        html_url = f"https://github.com/{METASPLOIT_REPO_OWNER}/{METASPLOIT_REPO_NAME}/blob/master/{path}"
        
        content = await self.get_file_content(path)
        if not content:
            return 0
        
        cve_ids = self.extract_cve_ids(content)
        if not cve_ids:
            return 0
        
        metadata = self.extract_metadata(content)
        title = metadata.get("name", module_name.replace(".rb", ""))
        description = metadata.get("description", title)
        author = metadata.get("author", "")
        platform = metadata.get("platform", "")
        disclosure_date = metadata.get("disclosure_date", "")
        rank = metadata.get("rank", "")
        
        published_date = self.parse_date(disclosure_date)
        reliability_score = self.calculate_reliability(rank)
        
        added = 0
        for cve_id in cve_ids:
            existing = db.query(Exploit).filter(
                Exploit.cve_id == cve_id,
                Exploit.source == "metasploit",
                Exploit.source_id == source_id
            ).first()
            
            if existing:
                continue
            
            try:
                cve = db.query(CVE).filter(CVE.cve_id == cve_id).first()
                if not cve:
                    cve = CVE(
                        cve_id=cve_id,
                        title=title[:500] if title else "",
                        description=description,
                        published_date=published_date,
                        data_sources=["metasploit"],
                    )
                    db.add(cve)
                    db.flush()
                
                exploit = Exploit(
                    cve_id=cve_id,
                    source="metasploit",
                    source_id=source_id,
                    source_url=html_url,
                    title=title[:500] if title else "",
                    code=content[:10000] if content else "",
                    language="Ruby",
                    author=author,
                    platform=platform,
                    exploit_type="exploit",
                    verified=True,
                    reliability_score=reliability_score,
                    published_date=published_date,
                )
                db.add(exploit)
                
                if cve:
                    cve.exploits_count = db.query(Exploit).filter(
                        Exploit.cve_id == cve_id
                    ).count()
                
                db.commit()
                added += 1
            except Exception as e:
                db.rollback()
                print(f"Error saving Metasploit module {source_id} for CVE {cve_id}: {e}")
        
        return added
    
    async def sync(self, limit: int = 100):
        """Sync Metasploit exploit modules."""
        print("Fetching Metasploit exploit modules list")
        all_modules = await self.get_all_exploit_modules()
        print(f"Found {len(all_modules)} exploit modules")
        
        added = 0
        if all_modules:
            db = SessionLocal()
            try:
                for i, module_item in enumerate(all_modules):
                    if added >= limit:
                        break
                    
                    print(f"Processing module {i+1}/{len(all_modules)}: {module_item.get('path')}")
                    module_added = await self.process_module(module_item, db)
                    added += module_added
                    
                    await asyncio.sleep(0.1)
                
                print(f"Added {added} Metasploit records")
            finally:
                db.close()
        
        return added


if __name__ == "__main__":
    crawler = MetasploitCrawler()
    asyncio.run(crawler.sync(limit=100))
