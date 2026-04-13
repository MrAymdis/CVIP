"""
GitHub PoC Crawler
Searches for CVE-related Proof-of-Concept repositories on GitHub
"""
import httpx
import asyncio
import re
from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models import CVE, Exploit

GITHUB_API_BASE = "https://api.github.com"


class GitHubCrawler:
    def __init__(self, token: Optional[str] = None):
        self.token = token
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
        }
        if token:
            self.headers["Authorization"] = f"token {token}"
    
    async def search_cve_repos(
        self,
        cve_id: str,
        per_page: int = 10
    ) -> List[Dict[str, Any]]:
        """Search GitHub repositories for a specific CVE."""
        async with httpx.AsyncClient() as client:
            try:
                query = f"{cve_id} in:name,description,readme"
                response = await client.get(
                    f"{GITHUB_API_BASE}/search/repositories",
                    params={
                        "q": query,
                        "sort": "stars",
                        "order": "desc",
                        "per_page": per_page,
                    },
                    headers=self.headers,
                    timeout=30.0
                )
                response.raise_for_status()
                data = response.json()
                return data.get("items", [])
            except httpx.HTTPError as e:
                print(f"HTTP error searching GitHub: {e}")
                return []
            except Exception as e:
                print(f"Error searching GitHub: {e}")
                return []
    
    async def get_repo_content(
        self,
        owner: str,
        repo: str,
        path: str = ""
    ) -> List[Dict[str, Any]]:
        """Get repository content."""
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    f"{GITHUB_API_BASE}/repos/{owner}/{repo}/contents/{path}",
                    headers=self.headers,
                    timeout=30.0
                )
                if response.status_code == 404:
                    return []
                response.raise_for_status()
                return response.json()
            except httpx.HTTPError as e:
                print(f"HTTP error fetching repo content: {e}")
                return []
            except Exception as e:
                print(f"Error fetching repo content: {e}")
                return []
    
    async def get_file_content(
        self,
        owner: str,
        repo: str,
        path: str
    ) -> str:
        """Get file content."""
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    f"{GITHUB_API_BASE}/repos/{owner}/{repo}/contents/{path}",
                    headers=self.headers,
                    timeout=30.0
                )
                response.raise_for_status()
                data = response.json()
                import base64
                content = base64.b64decode(data.get("content", "")).decode("utf-8", errors="ignore")
                return content
            except Exception as e:
                print(f"Error fetching file content: {e}")
                return ""
    
    def detect_language(self, filename: str) -> str:
        """Detect programming language from filename."""
        ext_map = {
            ".py": "Python",
            ".rb": "Ruby",
            ".go": "Go",
            ".js": "JavaScript",
            ".ts": "TypeScript",
            ".java": "Java",
            ".c": "C",
            ".cpp": "C++",
            ".h": "C/C++",
            ".cs": "C#",
            ".php": "PHP",
            ".sh": "Shell",
            ".ps1": "PowerShell",
            ".pl": "Perl",
            ".rs": "Rust",
            ".swift": "Swift",
            ".kt": "Kotlin",
            ".scala": "Scala",
            ".r": "R",
            ".m": "MATLAB/Objective-C",
        }
        
        for ext, lang in ext_map.items():
            if filename.endswith(ext):
                return lang
        return "Unknown"
    
    def calculate_reliability(self, repo: Dict[str, Any]) -> float:
        """Calculate reliability score based on repo metrics."""
        stars = repo.get("stargazers_count", 0)
        forks = repo.get("forks_count", 0)
        has_readme = 1 if repo.get("description") else 0
        
        # Simple scoring algorithm
        score = min(stars / 100, 5) + min(forks / 50, 3) + has_readme * 2
        return min(score, 10)
    
    def save_to_db(self, cve_id: str, repos: List[Dict[str, Any]], db: Session):
        """Save GitHub repos as exploits."""
        added = 0
        
        for repo in repos:
            repo_id = repo.get("id")
            
            # Check if already exists
            existing = db.query(Exploit).filter(
                Exploit.cve_id == cve_id,
                Exploit.source == "github",
                Exploit.source_id == str(repo_id)
            ).first()
            
            if existing:
                continue
            
            # Create exploit
            exploit = Exploit(
                cve_id=cve_id,
                source="github",
                source_id=str(repo_id),
                source_url=repo.get("html_url"),
                title=repo.get("name"),
                description=repo.get("description", "")[:500],
                language=self.detect_language(repo.get("name", "")),
                author=repo.get("owner", {}).get("login"),
                github_stars=repo.get("stargazers_count"),
                github_forks=repo.get("forks_count"),
                reliability_score=self.calculate_reliability(repo),
                published_date=datetime.strptime(
                    repo.get("created_at"), "%Y-%m-%dT%H:%M:%SZ"
                ) if repo.get("created_at") else None,
            )
            db.add(exploit)
            added += 1
        
        # Update CVE exploits count
        cve = db.query(CVE).filter(CVE.cve_id == cve_id).first()
        if cve:
            cve.exploits_count = db.query(Exploit).filter(
                Exploit.cve_id == cve_id
            ).count()
        
        db.commit()
        return added
    
    async def sync_for_cve(self, cve_id: str):
        """Sync GitHub repos for a specific CVE."""
        print(f"Searching GitHub for {cve_id}")
        repos = await self.search_cve_repos(cve_id)
        print(f"Found {len(repos)} repositories")
        
        if repos:
            db = SessionLocal()
            try:
                added = self.save_to_db(cve_id, repos, db)
                print(f"Added {added} GitHub exploits for {cve_id}")
            finally:
                db.close()
        
        return len(repos)
    
    async def sync_recent_cves(self, limit: int = 100):
        """Sync GitHub repos for recent CVEs."""
        db = SessionLocal()
        try:
            # Get recent CVEs without GitHub exploits
            from sqlalchemy import desc
            cves = db.query(CVE).outerjoin(Exploit).filter(
                Exploit.id == None
            ).order_by(desc(CVE.published_date)).limit(limit).all()
            
            print(f"Processing {len(cves)} CVEs")
            
            for cve in cves:
                await self.sync_for_cve(cve.cve_id)
                await asyncio.sleep(2)  # Rate limiting
        finally:
            db.close()


if __name__ == "__main__":
    import os
    token = os.getenv("GITHUB_TOKEN")
    crawler = GitHubCrawler(token=token)
    asyncio.run(crawler.sync_recent_cves(limit=10))
