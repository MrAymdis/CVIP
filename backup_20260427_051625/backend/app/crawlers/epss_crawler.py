"""
EPSS (Exploit Prediction Scoring System) Crawler
Fetches EPSS scores from FIRST API
"""
import httpx
import asyncio
from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models import CVE

EPSS_API_BASE = "https://api.first.org/data/v1/epss"


class EPSSCrawler:
    def __init__(self):
        pass
    
    async def fetch_epss_scores(
        self,
        cve_ids: Optional[List[str]] = None,
        date: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Fetch EPSS scores from API."""
        all_scores = []
        
        # EPSS API has a limit of 1000 CVEs per request
        batch_size = 1000
        
        async with httpx.AsyncClient() as client:
            if cve_ids:
                # Fetch specific CVEs in batches
                for i in range(0, len(cve_ids), batch_size):
                    batch = cve_ids[i:i + batch_size]
                    params = {
                        "cve": ",".join(batch),
                    }
                    if date:
                        params["date"] = date
                    
                    try:
                        response = await client.get(
                            EPSS_API_BASE,
                            params=params,
                            timeout=60.0
                        )
                        response.raise_for_status()
                        data = response.json()
                        all_scores.extend(data.get("data", []))
                        
                        # Rate limiting
                        await asyncio.sleep(0.5)
                        
                    except httpx.HTTPError as e:
                        print(f"HTTP error fetching EPSS: {e}")
                    except Exception as e:
                        print(f"Error fetching EPSS: {e}")
            else:
                # Fetch all scores for a date
                params = {}
                if date:
                    params["date"] = date
                
                try:
                    response = await client.get(
                        EPSS_API_BASE,
                        params=params,
                        timeout=120.0
                    )
                    response.raise_for_status()
                    data = response.json()
                    all_scores = data.get("data", [])
                    
                except httpx.HTTPError as e:
                    print(f"HTTP error fetching EPSS: {e}")
                except Exception as e:
                    print(f"Error fetching EPSS: {e}")
        
        return all_scores
    
    def save_to_db(self, scores: List[Dict[str, Any]], db: Session):
        """Save EPSS scores to database."""
        updated = 0
        
        for score_data in scores:
            cve_id = score_data.get("cve")
            epss_score = score_data.get("epss")
            percentile = score_data.get("percentile")
            
            if not cve_id:
                continue
            
            # Find CVE
            cve = db.query(CVE).filter(CVE.cve_id == cve_id).first()
            if cve:
                cve.epss_score = epss_score
                cve.epss_percentile = percentile
                updated += 1
        
        db.commit()
        return updated
    
    async def sync_recent(self, days: int = 1):
        """Sync recent EPSS scores."""
        date = (datetime.utcnow() - __import__('datetime').timedelta(days=days)).strftime("%Y-%m-%d")
        
        print(f"Fetching EPSS scores for {date}")
        scores = await self.fetch_epss_scores(date=date)
        print(f"Fetched {len(scores)} EPSS scores")
        
        if scores:
            db = SessionLocal()
            try:
                updated = self.save_to_db(scores, db)
                print(f"Updated {updated} CVEs with EPSS scores")
            finally:
                db.close()
        
        return len(scores)
    
    async def sync(self, days: int = 1):
        """Sync EPSS scores (alias for sync_recent)."""
        return await self.sync_recent(days=days)
    
    async def sync_for_cves(self, cve_ids: List[str]):
        """Sync EPSS scores for specific CVEs."""
        print(f"Fetching EPSS scores for {len(cve_ids)} CVEs")
        scores = await self.fetch_epss_scores(cve_ids=cve_ids)
        print(f"Fetched {len(scores)} EPSS scores")
        
        if scores:
            db = SessionLocal()
            try:
                updated = self.save_to_db(scores, db)
                print(f"Updated {updated} CVEs with EPSS scores")
            finally:
                db.close()
        
        return len(scores)


if __name__ == "__main__":
    crawler = EPSSCrawler()
    asyncio.run(crawler.sync_recent())
