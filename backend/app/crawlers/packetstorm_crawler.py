"""
Packet Storm Crawler
Fetches vulnerability advisories from Packet Storm Security
"""
import httpx
import asyncio
import re
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models import CVE, Reference

PACKETSTORM_BASE_URL = "https://packetstormsecurity.com"
PACKETSTORM_ADVISORY_URL = "https://packetstormsecurity.com/files/advisory/"


class PacketStormCrawler:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        self.cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}')
    
    async def accept_tos(self, client: httpx.AsyncClient) -> bool:
        """Accept Terms of Service if needed."""
        try:
            response = await client.get(PACKETSTORM_BASE_URL, timeout=60.0)
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'lxml')
            tos_form = soup.find('form', action='/tos/')
            
            if tos_form:
                print("Accepting Packet Storm Terms of Service...")
                csrf_input = tos_form.find('input', {'name': 'csrf'})
                redir_input = tos_form.find('input', {'name': 'redir'})
                
                if csrf_input and redir_input:
                    csrf = csrf_input.get('value', '')
                    redir = redir_input.get('value', '')
                    
                    await client.post(
                        'https://packetstormsecurity.com/tos/',
                        data={'csrf': csrf, 'redir': redir, 'go': 'Accept'},
                        timeout=60.0
                    )
            return True
        except Exception as e:
            print(f"Warning: Error in ToS handling: {e}")
            return True
    
    async def fetch_page(self, client: httpx.AsyncClient, url: str) -> Optional[str]:
        """Fetch a page from Packet Storm."""
        try:
            response = await client.get(url, timeout=60.0)
            response.raise_for_status()
            return response.text
        except httpx.HTTPError as e:
            print(f"HTTP error fetching {url}: {e}")
            return None
        except Exception as e:
            print(f"Error fetching {url}: {e}")
            return None
    
    def extract_cve_ids(self, text: str) -> List[str]:
        """Extract CVE IDs from text."""
        cves = self.cve_pattern.findall(text)
        return list(set(cves))
    
    def parse_page_for_advisories(self, html: str, page_url: str) -> List[Dict[str, Any]]:
        """Comprehensive advisory parsing using multiple strategies."""
        from bs4 import BeautifulSoup
        advisories = []
        soup = BeautifulSoup(html, 'lxml')
        
        # Strategy 1: Look for all links with CVE in their text
        links = soup.find_all('a', href=True)
        for link in links:
            href = link.get('href', '')
            text = link.get_text(strip=True)
            full_text = str(link.parent) if link.parent else text
            
            cves = self.extract_cve_ids(full_text)
            
            if cves and '/files/' in href:
                full_url = urljoin(PACKETSTORM_BASE_URL, href)
                title = text[:500] if text else 'Packet Storm Advisory'
                
                advisories.append({
                    'title': title,
                    'url': full_url,
                    'cve_ids': cves
                })
        
        # Strategy 2: Look for CVE patterns in the entire page and find nearby context
        if not advisories:
            cve_matches = list(self.cve_pattern.finditer(html))
            processed_urls = set()
            
            for match in cve_matches[:100]:
                start = max(0, match.start() - 1000)
                end = min(len(html), match.end() + 1000)
                context = html[start:end]
                
                context_soup = BeautifulSoup(context, 'lxml')
                link = context_soup.find('a', href=True)
                
                if link:
                    href = link.get('href', '')
                    if '/files/' in href and href not in processed_urls:
                        processed_urls.add(href)
                        full_url = urljoin(PACKETSTORM_BASE_URL, href)
                        link_text = link.get_text(strip=True)
                        
                        cves_in_context = self.extract_cve_ids(context)
                        
                        advisories.append({
                            'title': link_text[:500] if link_text else 'Packet Storm Advisory',
                            'url': full_url,
                            'cve_ids': cves_in_context
                        })
        
        # Deduplicate by URL
        unique_advisories = {}
        for adv in advisories:
            url = adv['url']
            if url not in unique_advisories:
                unique_advisories[url] = adv
            else:
                # Merge CVE IDs
                existing = unique_advisories[url]
                existing['cve_ids'] = list(set(existing['cve_ids'] + adv['cve_ids']))
        
        return list(unique_advisories.values())
    
    async def collect_advisories(self, client: httpx.AsyncClient) -> List[Dict[str, Any]]:
        """Collect advisories from multiple sources."""
        all_advisories = []
        sources = [
            ('advisories', PACKETSTORM_ADVISORY_URL, 10),
            ('latest', 'https://packetstormsecurity.com/files/latest/', 10),
            ('search-cve', 'https://packetstormsecurity.com/search/?q=CVE&a=files', 5),
        ]
        
        for source_name, base_url, num_pages in sources:
            print(f"\nCollecting from {source_name}...")
            
            for page in range(1, num_pages + 1):
                if page == 1:
                    url = base_url
                else:
                    url = f"{base_url.rstrip('/')}/page/{page}"
                
                print(f"  Fetching {url}")
                
                html = await self.fetch_page(client, url)
                if html:
                    advisories = self.parse_page_for_advisories(html, url)
                    print(f"  Found {len(advisories)} advisories on page {page}")
                    all_advisories.extend(advisories)
                
                await asyncio.sleep(0.5)
        
        # Deduplicate again across all sources
        unique = {}
        for adv in all_advisories:
            url = adv['url']
            if url not in unique:
                unique[url] = adv
            else:
                unique[url]['cve_ids'] = list(set(unique[url]['cve_ids'] + adv['cve_ids']))
        
        return list(unique.values())
    
    def save_references_to_db(self, advisories: List[Dict[str, Any]], db: Session, limit: int = 100) -> int:
        """Save advisories as Reference records in database."""
        added = 0
        
        for advisory in advisories:
            if added >= limit:
                break
            
            title = advisory.get('title', '')
            url = advisory.get('url', '')
            cve_ids = advisory.get('cve_ids', [])
            
            if not url or not cve_ids:
                continue
            
            for cve_id in cve_ids:
                if added >= limit:
                    break
                
                existing = db.query(Reference).filter(
                    Reference.cve_id == cve_id,
                    Reference.source == 'packetstorm',
                    Reference.url == url[:500]
                ).first()
                
                if existing:
                    continue
                
                cve = db.query(CVE).filter(CVE.cve_id == cve_id).first()
                if not cve:
                    cve = CVE(
                        cve_id=cve_id,
                        title=title[:500] if title else 'Packet Storm CVE',
                        description=title if title else '',
                        data_sources=['packetstorm'],
                    )
                    db.add(cve)
                    try:
                        db.flush()
                    except Exception:
                        db.rollback()
                        cve = db.query(CVE).filter(CVE.cve_id == cve_id).first()
                
                reference = Reference(
                    cve_id=cve_id,
                    url=url[:500],
                    title=title[:500] if title else None,
                    ref_type='advisory',
                    source='packetstorm',
                    tags=['packetstorm', 'security-advisory'],
                )
                db.add(reference)
                
                if cve:
                    cve.references_count = db.query(Reference).filter(
                        Reference.cve_id == cve_id
                    ).count()
                
                try:
                    db.commit()
                    added += 1
                except Exception as e:
                    db.rollback()
                    print(f"Error saving reference: {e}")
        
        return added
    
    async def sync(self, limit: int = 100):
        """Main sync method."""
        print("=" * 60)
        print("Starting Packet Storm Security Crawler")
        print("=" * 60)
        
        async with httpx.AsyncClient(headers=self.headers, follow_redirects=True, timeout=httpx.Timeout(60.0)) as client:
            await self.accept_tos(client)
            
            print("\nCollecting advisories...")
            advisories = await self.collect_advisories(client)
            
            print(f"\nTotal unique advisories found: {len(advisories)}")
            
            if advisories:
                print("\nSample advisories:")
                for i, adv in enumerate(advisories[:5]):
                    print(f"  {i+1}. {adv['title'][:60]}...")
                    print(f"     URL: {adv['url']}")
                    print(f"     CVEs: {', '.join(adv['cve_ids'])}")
            
            added = 0
            if advisories:
                print("\nSaving to database...")
                db = SessionLocal()
                try:
                    added = self.save_references_to_db(advisories, db, limit=limit)
                    print(f"\nSuccessfully saved {added} references!")
                finally:
                    db.close()
            else:
                print("\nNo advisories found to save")
            
            print("\n" + "=" * 60)
            print(f"Sync complete. Added {added} records.")
            print("=" * 60)
            
            return added


if __name__ == "__main__":
    crawler = PacketStormCrawler()
    asyncio.run(crawler.sync(limit=100))
