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
from app.models import CVE, Reference, PacketStormExploit

PACKETSTORM_BASE_URL = "https://packetstorm.news"
PACKETSTORM_ADVISORY_URL = "https://packetstorm.news/files/advisory/"


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
                        f'{PACKETSTORM_BASE_URL}/tos/',
                        data={'csrf': csrf, 'redir': redir, 'go': 'Accept'},
                        timeout=60.0
                    )
            return True
        except Exception as e:
            print(f"Warning: Error in ToS handling: {e}")
            return True
    
    async def fetch_page(self, client: httpx.AsyncClient, url: str) -> Optional[str]:
        """Fetch a page from Packet Storm, handling ToS if needed."""
        try:
            response = await client.get(url, timeout=60.0)
            response.raise_for_status()
            
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'lxml')
            
            tos_form = soup.find('form', action='/tos/')
            if tos_form:
                print(f"ToS form encountered on {url}, accepting...")
                csrf_input = tos_form.find('input', {'name': 'csrf'})
                redir_input = tos_form.find('input', {'name': 'redir'})
                
                if csrf_input and redir_input:
                    csrf = csrf_input.get('value', '')
                    redir = redir_input.get('value', '')
                    
                    await client.post(
                        f'{PACKETSTORM_BASE_URL}/tos/',
                        data={'csrf': csrf, 'redir': redir, 'go': 'Accept'},
                        timeout=60.0
                    )
                    
                    response = await client.get(url, timeout=60.0)
                    response.raise_for_status()
            
            return response.text
        except httpx.HTTPError as e:
            print(f"HTTP error fetching {url}: {e}")
            return None
        except Exception as e:
            print(f"Error fetching {url}: {e}")
            return None
    
    async def fetch_exploit_details(self, client: httpx.AsyncClient, url: str) -> Dict[str, Any]:
        """Fetch detailed information from an exploit page."""
        details = {
            'description': '',
            'exploit_code': '',
            'author': '',
            'platform': '',
            'software': '',
            'version': '',
            'exploit_type': '',
            'published_date': '',
            'tags': [],
            'vendor_homepage': '',
            'software_link': '',
            'tested_on': ''
        }
        
        try:
            response = await client.get(url, timeout=60.0)
            
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'lxml')
            
            tos_form = soup.find('form', action='/tos/')
            if tos_form:
                csrf_input = tos_form.find('input', {'name': 'csrf'})
                redir_input = tos_form.find('input', {'name': 'redir'})
                
                if csrf_input and redir_input:
                    csrf = csrf_input.get('value', '')
                    redir = redir_input.get('value', '')
                    
                    await client.post(
                        f'{PACKETSTORM_BASE_URL}/tos/',
                        data={'csrf': csrf, 'redir': redir, 'go': 'Accept'},
                        timeout=60.0
                    )
                    
                    response = await client.get(url, timeout=60.0)
                    soup = BeautifulSoup(response.text, 'lxml')
            
            pre_blocks = soup.find_all('pre')
            if pre_blocks:
                exploit_text = pre_blocks[0].get_text(strip=False)[:10000]
                details['exploit_code'] = exploit_text
                
                # Parse standard exploit format
                lines = exploit_text.split('\n')
                for line in lines:
                    line = line.strip()
                    if line.startswith('# Exploit Title:'):
                        details['exploit_type'] = line.replace('# Exploit Title:', '').strip()[:100]
                    elif line.startswith('# Date:'):
                        details['published_date'] = line.replace('# Date:', '').strip()[:50]
                    elif line.startswith('# Exploit Author:'):
                        details['author'] = line.replace('# Exploit Author:', '').strip()[:200]
                    elif line.startswith('# Vendor Homepage:'):
                        details['vendor_homepage'] = line.replace('# Vendor Homepage:', '').strip()[:500]
                    elif line.startswith('# Software Link:'):
                        details['software_link'] = line.replace('# Software Link:', '').strip()[:500]
                    elif line.startswith('# Version:'):
                        details['version'] = line.replace('# Version:', '').strip()[:100]
                    elif line.startswith('# Tested on:'):
                        details['tested_on'] = line.replace('# Tested on:', '').strip()[:200]
                    elif line.startswith('# Description:'):
                        details['description'] = line.replace('# Description:', '').strip()[:5000]
            
            # Find tags from page
            tags = soup.find_all('a', rel='tag')
            if tags:
                details['tags'] = [tag.get_text(strip=True)[:50] for tag in tags]
            
            # Find time elements
            date_elem = soup.find('time') or soup.find('span', class_='date')
            if date_elem and not details['published_date']:
                details['published_date'] = date_elem.get_text(strip=True)[:50]
            
        except Exception as e:
            print(f"Error parsing exploit details for {url}: {e}")
        
        return details
    
    def extract_cve_ids(self, text: str) -> List[str]:
        """Extract CVE IDs from text."""
        cves = self.cve_pattern.findall(text)
        return list(set(cves))
    
    def parse_page_for_advisories(self, html: str, page_url: str, only_cve: bool = False) -> List[Dict[str, Any]]:
        """Comprehensive advisory parsing using multiple strategies.
        
        Args:
            html: Page HTML content
            page_url: Source page URL
            only_cve: If True, only collect items with CVE IDs; if False, collect all exploits
        """
        from bs4 import BeautifulSoup
        advisories = []
        soup = BeautifulSoup(html, 'lxml')
        
        processed_urls = set()
        
        # Strategy 1: Parse tables for exploit listings (main data tables)
        tables = soup.find_all('table')
        for table in tables:
            rows = table.find_all('tr')
            for row in rows:
                cells = row.find_all('td')
                if len(cells) >= 4:
                    for cell in cells:
                        links = cell.find_all('a', href=True)
                        for link in links:
                            href = link.get('href', '')
                            text = link.get_text(strip=True)
                            
                            if '/files/id/' in href and href not in processed_urls:
                                processed_urls.add(href)
                                full_url = urljoin(PACKETSTORM_BASE_URL, href)
                                title = text[:500] if text else 'Packet Storm Advisory'
                                
                                row_text = str(row)
                                cves = self.extract_cve_ids(row_text)
                                
                                if not only_cve or cves:
                                    advisories.append({
                                        'title': title,
                                        'url': full_url,
                                        'cve_ids': cves
                                    })
        
        # Strategy 2: Look for all links with /files/id/ pattern
        links = soup.find_all('a', href=True)
        for link in links:
            href = link.get('href', '')
            text = link.get_text(strip=True)
            
            if '/files/id/' in href and href not in processed_urls:
                processed_urls.add(href)
                full_url = urljoin(PACKETSTORM_BASE_URL, href)
                title = text[:500] if text else 'Packet Storm Advisory'
                
                full_text = str(link.parent) if link.parent else text
                cves = self.extract_cve_ids(full_text)
                
                if not only_cve or cves:
                    advisories.append({
                        'title': title,
                        'url': full_url,
                        'cve_ids': cves
                    })
        
        # Strategy 3: Look for CVE patterns in the entire page and find nearby context
        if only_cve:
            cve_matches = list(self.cve_pattern.finditer(html))
            
            for match in cve_matches[:100]:
                start = max(0, match.start() - 1000)
                end = min(len(html), match.end() + 1000)
                context = html[start:end]
                
                context_soup = BeautifulSoup(context, 'lxml')
                link = context_soup.find('a', href=True)
                
                if link:
                    href = link.get('href', '')
                    if '/files/id/' in href and href not in processed_urls:
                        processed_urls.add(href)
                        full_url = urljoin(PACKETSTORM_BASE_URL, href)
                        link_text = link.get_text(strip=True)
                        
                        cves_in_context = self.extract_cve_ids(context)
                        
                        advisories.append({
                            'title': link_text[:500] if link_text else 'Packet Storm Advisory',
                            'url': full_url,
                            'cve_ids': cves_in_context
                        })
        
        return advisories
    
    async def collect_advisories(self, client: httpx.AsyncClient, max_pages_per_source: int = 10, crawl_all: bool = False, only_cve: bool = False, sources_to_crawl: list = None, start_page: int = 1, db: Session = None, save_to_packetstorm_table: bool = True, limit: int = 0) -> List[Dict[str, Any]]:
        """Collect advisories from multiple sources.
        
        Args:
            client: HTTP client
            max_pages_per_source: Maximum pages per source (default: 10)
            crawl_all: If True, crawl until no more data is found
            only_cve: If True, only collect items with CVE IDs
            sources_to_crawl: List of source names to crawl (e.g., ['exploits']). If None, crawl all sources.
            start_page: Page number to start crawling from (default: 1)
            db: Database session for immediate saving
            save_to_packetstorm_table: If True, save to packetstorm_exploits table; else save to references table
            limit: Maximum number of records to save (0 = unlimited)
        """
        all_advisories = []
        total_added = 0
        all_sources = [
            ('advisories', PACKETSTORM_ADVISORY_URL),
            ('exploits', 'https://packetstorm.news/files/exploit/'),
            ('latest', 'https://packetstorm.news/files/latest/'),
            ('search-cve', 'https://packetstorm.news/search/?q=CVE&a=files'),
        ]
        
        if sources_to_crawl:
            sources = [(name, url) for name, url in all_sources if name in sources_to_crawl]
        else:
            sources = all_sources
        
        for source_name, base_url in sources:
            print(f"\nCollecting from {source_name}...")

            page = start_page
            empty_page_count = 0
            first_empty_page = None
            pages_crawled = 0

            while True:
                url = f"{base_url.rstrip('/')}/{page}"

                print(f"  Fetching page {page}: {url}")

                html = await self.fetch_page(client, url)
                if html:
                    advisories = self.parse_page_for_advisories(html, url, only_cve=only_cve)
                    print(f"  Found {len(advisories)} advisories on page {page}")

                    if advisories:
                        all_advisories.extend(advisories)
                        empty_page_count = 0
                        first_empty_page = None

                        if db:
                            if save_to_packetstorm_table:
                                added = self.save_to_packetstorm_table(advisories, db, limit=limit - total_added if limit > 0 else len(advisories) * 10)
                            else:
                                added = self.save_references_to_db(advisories, db, limit=limit - total_added if limit > 0 else len(advisories) * 10)
                            total_added += added
                            print(f"  Saved {added} records to database (total: {total_added})")
                    else:
                        if first_empty_page is None:
                            first_empty_page = page
                        empty_page_count += 1
                        if crawl_all and empty_page_count >= 3:
                            print(f"  No more data found after 3 empty pages. Waiting 10 seconds...")
                            await asyncio.sleep(10)
                            page = first_empty_page
                            empty_page_count = 0
                            first_empty_page = None
                            continue
                pages_crawled += 1
                page += 1

                if pages_crawled % 10 == 0:
                    print(f"  Crawled {pages_crawled} pages. Pausing for 10 seconds...")
                    await asyncio.sleep(10)

                if not crawl_all and pages_crawled >= max_pages_per_source:
                    print(f"  Reached max pages ({max_pages_per_source}). Stopping.")
                    break

                await asyncio.sleep(1.5)
        
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
                else:
                    current_sources = cve.data_sources or []
                    if 'packetstorm' not in current_sources:
                        cve.data_sources = current_sources + ['packetstorm']
                
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
    
    def save_to_packetstorm_table(self, advisories: List[Dict[str, Any]], db: Session, limit: int = 100) -> int:
        """Save advisories to packetstorm_exploits table."""
        added = 0
        updated = 0
        
        for advisory in advisories:
            if added >= limit:
                break
            
            title = advisory.get('title', '')
            url = advisory.get('url', '')
            cve_ids = advisory.get('cve_ids', [])
            details = advisory.get('details', {})
            
            if not url:
                continue
            
            packetstorm_id = self.extract_packetstorm_id(url)
            
            existing = db.query(PacketStormExploit).filter(
                PacketStormExploit.url == url[:500]
            ).first()
            
            if existing:
                if details:
                    existing.description = details.get('description', '')[:5000] or existing.description
                    existing.exploit_code = details.get('exploit_code', '')[:10000] or existing.exploit_code
                    existing.author = details.get('author', '')[:200] or existing.author
                    existing.platform = details.get('tested_on', '')[:200] or existing.platform
                    existing.exploit_type = details.get('exploit_type', '')[:100] or existing.exploit_type
                    existing.version = details.get('version', '')[:100] or existing.version
                    existing.tags = ','.join(details.get('tags', []))[:500] or existing.tags
                    
                    if details.get('published_date'):
                        try:
                            from datetime import datetime
                            existing.published_date = datetime.strptime(details['published_date'], '%Y-%m-%d')
                        except:
                            pass
                    
                    try:
                        db.commit()
                        updated += 1
                    except Exception as e:
                        db.rollback()
                        print(f"Error updating packetstorm exploit: {e}")
                continue
            
            exploit = PacketStormExploit(
                packetstorm_id=packetstorm_id,
                cve_ids=','.join(cve_ids) if cve_ids else None,
                title=title[:500] if title else None,
                url=url[:500],
                category='exploit',
                description=details.get('description', '')[:5000],
                exploit_code=details.get('exploit_code', '')[:10000],
                author=details.get('author', '')[:200],
                platform=details.get('tested_on', '')[:200],
                software=details.get('software', '')[:200],
                version=details.get('version', '')[:100],
                exploit_type=details.get('exploit_type', '')[:100],
                tags=','.join(details.get('tags', []))[:500],
            )
            
            if details.get('published_date'):
                try:
                    from datetime import datetime
                    exploit.published_date = datetime.strptime(details['published_date'], '%Y-%m-%d')
                except:
                    pass
            
            db.add(exploit)
            
            try:
                db.commit()
                added += 1
            except Exception as e:
                db.rollback()
                print(f"Error saving packetstorm exploit: {e}")
        
        if updated > 0:
            print(f"Updated {updated} existing records with details")
        
        return added
    
    def extract_packetstorm_id(self, url: str) -> str:
        """Extract the packetstorm ID from URL."""
        import re
        match = re.search(r'/files/id/(\d+)/?', url)
        if match:
            return match.group(1)
        return ''
    
    async def sync(self, limit: int = 100, crawl_all: bool = False, max_pages: int = 10, only_cve: bool = False, sources: list = None, save_to_packetstorm_table: bool = True, fetch_details: bool = False, start_page: int = 1):
        """Main sync method.
        
        Args:
            limit: Maximum number of records to save (0 = unlimited)
            crawl_all: If True, crawl all available pages until no more data
            max_pages: Maximum pages per source when crawl_all is False
            only_cve: If True, only collect items with CVE IDs; if False, collect all exploits
            sources: List of source names to crawl (e.g., ['exploits']). If None, crawl all sources.
            save_to_packetstorm_table: If True, save to packetstorm_exploits table; else save to references table
            fetch_details: If True, fetch detailed information from each exploit page
            start_page: Page number to start crawling from (default: 1)
        """
        print("=" * 60)
        print("Starting Packet Storm Security Crawler")
        print("=" * 60)
        print(f"  Mode: {'Full crawl' if crawl_all else f'Limited ({max_pages} pages/source)'}")
        print(f"  Save limit: {'Unlimited' if limit == 0 else limit}")
        print(f"  Filter: {'CVE only' if only_cve else 'All exploits'}")
        print(f"  Sources: {', '.join(sources) if sources else 'All'}")
        print(f"  Target Table: {'packetstorm_exploits' if save_to_packetstorm_table else 'references'}")
        print(f"  Fetch Details: {'Yes' if fetch_details else 'No'}")
        print(f"  Start Page: {start_page}")
        print("=" * 60)
        
        async with httpx.AsyncClient(headers=self.headers, follow_redirects=True, timeout=httpx.Timeout(60.0), proxy="http://10.0.0.119:10811") as client:
            await self.accept_tos(client)

            db = SessionLocal()
            try:
                print("\nCollecting advisories...")
                advisories = await self.collect_advisories(client, max_pages_per_source=max_pages, crawl_all=crawl_all, only_cve=only_cve, sources_to_crawl=sources, start_page=start_page, db=db, save_to_packetstorm_table=save_to_packetstorm_table, limit=limit)
            finally:
                db.close()
            
            print(f"\nTotal unique advisories found: {len(advisories)}")
            
            # 统计有/无 CVE 的数量
            with_cve = sum(1 for adv in advisories if adv['cve_ids'])
            without_cve = len(advisories) - with_cve
            print(f"  - With CVE: {with_cve}")
            print(f"  - Without CVE: {without_cve}")
            
            # 获取详情
            if fetch_details and advisories:
                print("\nFetching exploit details...")
                save_limit = limit if limit > 0 else len(advisories)
                for i, advisory in enumerate(advisories[:save_limit], 1):
                    url = advisory.get('url', '')
                    if url:
                        print(f"  [{i}/{save_limit}] Fetching details for: {url}")
                        details = await self.fetch_exploit_details(client, url)
                        advisory['details'] = details
                        await asyncio.sleep(0.5)
            
            if advisories:
                print("\nSample advisories:")
                for i, adv in enumerate(advisories[:5]):
                    print(f"  {i+1}. {adv['title'][:60]}...")
                    print(f"     URL: {adv['url']}")
                    print(f"     CVEs: {', '.join(adv['cve_ids']) if adv['cve_ids'] else '(None)'}")
                    if adv.get('details'):
                        has_code = 'Yes' if adv['details'].get('exploit_code') else 'No'
                        print(f"     Has Exploit Code: {has_code}")
            
            added = 0
            if advisories:
                print("\nSaving to database...")
                db = SessionLocal()
                try:
                    save_limit = limit if limit > 0 else len(advisories) * 10  # No limit means save all
                    if save_to_packetstorm_table:
                        added = self.save_to_packetstorm_table(advisories, db, limit=save_limit)
                        print(f"\nSuccessfully saved {added} records to packetstorm_exploits!")
                    else:
                        added = self.save_references_to_db(advisories, db, limit=save_limit)
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
    import argparse
    parser = argparse.ArgumentParser(description='Packet Storm Security Crawler')
    parser.add_argument('--crawl-all', action='store_true', help='Crawl all pages until no more data')
    parser.add_argument('--max-pages', type=int, default=10, help='Max pages per source (when not crawling all)')
    parser.add_argument('--limit', type=int, default=0, help='Max records to save (0 = unlimited)')
    parser.add_argument('--only-cve', action='store_true', help='Only collect items with CVE IDs')
    parser.add_argument('--sources', type=str, nargs='+', choices=['advisories', 'exploits', 'latest', 'search-cve'], 
                        help='Specify sources to crawl (default: all)')
    parser.add_argument('--save-to-references', action='store_true', help='Save to references table instead of packetstorm_exploits')
    parser.add_argument('--fetch-details', action='store_true', help='Fetch detailed information from each exploit page')
    parser.add_argument('--start-page', type=int, default=1, help='Page number to start crawling from (default: 1)')
    args = parser.parse_args()
    
    crawler = PacketStormCrawler()
    asyncio.run(crawler.sync(
        limit=args.limit, 
        crawl_all=args.crawl_all, 
        max_pages=args.max_pages, 
        only_cve=args.only_cve, 
        sources=args.sources,
        save_to_packetstorm_table=not args.save_to_references,
        fetch_details=args.fetch_details,
        start_page=args.start_page
    ))
