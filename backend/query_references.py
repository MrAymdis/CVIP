#!/usr/bin/env python3
"""
Query references table from database
"""
import sys
from app.database import SessionLocal
from app.models import Reference

def query_references(limit=100, source=None):
    """Query references from database"""
    db = SessionLocal()
    try:
        if source:
            references = db.query(Reference).filter(Reference.source == source).limit(limit).all()
        else:
            references = db.query(Reference).limit(limit).all()
        
        print(f"Found {len(references)} references")
        print("=" * 120)
        print(f"{'ID':<5} {'CVE ID':<15} {'Source':<12} {'Title':<40} {'URL':<40}")
        print("=" * 120)
        
        for ref in references:
            title = ref.title or ''
            title_display = title[:37] + '...' if len(title) > 40 else title
            url = ref.url or ''
            url_display = url[:37] + '...' if len(url) > 40 else url
            print(f"{ref.id:<5} {ref.cve_id:<15} {ref.source:<12} {title_display:<40} {url_display:<40}")
        
        print("=" * 120)
        
    finally:
        db.close()

if __name__ == "__main__":
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    source = sys.argv[2] if len(sys.argv) > 2 else None
    query_references(limit, source)
