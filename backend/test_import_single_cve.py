#!/usr/bin/env python3
"""Test script to import a single CVE and verify affected versions"""
import sys
import json
from pathlib import Path
from app.database import SessionLocal
from app.crawlers.cvelistv5_crawler_v2 import CVEListV5CrawlerV2

def test_single_cve_import():
    """Test importing a single CVE"""
    # Path to CVE-2025-69288
    cve_path = Path(__file__).parent / "cvelistV5" / "cves" / "2025" / "69xxx" / "CVE-2025-69288.json"
    
    if not cve_path.exists():
        print(f"File not found: {cve_path}")
        return False
    
    print(f"Reading CVE from: {cve_path}")
    
    # Read and parse CVE
    with open(cve_path, 'r', encoding='utf-8') as f:
        cve_data = json.load(f)
    
    crawler = CVEListV5CrawlerV2()
    parsed = crawler.parse_cve_json(cve_data)
    
    if not parsed:
        print("Failed to parse CVE")
        return False
    
    print(f"Successfully parsed CVE: {parsed['cve_id']}")
    print(f"Title: {parsed['title']}")
    print(f"Affected versions: {json.dumps(parsed.get('affected_versions', []), indent=2)}")
    print(f"References: {json.dumps(parsed.get('references', []), indent=2)}")
    print(f"Exploits: {json.dumps(parsed.get('exploits', []), indent=2)}")
    
    # Save to database
    db = SessionLocal()
    try:
        success = crawler.save_cve_to_db(parsed, db)
        if success:
            db.commit()
            print(f"Successfully saved CVE to database")
            
            # Verify the saved data
            from app.models import CVE, Reference, Exploit
            cve = db.query(CVE).filter(CVE.cve_id == parsed['cve_id']).first()
            if cve:
                print(f"Database record found")
                print(f"  affected_versions: {json.dumps(cve.affected_versions, indent=2)}")
                
                # Check references
                refs = db.query(Reference).filter(Reference.cve_id == parsed['cve_id']).all()
                print(f"  References found: {len(refs)}")
                for ref in refs:
                    print(f"    - {ref.title}: {ref.url}")
                
                # Check exploits
                exps = db.query(Exploit).filter(Exploit.cve_id == parsed['cve_id']).all()
                print(f"  Exploits found: {len(exps)}")
                for exp in exps:
                    print(f"    - {exp.source}: {exp.source_url}")
            
        else:
            print("Failed to save CVE to database")
            db.rollback()
            return False
            
    except Exception as e:
        print(f"Error saving to database: {e}")
        db.rollback()
        import traceback
        traceback.print_exc()
        return False
    finally:
        db.close()
    
    return True

if __name__ == "__main__":
    success = test_single_cve_import()
    sys.exit(0 if success else 1)
