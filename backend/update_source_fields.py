"""
Update existing UnifiedVulnerability source fields from data_sources
"""
from app.database import SessionLocal
from app.models import UnifiedVulnerability

def update_source_fields():
    db = SessionLocal()
    try:
        print('Querying UnifiedVulnerability records with source=None...')
        vulns = db.query(UnifiedVulnerability).filter(
            UnifiedVulnerability.source == None,
            UnifiedVulnerability.data_sources != None
        ).all()
        
        print(f'Found {len(vulns)} records to update')
        
        updated_count = 0
        for vuln in vulns:
            if vuln.data_sources and len(vuln.data_sources) > 0:
                # Determine source
                source = None
                for s in ['nvd', 'cvelistv5', 'mitre']:
                    if s in vuln.data_sources:
                        source = s
                        break
                if source is None:
                    source = vuln.data_sources[0]
                
                vuln.source = source
                updated_count += 1
                
                if updated_count % 100 == 0:
                    print(f'  Updated {updated_count} records...')
                    db.commit()
        
        db.commit()
        print(f'Successfully updated {updated_count} records')
        return updated_count
    except Exception as e:
        db.rollback()
        print(f'Error: {e}')
        import traceback
        traceback.print_exc()
        return 0
    finally:
        db.close()

if __name__ == '__main__':
    print('Starting source field update...')
    count = update_source_fields()
    print(f'Update complete, {count} records updated')
