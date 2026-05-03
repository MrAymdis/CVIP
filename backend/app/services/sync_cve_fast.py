import json
from sqlalchemy.orm import Session
from app.models import CVE, UnifiedVulnerability, Reference
from app.database import SessionLocal
from sqlalchemy import func


def extract_cve_references(db: Session, cve_id: str) -> list:
    references = db.query(Reference).filter(Reference.cve_id == cve_id).all()
    result = []
    for ref in references:
        result.append({
            "url": ref.url,
            "title": ref.title,
            "source": ref.source,
            "ref_type": ref.ref_type
        })
    return result


def cve_to_unified_dict(cve: CVE, db: Session) -> dict:
    references = extract_cve_references(db, cve.cve_id)
    
    cvss_scores = []
    if cve.cvss_v3_score is not None:
        cvss_scores.append({
            "version": "3.1",
            "score": cve.cvss_v3_score,
            "severity": cve.cvss_v3_severity,
            "vector": cve.cvss_v3_vector
        })
    if cve.cvss_v4_score is not None:
        cvss_scores.append({
            "version": "4.0",
            "score": cve.cvss_v4_score,
            "severity": cve.cvss_v4_severity,
            "vector": cve.cvss_v4_vector
        })
    
    return {
        "vuln_id": cve.cve_id,
        "type": "cve",
        "title": cve.title,
        "title_zh": cve.title_zh,
        "description": cve.description,
        "description_zh": cve.description_zh,
        "severity": cve.cvss_v3_severity,
        "cvss_scores": cvss_scores if cvss_scores else None,
        "cvss_v3_score": cve.cvss_v3_score,
        "cvss_v3_vector": cve.cvss_v3_vector,
        "cvss_v4_score": cve.cvss_v4_score,
        "cvss_v4_vector": cve.cvss_v4_vector,
        "epss_score": cve.epss_score,
        "epss_percentile": cve.epss_percentile,
        "cwes": cve.cwes,
        "cisa_kev": cve.cisa_kev,
        "cisa_kev_date_added": cve.cisa_kev_date_added,
        "cisa_due_date": cve.cisa_due_date,
        "cisa_required_action": cve.cisa_required_action,
        "published_date": cve.published_date,
        "modified_date": cve.modified_date,
        "affected": cve.affected_versions,
        "references": references if references else None,
        "fixes": None,
        "source": None,
        "data_sources": cve.data_sources,
        "tags": None,
        "related_cve_ids": None,
        "exploits_count": cve.exploits_count,
        "view_count": 0,
        "original_data": json.dumps({
            "id": cve.id,
            "cve_id": cve.cve_id,
            "title": cve.title,
            "title_zh": cve.title_zh,
            "description": cve.description,
            "description_zh": cve.description_zh,
            "cvss_v3_score": cve.cvss_v3_score,
            "cvss_v3_severity": cve.cvss_v3_severity,
            "cvss_v3_vector": cve.cvss_v3_vector,
            "cvss_v4_score": cve.cvss_v4_score,
            "cvss_v4_severity": cve.cvss_v4_severity,
            "cvss_v4_vector": cve.cvss_v4_vector,
            "epss_score": cve.epss_score,
            "epss_percentile": cve.epss_percentile,
            "cisa_kev": cve.cisa_kev,
            "cisa_kev_date_added": cve.cisa_kev_date_added.isoformat() if cve.cisa_kev_date_added else None,
            "cisa_due_date": cve.cisa_due_date.isoformat() if cve.cisa_due_date else None,
            "cisa_required_action": cve.cisa_required_action,
            "vendor_id": cve.vendor_id,
            "product_id": cve.product_id,
            "published_date": cve.published_date.isoformat() if cve.published_date else None,
            "modified_date": cve.modified_date.isoformat() if cve.modified_date else None,
            "cwes": cve.cwes,
            "references_count": cve.references_count,
            "exploits_count": cve.exploits_count,
            "data_sources": cve.data_sources,
            "affected_versions": cve.affected_versions
        })
    }


def sync_cve_fast(db: Session, batch_size: int = 500):
    print('=' * 60)
    print('Starting FAST CVE sync...')
    print('=' * 60)
    
    # 1. 先获取已存在的ID
    print('Loading existing CVE IDs...')
    existing_query = db.query(UnifiedVulnerability.vuln_id).filter(
        UnifiedVulnerability.type == 'cve'
    )
    existing_ids = {row[0] for row in existing_query.yield_per(10000)}
    print(f'  Found {len(existing_ids)} existing CVE records')
    
    # 2. 获取CVE总数
    total_count = db.query(func.count(CVE.id)).scalar()
    print(f'  Total CVE records: {total_count}')
    
    added_count = 0
    last_progress = 0
    
    # 3. 批量处理
    print('Starting bulk processing...')
    for offset in range(0, total_count, batch_size):
        # 显示进度
        if (offset - last_progress) >= 10000 or offset == 0:
            print(f'  Progress: {offset}/{total_count} ({(offset/total_count*100):.1f}%) - added {added_count}')
            last_progress = offset
        
        # 获取当前批次
        batch = db.query(CVE).limit(batch_size).offset(offset).all()
        
        # 过滤需要插入的数据
        to_insert = []
        for item in batch:
            if item.cve_id not in existing_ids:
                item_dict = cve_to_unified_dict(item, db)
                to_insert.append(item_dict)
        
        if to_insert:
            # 尝试批量插入
            try:
                db.bulk_insert_mappings(UnifiedVulnerability, to_insert)
                db.commit()
                added_count += len(to_insert)
            except Exception as e:
                db.rollback()
                print(f'  Batch failed at offset {offset}, trying smaller batches...')
                # 分更小的批次
                sub_batch_size = 50
                for i in range(0, len(to_insert), sub_batch_size):
                    sub_batch = to_insert[i:i+sub_batch_size]
                    try:
                        db.bulk_insert_mappings(UnifiedVulnerability, sub_batch)
                        db.commit()
                        added_count += len(sub_batch)
                    except Exception as e2:
                        db.rollback()
                        continue
    
    print('=' * 60)
    print(f'CVE sync completed! Added {added_count} new records')
    print('=' * 60)
    return added_count


if __name__ == "__main__":
    db = SessionLocal()
    try:
        import time
        start = time.time()
        
        cve_added = sync_cve_fast(db)
        
        elapsed = time.time() - start
        print(f'\nTotal time: {elapsed:.2f} seconds')
        
    except Exception as e:
        print(f'Sync error: {e}')
        import traceback
        traceback.print_exc()
    finally:
        db.close()
