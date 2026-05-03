import json
from sqlalchemy.orm import Session
from app.models import CNVDVulnerability, UnifiedVulnerability
from app.database import SessionLocal
from sqlalchemy import func


def cnvd_to_unified_dict(cnvd: CNVDVulnerability) -> dict:
    cvss_scores = []
    if cnvd.cvss_v3_score is not None:
        cvss_scores.append({
            "version": "3.1",
            "score": cnvd.cvss_v3_score,
            "severity": cnvd.cvss_v3_severity,
            "vector": cnvd.cvss_v3_vector
        })
    
    return {
        "vuln_id": cnvd.vuln_id,
        "type": "cnvd",
        "title": cnvd.title,
        "title_zh": None,
        "description": cnvd.description,
        "description_zh": None,
        "severity": cnvd.severity,
        "cvss_scores": cvss_scores if cvss_scores else None,
        "cvss_v3_score": cnvd.cvss_v3_score,
        "cvss_v3_vector": cnvd.cvss_v3_vector,
        "cvss_v4_score": None,
        "cvss_v4_vector": None,
        "epss_score": None,
        "epss_percentile": None,
        "cwes": cnvd.cwe_ids,
        "cisa_kev": None,
        "cisa_kev_date_added": None,
        "cisa_due_date": None,
        "cisa_required_action": None,
        "published_date": cnvd.published_date,
        "modified_date": cnvd.modified_date,
        "affected": cnvd.affected_products,
        "references": cnvd.references,
        "fixes": [cnvd.solution] if cnvd.solution else None,
        "source": cnvd.source,
        "data_sources": cnvd.data_sources,
        "tags": cnvd.tags,
        "related_cve_ids": cnvd.related_cve_ids,
        "exploits_count": cnvd.exploits_count,
        "view_count": 0,
        "original_data": json.dumps({
            "id": cnvd.id,
            "vuln_id": cnvd.vuln_id,
            "title": cnvd.title,
            "description": cnvd.description,
            "source": cnvd.source,
            "severity": cnvd.severity,
            "cvss_v3_score": cnvd.cvss_v3_score,
            "cvss_v3_severity": cnvd.cvss_v3_severity,
            "cvss_v3_vector": cnvd.cvss_v3_vector,
            "published_date": cnvd.published_date.isoformat() if cnvd.published_date else None,
            "modified_date": cnvd.modified_date.isoformat() if cnvd.modified_date else None,
            "cwe_ids": cnvd.cwe_ids,
            "related_cve_ids": cnvd.related_cve_ids,
            "references": cnvd.references,
            "tags": cnvd.tags,
            "affected_products": cnvd.affected_products,
            "solution": cnvd.solution,
            "data_sources": cnvd.data_sources,
            "exploits_count": cnvd.exploits_count
        })
    }


def sync_cnvd_fast(db: Session, batch_size: int = 500, update_existing: bool = True):
    print('=' * 60)
    print('Starting FAST CNVD sync...')
    print('=' * 60)
    
    # 1. 先获取已存在的ID和它们的数据库ID
    print('Loading existing CNVD records...')
    existing_query = db.query(UnifiedVulnerability.id, UnifiedVulnerability.vuln_id).filter(
        UnifiedVulnerability.type == 'cnvd'
    )
    existing_map = {row[1]: row[0] for row in existing_query.yield_per(10000)}
    existing_ids = set(existing_map.keys())
    print(f'  Found {len(existing_ids)} existing CNVD records')
    
    # 2. 获取CNVD总数
    total_count = db.query(func.count(CNVDVulnerability.id)).scalar()
    print(f'  Total CNVD records: {total_count}')
    
    added_count = 0
    updated_count = 0
    last_progress = 0
    
    # 3. 批量处理
    print('Starting bulk processing...')
    for offset in range(0, total_count, batch_size):
        # 显示进度
        if (offset - last_progress) >= 10000 or offset == 0:
            print(f'  Progress: {offset}/{total_count} ({(offset/total_count*100):.1f}%) - added {added_count}, updated {updated_count}')
            last_progress = offset
        
        # 获取当前批次
        batch = db.query(CNVDVulnerability).limit(batch_size).offset(offset).all()
        
        # 准备要插入和更新的数据
        to_insert = []
        to_update = []
        
        for item in batch:
            item_dict = cnvd_to_unified_dict(item)
            if item.vuln_id not in existing_ids:
                # 新记录，准备插入
                to_insert.append(item_dict)
            elif update_existing:
                # 现有记录，准备更新
                item_dict['id'] = existing_map[item.vuln_id]
                to_update.append(item_dict)
        
        # 批量插入
        if to_insert:
            try:
                db.bulk_insert_mappings(UnifiedVulnerability, to_insert)
                db.commit()
                added_count += len(to_insert)
            except Exception as e:
                db.rollback()
                print(f'  Insert error at offset {offset}: {e}')
        
        # 批量更新
        if to_update:
            try:
                db.bulk_update_mappings(UnifiedVulnerability, to_update)
                db.commit()
                updated_count += len(to_update)
            except Exception as e:
                db.rollback()
                print(f'  Update error at offset {offset}: {e}')
    
    print('=' * 60)
    print(f'CNVD sync completed!')
    print(f'  Added {added_count} new records')
    print(f'  Updated {updated_count} existing records')
    print('=' * 60)
    return added_count, updated_count


if __name__ == "__main__":
    db = SessionLocal()
    try:
        import time
        start = time.time()
        
        cnvd_added, cnvd_updated = sync_cnvd_fast(db, update_existing=True)
        
        elapsed = time.time() - start
        print(f'\nTotal time: {elapsed:.2f} seconds')
        
    except Exception as e:
        print(f'Sync error: {e}')
        import traceback
        traceback.print_exc()
    finally:
        db.close()
