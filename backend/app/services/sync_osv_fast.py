import json
from sqlalchemy.orm import Session
from app.models import OSVVulnerability, UnifiedVulnerability
from app.database import SessionLocal
from sqlalchemy import func


def osv_to_unified_dict(osv: OSVVulnerability) -> dict:
    severity_info = osv.severity or []
    cvss_scores = []
    primary_severity = None
    primary_cvss_v3_score = None
    primary_cvss_v3_vector = None
    
    for sev in severity_info:
        if isinstance(sev, dict):
            version = sev.get("type", "").replace("CVSS_V", "3.")
            score = sev.get("score")
            vector = sev.get("vector")
            
            if score is not None and isinstance(score, str):
                try:
                    score = float(score)
                except (ValueError, TypeError):
                    score = None
            
            severity_label = None
            if score is not None and isinstance(score, (int, float)):
                if score >= 9.0:
                    severity_label = "CRITICAL"
                elif score >= 7.0:
                    severity_label = "HIGH"
                elif score >= 4.0:
                    severity_label = "MEDIUM"
                elif score >= 0.1:
                    severity_label = "LOW"
                else:
                    severity_label = "NONE"
            
            cvss_scores.append({
                "version": version,
                "score": score,
                "severity": severity_label,
                "vector": vector
            })
            
            if sev.get("type") == "CVSS_V3":
                primary_severity = severity_label
                primary_cvss_v3_score = score
                primary_cvss_v3_vector = vector
    
    return {
        "vuln_id": osv.osv_id,
        "type": "osv",
        "title": osv.summary,
        "title_zh": None,
        "description": osv.details,
        "description_zh": None,
        "severity": primary_severity,
        "cvss_scores": cvss_scores if cvss_scores else None,
        "cvss_v3_score": primary_cvss_v3_score,
        "cvss_v3_vector": primary_cvss_v3_vector,
        "cvss_v4_score": None,
        "cvss_v4_vector": None,
        "epss_score": None,
        "epss_percentile": None,
        "cwes": None,
        "cisa_kev": None,
        "cisa_kev_date_added": None,
        "cisa_due_date": None,
        "cisa_required_action": None,
        "published_date": osv.published,
        "modified_date": osv.modified,
        "withdrawn_date": osv.withdrawn,
        "aliases": osv.aliases,
        "related": osv.related,
        "affected": osv.affected,
        "references": osv.references,
        "fixes": None,
        "source": None,
        "data_sources": None,
        "tags": None,
        "related_cve_ids": None,
        "exploits_count": osv.exploits_count,
        "view_count": 0,
        "original_data": json.dumps({
            "id": osv.id,
            "osv_id": osv.osv_id,
            "schema_version": osv.schema_version,
            "published": osv.published.isoformat() if osv.published else None,
            "modified": osv.modified.isoformat() if osv.modified else None,
            "withdrawn": osv.withdrawn.isoformat() if osv.withdrawn else None,
            "aliases": osv.aliases,
            "related": osv.related,
            "summary": osv.summary,
            "details": osv.details,
            "affected": osv.affected,
            "references": osv.references,
            "severity": osv.severity,
            "database_specific": osv.database_specific,
            "exploits_count": osv.exploits_count
        })
    }


def sync_osv_fast(db: Session, batch_size: int = 1000):
    print('=' * 60)
    print('Starting FAST OSV sync...')
    print('=' * 60)
    
    # 1. 先获取已存在的ID，用集合快速查找
    print('Loading existing OSV IDs...')
    existing_query = db.query(UnifiedVulnerability.vuln_id).filter(
        UnifiedVulnerability.type == 'osv'
    )
    existing_ids = {row[0] for row in existing_query.yield_per(10000)}
    print(f'  Found {len(existing_ids)} existing OSV records')
    
    # 2. 获取OSV总数
    total_count = db.query(func.count(OSVVulnerability.id)).scalar()
    print(f'  Total OSV records: {total_count}')
    
    added_count = 0
    last_progress = 0
    
    # 3. 用yield_per流式读取数据，避免内存溢出
    print('Starting bulk processing...')
    for offset in range(0, total_count, batch_size):
        # 显示进度
        if (offset - last_progress) >= 20000 or offset == 0:
            print(f'  Progress: {offset}/{total_count} ({(offset/total_count*100):.1f}%) - added {added_count}')
            last_progress = offset
        
        # 获取当前批次
        batch = db.query(OSVVulnerability).limit(batch_size).offset(offset).all()
        
        # 过滤需要插入的数据
        to_insert = []
        for item in batch:
            if item.osv_id not in existing_ids:
                to_insert.append(osv_to_unified_dict(item))
        
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
                sub_batch_size = 100
                for i in range(0, len(to_insert), sub_batch_size):
                    sub_batch = to_insert[i:i+sub_batch_size]
                    try:
                        db.bulk_insert_mappings(UnifiedVulnerability, sub_batch)
                        db.commit()
                        added_count += len(sub_batch)
                    except Exception as e2:
                        db.rollback()
                        # 还不行就跳过这个子批次
                        continue
    
    print('=' * 60)
    print(f'OSV sync completed! Added {added_count} new records')
    print('=' * 60)
    return added_count


if __name__ == "__main__":
    db = SessionLocal()
    try:
        import time
        start = time.time()
        
        osv_added = sync_osv_fast(db)
        
        elapsed = time.time() - start
        print(f'\nTotal time: {elapsed:.2f} seconds')
        
    except Exception as e:
        print(f'Sync error: {e}')
        import traceback
        traceback.print_exc()
    finally:
        db.close()
