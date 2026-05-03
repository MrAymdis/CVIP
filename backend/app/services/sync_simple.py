import json
from sqlalchemy.orm import Session
from app.models import OSVVulnerability, GitHubAdvisory, UnifiedVulnerability
from app.database import SessionLocal


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
            
            # 确保score是数值类型
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
        "description": osv.details,
        "severity": primary_severity,
        "cvss_scores": cvss_scores if cvss_scores else None,
        "cvss_v3_score": primary_cvss_v3_score,
        "cvss_v3_vector": primary_cvss_v3_vector,
        "published_date": osv.published,
        "modified_date": osv.modified,
        "withdrawn_date": osv.withdrawn,
        "aliases": osv.aliases,
        "related": osv.related,
        "affected": osv.affected,
        "references": osv.references,
        "exploits_count": osv.exploits_count,
        "view_count": 0,
        "original_data": json.dumps({
            "id": osv.id,
            "osv_id": osv.osv_id
        })
    }


def ghsa_to_unified_dict(ghsa: GitHubAdvisory) -> dict:
    related_cve_ids = []
    if ghsa.cve_id:
        related_cve_ids.append(ghsa.cve_id)
    
    cvss_scores = []
    if ghsa.cvss_score is not None:
        cvss_scores.append({
            "version": "3.1",
            "score": ghsa.cvss_score,
            "severity": ghsa.severity,
            "vector": ghsa.cvss_vector
        })
    
    return {
        "vuln_id": ghsa.ghsa_id,
        "type": "ghsa",
        "title": ghsa.summary,
        "description": ghsa.description,
        "severity": ghsa.severity,
        "cvss_scores": cvss_scores if cvss_scores else None,
        "cvss_v3_score": ghsa.cvss_score,
        "cvss_v3_vector": ghsa.cvss_vector,
        "published_date": ghsa.published_at,
        "modified_date": ghsa.updated_at,
        "withdrawn_date": ghsa.withdrawn_at,
        "aliases": ghsa.aliases,
        "affected": ghsa.affected_packages,
        "references": ghsa.references,
        "fixes": ghsa.patched_versions,
        "related_cve_ids": related_cve_ids if related_cve_ids else None,
        "view_count": 0,
        "original_data": json.dumps({
            "id": ghsa.id,
            "ghsa_id": ghsa.ghsa_id
        })
    }


def sync_simple(db: Session, source_type: str, converter_func, source_model):
    print(f'Syncing {source_type}...')
    
    # 查询已存在的
    existing_vulns = db.query(UnifiedVulnerability.vuln_id).filter(
        UnifiedVulnerability.type == source_type
    ).all()
    existing_ids = {r[0] for r in existing_vulns}
    print(f'  Found {len(existing_ids)} existing {source_type} records')
    
    # 获取总数
    total_count = db.query(source_model.id).count()
    print(f'  Found {total_count} {source_type} records')
    
    added_count = 0
    for offset in range(0, total_count, 1000):
        if offset % 10000 == 0:
            print(f'  Processing {source_type} batch {offset}-{offset+999} (added {added_count} so far)')
        
        batch = db.query(source_model).limit(1000).offset(offset).all()
        
        for item in batch:
            if hasattr(item, 'osv_id'):
                vuln_id = item.osv_id
            elif hasattr(item, 'ghsa_id'):
                vuln_id = item.ghsa_id
            else:
                continue
            
            if vuln_id not in existing_ids:
                try:
                    item_dict = converter_func(item)
                    vuln = UnifiedVulnerability(**item_dict)
                    db.add(vuln)
                    db.commit()
                    added_count += 1
                except Exception as e:
                    db.rollback()
                    # 继续处理下一个，跳过错误
    
    print(f'  Done {source_type}! Added {added_count} new records')
    return added_count


def get_stats(db: Session) -> dict:
    from sqlalchemy import func
    total = db.query(func.count(UnifiedVulnerability.id)).scalar()
    by_type = db.query(
        UnifiedVulnerability.type,
        func.count(UnifiedVulnerability.id)
    ).group_by(UnifiedVulnerability.type).all()
    
    result = {
        "total": total,
        "by_type": dict(by_type)
    }
    return result


if __name__ == "__main__":
    db = SessionLocal()
    try:
        print('Starting sync...')
        import time
        start = time.time()
        
        # 先同步OSV
        osv_added = sync_simple(db, 'osv', osv_to_unified_dict, OSVVulnerability)
        
        # 再同步GHSA
        ghsa_added = sync_simple(db, 'ghsa', ghsa_to_unified_dict, GitHubAdvisory)
        
        elapsed = time.time() - start
        print(f'Sync completed in {elapsed:.2f} seconds')
        
        final_stats = get_stats(db)
        print(f'Final DB stats: {final_stats}')
    except Exception as e:
        print(f'Sync error: {e}')
        import traceback
        traceback.print_exc()
    finally:
        db.close()
