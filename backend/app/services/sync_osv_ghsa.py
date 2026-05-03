import json
from sqlalchemy.orm import Session
from datetime import datetime
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
        "title_zh": None,
        "description": ghsa.description,
        "description_zh": None,
        "severity": ghsa.severity,
        "cvss_scores": cvss_scores if cvss_scores else None,
        "cvss_v3_score": ghsa.cvss_score,
        "cvss_v3_vector": ghsa.cvss_vector,
        "cvss_v4_score": None,
        "cvss_v4_vector": None,
        "epss_score": None,
        "epss_percentile": None,
        "cwes": ghsa.cwe_ids,
        "cisa_kev": None,
        "cisa_kev_date_added": None,
        "cisa_due_date": None,
        "cisa_required_action": None,
        "published_date": ghsa.published_at,
        "modified_date": ghsa.updated_at,
        "withdrawn_date": ghsa.withdrawn_at,
        "aliases": ghsa.aliases,
        "affected": ghsa.affected_packages,
        "references": ghsa.references,
        "fixes": ghsa.patched_versions,
        "source": None,
        "data_sources": ghsa.data_sources,
        "tags": None,
        "related_cve_ids": related_cve_ids if related_cve_ids else None,
        "exploits_count": 0,
        "view_count": 0,
        "original_data": json.dumps({
            "id": ghsa.id,
            "ghsa_id": ghsa.ghsa_id,
            "cve_id": ghsa.cve_id,
            "aliases": ghsa.aliases,
            "summary": ghsa.summary,
            "description": ghsa.description,
            "severity": ghsa.severity,
            "cvss_score": ghsa.cvss_score,
            "cvss_vector": ghsa.cvss_vector,
            "cwe_ids": ghsa.cwe_ids,
            "affected_packages": ghsa.affected_packages,
            "patched_versions": ghsa.patched_versions,
            "unaffected_versions": ghsa.unaffected_versions,
            "references": ghsa.references,
            "github_url": ghsa.github_url,
            "repository_url": ghsa.repository_url,
            "published_at": ghsa.published_at.isoformat() if ghsa.published_at else None,
            "updated_at": ghsa.updated_at.isoformat() if ghsa.updated_at else None,
            "withdrawn_at": ghsa.withdrawn_at.isoformat() if ghsa.withdrawn_at else None,
            "data_sources": ghsa.data_sources
        })
    }


def sync_single_type(db: Session, source_type: str, converter_func, source_model, batch_size: int = 200):
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
            print(f'  Processing {source_type} batch {offset}-{offset+999}')
        
        batch = db.query(source_model).limit(1000).offset(offset).all()
        
        # 转换并只保留新的
        to_insert = []
        for item in batch:
            if hasattr(item, 'osv_id'):
                vuln_id = item.osv_id
            elif hasattr(item, 'ghsa_id'):
                vuln_id = item.ghsa_id
            else:
                continue
            
            if vuln_id not in existing_ids:
                item_dict = converter_func(item)
                to_insert.append(item_dict)
        
        # 批量插入，更小的批次避免错误
        for i in range(0, len(to_insert), batch_size):
            sub_batch = to_insert[i:i+batch_size]
            try:
                db.bulk_insert_mappings(UnifiedVulnerability, sub_batch)
                db.commit()
                added_count += len(sub_batch)
            except Exception as e:
                db.rollback()
                print(f'    Error inserting {source_type} sub-batch, skipping: {e}')
                # 降级到逐个插入
                for item in sub_batch:
                    try:
                        vuln = UnifiedVulnerability(**item)
                        db.add(vuln)
                        db.commit()
                        added_count += 1
                    except Exception as e2:
                        db.rollback()
        
        # 定期报告进度
        if offset % 20000 == 0 and offset > 0:
            print(f'  Progress: {offset}/{total_count} - added {added_count} new records')
    
    print(f'  Done {source_type}! Added {added_count} new records')
    return added_count


def get_sync_stats(db: Session) -> dict:
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
        print('Starting OSV & GHSA sync...')
        import time
        start = time.time()
        
        # 同步OSV
        osv_added = sync_single_type(db, 'osv', osv_to_unified_dict, OSVVulnerability)
        
        # 同步GHSA
        ghsa_added = sync_single_type(db, 'ghsa', ghsa_to_unified_dict, GitHubAdvisory)
        
        elapsed = time.time() - start
        print(f'Sync completed in {elapsed:.2f} seconds')
        
        # Verify
        final_stats = get_sync_stats(db)
        print(f'Final DB stats: {final_stats}')
    except Exception as e:
        print(f'Sync error: {e}')
        import traceback
        traceback.print_exc()
    finally:
        db.close()
