import json
from sqlalchemy.orm import Session
from datetime import datetime
from app.models import CVE, CNVDVulnerability, OSVVulnerability, GitHubAdvisory, UnifiedVulnerability, Reference
from app.database import SessionLocal


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
    
    # Determine source from data_sources
    source = None
    if cve.data_sources:
        if len(cve.data_sources) > 0:
            # Prefer official sources first
            for s in ['nvd', 'cvelistv5', 'mitre']:
                if s in cve.data_sources:
                    source = s
                    break
            # If no official source found, use first one
            if source is None:
                source = cve.data_sources[0]
    
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
        "source": source,
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
        "affected": None,
        "references": cnvd.references,
        "fixes": None,
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
            "data_sources": cnvd.data_sources,
            "exploits_count": cnvd.exploits_count
        })
    }


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
            
            severity_label = None
            if score is not None:
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


def bulk_insert_with_dedup(db: Session, items: list, batch_size: int = 500, prefix: str = '  ') -> int:
    total_inserted = 0
    
    for i in range(0, len(items), batch_size):
        batch = items[i:i + batch_size]
        
        # 在内存中先去重
        seen = set()
        unique_batch = []
        for item in batch:
            key = (item['vuln_id'], item['type'])
            if key not in seen:
                seen.add(key)
                unique_batch.append(item)
        
        # 批量插入
        try:
            db.bulk_insert_mappings(UnifiedVulnerability, unique_batch)
            db.commit()
            total_inserted += len(unique_batch)
            print(f'{prefix}Inserted {len(unique_batch)}/{len(unique_batch)} in this batch, total so far: {total_inserted}')
        except Exception as e:
            db.rollback()
            print(f'{prefix}Error inserting batch, falling back to individual inserts: {e}')
            # 回退到逐个插入
            for item in unique_batch:
                try:
                    # 检查是否已存在
                    existing = db.query(UnifiedVulnerability).filter(
                        UnifiedVulnerability.vuln_id == item['vuln_id'],
                        UnifiedVulnerability.type == item['type']
                    ).first()
                    if existing:
                        continue
                    
                    vuln = UnifiedVulnerability(**item)
                    db.add(vuln)
                    db.commit()
                    total_inserted += 1
                except Exception as e2:
                    db.rollback()
                    print(f'{prefix}Error inserting {item["type"]}:{item["vuln_id"]}: {e2}')
    
    return total_inserted


def sync_all_data(db: Session, batch_size: int = 500) -> dict:
    stats = {
        "cve": {"added": 0, "updated": 0, "skipped": 0},
        "cnvd": {"added": 0, "updated": 0, "skipped": 0},
        "osv": {"added": 0, "updated": 0, "skipped": 0},
        "ghsa": {"added": 0, "updated": 0, "skipped": 0},
        "total": {"added": 0, "updated": 0, "skipped": 0}
    }
    
    # 先检查有多少数据了
    existing_count = db.query(func.count(UnifiedVulnerability.id)).scalar()
    print(f'Already has {existing_count} records')
    
    if existing_count > 0:
        # 增量同步模式：检查哪些还没同步
        print('Running in incremental sync mode')
        
        # Sync CVE
        print('Syncing CVE...')
        cve_count = db.query(func.count(CVE.id)).scalar()
        print(f'  Found {cve_count} CVE records')
        
        cve_items = []
        for offset in range(0, cve_count, 1000):
            print(f'  Processing CVE batch {offset}-{offset+999}')
            cve_batch = db.query(CVE).limit(1000).offset(offset).all()
            
            # 先获取这一批的所有cve_id
            cve_ids = [c.cve_id for c in cve_batch]
            
            # 查询已存在的
            existing_cves = set()
            if cve_ids:
                existing = db.query(UnifiedVulnerability.vuln_id).filter(
                    UnifiedVulnerability.vuln_id.in_(cve_ids),
                    UnifiedVulnerability.type == 'cve'
                ).all()
                existing_cves = {r[0] for r in existing}
            
            # 只添加不存在的
            for cve in cve_batch:
                if cve.cve_id not in existing_cves:
                    cve_dict = cve_to_unified_dict(cve, db)
                    cve_items.append(cve_dict)
            
            if len(cve_items) >= 5000:
                added = bulk_insert_with_dedup(db, cve_items, batch_size=batch_size, prefix='  ')
                stats["cve"]["added"] += added
                cve_items = []
        
        if cve_items:
            added = bulk_insert_with_dedup(db, cve_items, batch_size=batch_size, prefix='  ')
            stats["cve"]["added"] += added
        
        # Sync CNVD
        print('Syncing CNVD...')
        cnvd_count = db.query(func.count(CNVDVulnerability.id)).scalar()
        print(f'  Found {cnvd_count} CNVD records')
        
        cnvd_items = []
        for offset in range(0, cnvd_count, 1000):
            print(f'  Processing CNVD batch {offset}-{offset+999}')
            cnvd_batch = db.query(CNVDVulnerability).limit(1000).offset(offset).all()
            
            cnvd_ids = [c.vuln_id for c in cnvd_batch]
            
            existing_cnvd = set()
            if cnvd_ids:
                existing = db.query(UnifiedVulnerability.vuln_id).filter(
                    UnifiedVulnerability.vuln_id.in_(cnvd_ids),
                    UnifiedVulnerability.type == 'cnvd'
                ).all()
                existing_cnvd = {r[0] for r in existing}
            
            for cnvd in cnvd_batch:
                if cnvd.vuln_id not in existing_cnvd:
                    cnvd_dict = cnvd_to_unified_dict(cnvd)
                    cnvd_items.append(cnvd_dict)
            
            if len(cnvd_items) >= 5000:
                added = bulk_insert_with_dedup(db, cnvd_items, batch_size=batch_size, prefix='  ')
                stats["cnvd"]["added"] += added
                cnvd_items = []
        
        if cnvd_items:
            added = bulk_insert_with_dedup(db, cnvd_items, batch_size=batch_size, prefix='  ')
            stats["cnvd"]["added"] += added
        
        # Sync OSV
        print('Syncing OSV...')
        osv_count = db.query(func.count(OSVVulnerability.id)).scalar()
        print(f'  Found {osv_count} OSV records')
        
        osv_items = []
        for offset in range(0, osv_count, 1000):
            print(f'  Processing OSV batch {offset}-{offset+999}')
            osv_batch = db.query(OSVVulnerability).limit(1000).offset(offset).all()
            
            osv_ids = [o.osv_id for o in osv_batch]
            
            existing_osv = set()
            if osv_ids:
                existing = db.query(UnifiedVulnerability.vuln_id).filter(
                    UnifiedVulnerability.vuln_id.in_(osv_ids),
                    UnifiedVulnerability.type == 'osv'
                ).all()
                existing_osv = {r[0] for r in existing}
            
            for osv in osv_batch:
                if osv.osv_id not in existing_osv:
                    osv_dict = osv_to_unified_dict(osv)
                    osv_items.append(osv_dict)
            
            if len(osv_items) >= 5000:
                added = bulk_insert_with_dedup(db, osv_items, batch_size=batch_size, prefix='  ')
                stats["osv"]["added"] += added
                osv_items = []
        
        if osv_items:
            added = bulk_insert_with_dedup(db, osv_items, batch_size=batch_size, prefix='  ')
            stats["osv"]["added"] += added
        
        # Sync GHSA
        print('Syncing GHSA...')
        ghsa_count = db.query(func.count(GitHubAdvisory.id)).scalar()
        print(f'  Found {ghsa_count} GHSA records')
        
        ghsa_items = []
        for offset in range(0, ghsa_count, 1000):
            print(f'  Processing GHSA batch {offset}-{offset+999}')
            ghsa_batch = db.query(GitHubAdvisory).limit(1000).offset(offset).all()
            
            ghsa_ids = [g.ghsa_id for g in ghsa_batch]
            
            existing_ghsa = set()
            if ghsa_ids:
                existing = db.query(UnifiedVulnerability.vuln_id).filter(
                    UnifiedVulnerability.vuln_id.in_(ghsa_ids),
                    UnifiedVulnerability.type == 'ghsa'
                ).all()
                existing_ghsa = {r[0] for r in existing}
            
            for ghsa in ghsa_batch:
                if ghsa.ghsa_id not in existing_ghsa:
                    ghsa_dict = ghsa_to_unified_dict(ghsa)
                    ghsa_items.append(ghsa_dict)
            
            if len(ghsa_items) >= 5000:
                added = bulk_insert_with_dedup(db, ghsa_items, batch_size=batch_size, prefix='  ')
                stats["ghsa"]["added"] += added
                ghsa_items = []
        
        if ghsa_items:
            added = bulk_insert_with_dedup(db, ghsa_items, batch_size=batch_size, prefix='  ')
            stats["ghsa"]["added"] += added
    
    stats["total"]["added"] = stats["cve"]["added"] + stats["cnvd"]["added"] + stats["osv"]["added"] + stats["ghsa"]["added"]
    
    # 如果有数据更新，清除相关缓存
    if stats["total"]["added"] > 0:
        try:
            from app.cache import clear_cache_after_update
            clear_cache_after_update()
        except Exception as e:
            print(f"Failed to clear cache after sync: {e}")
    
    return stats


def get_sync_stats(db: Session) -> dict:
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
    from sqlalchemy import func
    db = SessionLocal()
    try:
        print('Starting data sync...')
        import time
        start = time.time()
        stats = sync_all_data(db, batch_size=500)
        elapsed = time.time() - start
        print(f'Sync completed in {elapsed:.2f} seconds')
        print(f'Stats: {stats}')
        
        # Verify
        final_stats = get_sync_stats(db)
        print(f'Final DB stats: {final_stats}')
    except Exception as e:
        print(f'Sync error: {e}')
        import traceback
        traceback.print_exc()
    finally:
        db.close()
