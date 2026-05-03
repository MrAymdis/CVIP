import json
from sqlalchemy.orm import Session
from app.models import OSVVulnerability, UnifiedVulnerability
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


def sync_remaining_osv(db: Session, batch_size: int = 100):
    """只同步剩余的未同步OSV数据"""
    print('=' * 60)
    print('Starting OSV remaining sync...')
    print('=' * 60)

    # 获取已存在的vuln_id集合
    existing_ids = {row[0] for row in db.query(UnifiedVulnerability.vuln_id).filter(
        UnifiedVulnerability.type == 'osv'
    ).all()}

    print(f'  已存在: {len(existing_ids)} 条')

    # 直接查询未同步的OSV记录
    all_osv_ids = {row[0] for row in db.query(OSVVulnerability.osv_id).all()}
    missing_ids = all_osv_ids - existing_ids

    print(f'  未同步: {len(missing_ids)} 条')
    print()

    if not missing_ids:
        print('所有OSV数据已全部同步!')
        return 0

    # 分批处理未同步的记录
    missing_list = list(missing_ids)
    added_count = 0

    for i in range(0, len(missing_list), batch_size):
        batch_ids = missing_list[i:i+batch_size]
        batch = db.query(OSVVulnerability).filter(
            OSVVulnerability.osv_id.in_(batch_ids)
        ).all()

        to_insert = [osv_to_unified_dict(osv) for osv in batch]

        try:
            db.bulk_insert_mappings(UnifiedVulnerability, to_insert)
            db.commit()
            added_count += len(to_insert)
            print(f'  Progress: {i+len(batch_ids)}/{len(missing_ids)} - added {added_count}')
        except Exception as e:
            db.rollback()
            print(f'  Batch failed at {i}, trying smaller batches...')
            # 分更小的批次
            for j in range(0, len(to_insert), 10):
                sub_batch = to_insert[j:j+10]
                try:
                    db.bulk_insert_mappings(UnifiedVulnerability, sub_batch)
                    db.commit()
                    added_count += len(sub_batch)
                except Exception as e2:
                    db.rollback()
                    print(f'  Failed to insert {len(sub_batch)} records')
                    continue

    print('=' * 60)
    print(f'OSV remaining sync completed! Added {added_count} new records')
    print('=' * 60)
    return added_count


if __name__ == "__main__":
    db = SessionLocal()
    try:
        import time
        start = time.time()

        osv_added = sync_remaining_osv(db)

        elapsed = time.time() - start
        print(f'\nTotal time: {elapsed:.2f} seconds')

    except Exception as e:
        print(f'Sync error: {e}')
        import traceback
        traceback.print_exc()
    finally:
        db.close()
