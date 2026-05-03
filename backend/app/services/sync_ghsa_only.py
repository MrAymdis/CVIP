import json
import time
import signal
import sys
from sqlalchemy import func
from sqlalchemy.orm import Session
from app.models import GitHubAdvisory, UnifiedVulnerability
from app.database import SessionLocal


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


def bulk_insert_ghsa(db: Session, items: list, batch_size: int = 500) -> int:
    total_inserted = 0

    for i in range(0, len(items), batch_size):
        batch = items[i:i + batch_size]

        seen = set()
        unique_batch = []
        for item in batch:
            key = (item['vuln_id'], item['type'])
            if key not in seen:
                seen.add(key)
                unique_batch.append(item)

        try:
            db.bulk_insert_mappings(UnifiedVulnerability, unique_batch)
            db.commit()
            total_inserted += len(unique_batch)
            print(f'  Inserted batch {i//batch_size + 1}, total: {total_inserted}')
        except Exception as e:
            db.rollback()
            print(f'  Error in batch insert: {e}, falling back to individual inserts')
            for item in unique_batch:
                try:
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

    return total_inserted


def sync_ghsa(batch_size: int = 500):
    db = SessionLocal()
    running = True

    def signal_handler(signum, frame):
        nonlocal running
        print('\nReceived interrupt signal, finishing current batch...')
        running = False

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        ghsa_total = db.query(func.count(GitHubAdvisory.id)).scalar()
        ghsa_synced = db.query(func.count(UnifiedVulnerability.id)).filter(
            UnifiedVulnerability.type == 'ghsa'
        ).scalar()

        print('=' * 60)
        print('             GHSA 同步进程')
        print('=' * 60)
        print(f'  GHSA 源数据总数: {ghsa_total:,}')
        print(f'  已同步到统一表:  {ghsa_synced:,}')
        print(f'  剩余需要同步:   {ghsa_total - ghsa_synced:,}')
        print('=' * 60)
        print()

        if ghsa_synced >= ghsa_total:
            print('GHSA 数据已全部同步完成!')
            return

        ghsa_items = []
        batch_num = 0
        total_added = 0
        offset = 0
        last_progress_update = time.time()

        while running:
            ghsa_batch = db.query(GitHubAdvisory).limit(1000).offset(offset).all()

            if not ghsa_batch:
                break

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

            offset += 1000
            batch_num += 1

            if len(ghsa_items) >= 5000 or offset >= ghsa_total:
                added = bulk_insert_ghsa(db, ghsa_items, batch_size=batch_size)
                total_added += added
                ghsa_items = []

                current_synced = db.query(func.count(UnifiedVulnerability.id)).filter(
                    UnifiedVulnerability.type == 'ghsa'
                ).scalar()
                pct = current_synced / ghsa_total * 100 if ghsa_total > 0 else 0

                elapsed = time.time() - last_progress_update
                if elapsed > 10 or current_synced >= ghsa_total:
                    print(f'  Progress: {current_synced:,} / {ghsa_total:,} ({pct:.1f}%)')
                    last_progress_update = time.time()

                if current_synced >= ghsa_total:
                    running = False
                    break

            if batch_num % 10 == 0:
                print(f'  Processed {offset:,} / {ghsa_total:,} records')

        if ghsa_items and running:
            added = bulk_insert_ghsa(db, ghsa_items, batch_size=batch_size)
            total_added += added

        print()
        print('=' * 60)
        print('  GHSA 同步完成!')
        print(f'  本次新增同步: {total_added:,}')
        print('=' * 60)

    except Exception as e:
        print(f'Sync error: {e}')
        import traceback
        traceback.print_exc()
    finally:
        db.close()


if __name__ == "__main__":
    print('Starting GHSA sync...')
    sync_ghsa(batch_size=500)
