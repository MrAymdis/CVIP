#!/usr/bin/env python3
"""重新同步一条 OSV 数据"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from app.crawlers.osv_monitor import OSVMonitor

monitor = OSVMonitor()

osv_id = "MINI-gqp9-6cfr-q83h"
print(f"Resyncing: {osv_id}")
result = monitor.sync_osv_vulnerability(osv_id)

if result:
    print(f"Successfully resynced: {osv_id}")

    # 验证一下
    from app.database import SessionLocal
    from app.models import UnifiedVulnerability

    db = SessionLocal()
    vuln = db.query(UnifiedVulnerability).filter(
        UnifiedVulnerability.vuln_id == osv_id
    ).first()
    if vuln:
        print(f"\nUpdated unified_vulnerability:")
        print(f"  related_cve_ids: {vuln.related_cve_ids}")
        print(f"  data_sources: {vuln.data_sources}")
    db.close()
else:
    print(f"Failed to resync: {osv_id}")
