#!/usr/bin/env python3
"""
修复 unified_vulnerabilities 表中的 source 和 severity 字段
1. 从 data_sources 推导 source 字段
2. 标准化 severity 字段为统一格式
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.database import SessionLocal
from app.models import UnifiedVulnerability


def get_source_from_data_sources(data_sources):
    """从 data_sources 列表推导 source"""
    if not data_sources:
        return None

    priority = ['cvelistv5', 'cnvd', 'osv', 'github_advisory', 'github_advisory_local', 'mitre', 'packetstorm', 'exploitdb']

    for source in priority:
        if source in data_sources:
            return source

    return data_sources[0] if data_sources else None


def normalize_severity(severity):
    """标准化 severity 字段"""
    if not severity:
        return None

    severity = severity.upper()

    mapping = {
        'CRITICAL': 'CRITICAL',
        'HIGH': 'HIGH',
        'MEDIUM': 'MEDIUM',
        'MODERATE': 'MEDIUM',
        'LOW': 'LOW',
        'NONE': None,
        'UNKNOWN': None,
        'CRIT': 'CRITICAL',
        'HIGH': 'HIGH',
        'MED': 'MEDIUM',
    }

    return mapping.get(severity, severity)


def fix_source_and_severity(batch_size=5000):
    """修复 source 和 severity 字段"""
    db = SessionLocal()
    total_updated = 0
    source_updated = 0
    severity_updated = 0

    try:
        while True:
            vulns = db.query(UnifiedVulnerability).filter(
                UnifiedVulnerability.source.is_(None)
            ).limit(batch_size).all()

            if not vulns:
                break

            for vuln in vulns:
                changed = False

                if vuln.source is None and vuln.data_sources:
                    new_source = get_source_from_data_sources(vuln.data_sources)
                    if new_source:
                        vuln.source = new_source
                        source_updated += 1
                        changed = True

                if vuln.severity:
                    new_severity = normalize_severity(vuln.severity)
                    if new_severity != vuln.severity:
                        vuln.severity = new_severity
                        severity_updated += 1
                        changed = True

                if changed:
                    total_updated += 1

            db.commit()
            print(f"Processed {total_updated} records (source: {source_updated}, severity: {severity_updated})")

        print(f"\n✅ Fix completed!")
        print(f"  Total records changed: {total_updated}")
        print(f"  Source field updated: {source_updated}")
        print(f"  Severity field normalized: {severity_updated}")

    except Exception as e:
        db.rollback()
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        db.close()


if __name__ == "__main__":
    print("Starting source and severity fix...")
    fix_source_and_severity()