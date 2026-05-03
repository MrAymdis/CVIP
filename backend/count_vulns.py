#!/usr/bin/env python3
"""Query the number of vulnerabilities in unified_vulnerabilities table."""

from app.database import SessionLocal
from app.models import UnifiedVulnerability
from sqlalchemy import func

def main():
    db = SessionLocal()
    try:
        # Total vulnerabilities
        total_count = db.query(UnifiedVulnerability).count()
        print(f"Total vulnerabilities in unified_vulnerabilities: {total_count}")
        print(f"\n{'-'*50}\n")

        # Count by type
        print("Vulnerabilities by type:")
        type_counts = db.query(
            UnifiedVulnerability.type,
            func.count(UnifiedVulnerability.id).label('count')
        ).group_by(UnifiedVulnerability.type).all()
        
        for vuln_type, count in type_counts:
            print(f"  {vuln_type}: {count}")

        print(f"\n{'-'*50}\n")

        # Count by severity
        print("Vulnerabilities by severity:")
        severity_counts = db.query(
            UnifiedVulnerability.severity,
            func.count(UnifiedVulnerability.id).label('count')
        ).group_by(UnifiedVulnerability.severity).all()
        
        for severity, count in severity_counts:
            print(f"  {severity}: {count}")

    finally:
        db.close()

if __name__ == "__main__":
    main()
