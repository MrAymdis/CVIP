#!/usr/bin/env python3
"""分析受影响字段的数据格式"""

from app.database import SessionLocal
from app.models import UnifiedVulnerability
import json

def analyze():
    db = SessionLocal()
    try:
        print(f'=' * 80)
        print(f'分析 affected 字段的数据格式 (CNVD, CVE, OSV)')
        print(f'=' * 80)

        # 分别查看不同类型的affected数据
        for vuln_type in ['cnvd', 'cve', 'osv']:
            print(f'\n\n{"="*80}')
            print(f'{vuln_type.upper()} 类型数据:')
            print(f'{"="*80}')

            samples = db.query(UnifiedVulnerability).filter(
                UnifiedVulnerability.affected.isnot(None),
                UnifiedVulnerability.type == vuln_type
            ).limit(5).all()

            for i, item in enumerate(samples, 1):
                if item.affected and len(item.affected) > 0:
                    print(f'\n样例 {i} [{item.type}] {item.vuln_id}:')
                    print(f'  affected: {json.dumps(item.affected, ensure_ascii=False, indent=2)[:500]}')

    except Exception as e:
        print(f'Error: {e}')
        import traceback
        traceback.print_exc()
    finally:
        db.close()

if __name__ == "__main__":
    analyze()
