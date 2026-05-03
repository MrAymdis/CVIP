#!/usr/bin/env python3
"""分析 affected 字段的数据格式"""

from app.database import SessionLocal
from app.models import UnifiedVulnerability
import json

def analyze():
    db = SessionLocal()
    try:
        print(f'=' * 80)
        print(f'分析 affected 字段的数据格式')
        print(f'=' * 80)

        # 获取不同类型的样例数据
        samples = db.query(UnifiedVulnerability).filter(
            UnifiedVulnerability.affected.isnot(None),
            UnifiedVulnerability.type.in_(['cve', 'cnvd', 'osv', 'ghsa'])
        ).limit(20).all()

        for i, item in enumerate(samples, 1):
            print(f'\n样例 {i} [{item.type}] {item.vuln_id}:')
            print(f'  affected: {json.dumps(item.affected, ensure_ascii=False, indent=2)}')
            if i >= 10:
                break

    except Exception as e:
        print(f'Error: {e}')
        import traceback
        traceback.print_exc()
    finally:
        db.close()

if __name__ == "__main__":
    analyze()
