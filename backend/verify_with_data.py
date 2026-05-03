#!/usr/bin/env python3
"""验证有数据的记录"""

from app.database import SessionLocal
from app.models import UnifiedVulnerability

def verify():
    db = SessionLocal()
    try:
        # 查找有 affected 字段且不为 None 的记录
        print(f'=' * 60)
        print(f'查找有数据的 CNVD 记录')
        print(f'=' * 60)
        
        sample = db.query(UnifiedVulnerability).filter(
            UnifiedVulnerability.type == 'cnvd',
            UnifiedVulnerability.affected.isnot(None)
        ).limit(5).all()
        
        for i, item in enumerate(sample, 1):
            print(f'\n样例 {i}:')
            print(f'  vuln_id: {item.vuln_id}')
            print(f'  title: {item.title}')
            print(f'  affected: {item.affected}')
            print(f'  fixes: {item.fixes}')
        
    except Exception as e:
        print(f'Error: {e}')
        import traceback
        traceback.print_exc()
    finally:
        db.close()

if __name__ == "__main__":
    verify()
