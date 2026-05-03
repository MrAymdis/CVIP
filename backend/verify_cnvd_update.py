#!/usr/bin/env python3
"""验证 CNVD 数据更新"""

from app.database import SessionLocal
from app.models import UnifiedVulnerability
from sqlalchemy import func

def verify():
    db = SessionLocal()
    try:
        # 检查有 affected 字段的 CNVD 记录数量
        cnvd_with_affected = db.query(func.count(UnifiedVulnerability.id)).filter(
            UnifiedVulnerability.type == 'cnvd',
            UnifiedVulnerability.affected.isnot(None)
        ).scalar()
        
        # 检查有 fixes 字段的 CNVD 记录数量
        cnvd_with_fixes = db.query(func.count(UnifiedVulnerability.id)).filter(
            UnifiedVulnerability.type == 'cnvd',
            UnifiedVulnerability.fixes.isnot(None)
        ).scalar()
        
        # 总 CNVD 记录数
        total_cnvd = db.query(func.count(UnifiedVulnerability.id)).filter(
            UnifiedVulnerability.type == 'cnvd'
        ).scalar()
        
        print(f'=' * 60)
        print(f'CNVD 数据更新验证')
        print(f'=' * 60)
        print(f'总 CNVD 记录数: {total_cnvd}')
        print(f'有 affected 字段的记录: {cnvd_with_affected} ({(cnvd_with_affected/total_cnvd*100):.1f}%)')
        print(f'有 fixes 字段的记录: {cnvd_with_fixes} ({(cnvd_with_fixes/total_cnvd*100):.1f}%)')
        
        # 查看一些样例数据
        print(f'\n=' * 60)
        print(f'样例数据')
        print(f'=' * 60)
        sample = db.query(UnifiedVulnerability).filter(
            UnifiedVulnerability.type == 'cnvd',
            UnifiedVulnerability.affected.isnot(None)
        ).limit(3).all()
        
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
