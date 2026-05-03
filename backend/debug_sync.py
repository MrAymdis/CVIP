#!/usr/bin/env python3
"""调试同步问题"""

from app.database import SessionLocal
from app.models import CNVDVulnerability, UnifiedVulnerability
from app.services.sync_cnvd_fast import cnvd_to_unified_dict

def debug():
    db = SessionLocal()
    try:
        # 获取一个有数据的 CNVD 记录
        cnvd = db.query(CNVDVulnerability).filter(
            CNVDVulnerability.affected_products.isnot(None)
        ).first()
        
        print(f'=' * 60)
        print(f'CNVD 原始数据:')
        print(f'=' * 60)
        print(f'  vuln_id: {cnvd.vuln_id}')
        print(f'  title: {cnvd.title}')
        print(f'  affected_products: {cnvd.affected_products} (type: {type(cnvd.affected_products)})')
        print(f'  solution: {cnvd.solution} (type: {type(cnvd.solution)})')
        
        # 转换
        print(f'\n' + '=' * 60)
        print(f'转换后的数据:')
        print(f'=' * 60)
        unified = cnvd_to_unified_dict(cnvd)
        print(f'  affected: {unified["affected"]} (type: {type(unified["affected"])})')
        print(f'  fixes: {unified["fixes"]} (type: {type(unified["fixes"])})')
        
        # 检查对应的 UnifiedVulnerability 记录
        print(f'\n' + '=' * 60)
        print(f'数据库中的 UnifiedVulnerability 记录:')
        print(f'=' * 60)
        uv = db.query(UnifiedVulnerability).filter(
            UnifiedVulnerability.vuln_id == cnvd.vuln_id,
            UnifiedVulnerability.type == 'cnvd'
        ).first()
        print(f'  vuln_id: {uv.vuln_id}')
        print(f'  affected: {uv.affected} (type: {type(uv.affected)})')
        print(f'  fixes: {uv.fixes} (type: {type(uv.fixes)})')
        
    except Exception as e:
        print(f'Error: {e}')
        import traceback
        traceback.print_exc()
    finally:
        db.close()

if __name__ == "__main__":
    debug()
