#!/usr/bin/env python3
"""检查 CNVD 表数据"""

from app.database import SessionLocal
from app.models import CNVDVulnerability

def check():
    db = SessionLocal()
    try:
        # 查看一些样例数据
        print(f'=' * 60)
        print(f'CNVD 表数据检查')
        print(f'=' * 60)
        
        sample = db.query(CNVDVulnerability).limit(5).all()
        
        for i, item in enumerate(sample, 1):
            print(f'\n样例 {i}:')
            print(f'  vuln_id: {item.vuln_id}')
            print(f'  title: {item.title}')
            print(f'  affected_products: {item.affected_products}')
            print(f'  solution: {item.solution}')
            print(f'  tags: {item.tags}')
        
        # 统计一下
        total = db.query(CNVDVulnerability).count()
        with_affected = db.query(CNVDVulnerability).filter(CNVDVulnerability.affected_products.isnot(None)).count()
        with_solution = db.query(CNVDVulnerability).filter(CNVDVulnerability.solution.isnot(None)).count()
        with_tags = db.query(CNVDVulnerability).filter(CNVDVulnerability.tags.isnot(None)).count()
        
        print(f'\n=' * 60)
        print(f'统计')
        print(f'=' * 60)
        print(f'总记录数: {total}')
        print(f'有 affected_products: {with_affected}')
        print(f'有 solution: {with_solution}')
        print(f'有 tags: {with_tags}')
        
    except Exception as e:
        print(f'Error: {e}')
        import traceback
        traceback.print_exc()
    finally:
        db.close()

if __name__ == "__main__":
    check()
