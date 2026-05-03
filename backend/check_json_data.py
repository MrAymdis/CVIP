#!/usr/bin/env python3
"""检查 JSON 数据"""

from app.database import SessionLocal
from app.models import UnifiedVulnerability

def check():
    db = SessionLocal()
    try:
        print(f'=' * 60)
        print(f'检查 JSON 数据')
        print(f'=' * 60)
        
        # 先获取 100 条 CNVD 记录看看
        all_samples = db.query(UnifiedVulnerability).filter(
            UnifiedVulnerability.type == 'cnvd'
        ).limit(100).all()
        
        found = 0
        for item in all_samples:
            if item.affected and len(item.affected) > 0:
                print(f'\n找到有数据的记录:')
                print(f'  vuln_id: {item.vuln_id}')
                print(f'  title: {item.title}')
                print(f'  affected: {item.affected}')
                print(f'  fixes: {item.fixes}')
                found += 1
                if found >= 5:
                    break
        
        if found == 0:
            print("没有找到有数据的记录，让我们查看一下随机的一条记录的详细信息:")
            item = db.query(UnifiedVulnerability).filter(
                UnifiedVulnerability.type == 'cnvd'
            ).first()
            print(f'\n记录 {item.vuln_id}:')
            print(f'  affected 字段值: {item.affected}, 类型: {type(item.affected)}')
            print(f'  fixes 字段值: {item.fixes}, 类型: {type(item.fixes)}')
        
    except Exception as e:
        print(f'Error: {e}')
        import traceback
        traceback.print_exc()
    finally:
        db.close()

if __name__ == "__main__":
    check()
