#!/usr/bin/env python3
"""使用原始 SQL 检查数据"""

from app.database import SessionLocal
from sqlalchemy import text

def check():
    db = SessionLocal()
    try:
        print(f'=' * 60)
        print(f'使用原始 SQL 检查数据')
        print(f'=' * 60)
        
        # 查找 affected 不为空的记录
        result = db.execute(text("""
            SELECT vuln_id, title, affected, fixes
            FROM unified_vulnerabilities
            WHERE type = 'cnvd'
            AND affected IS NOT NULL
            AND array_length(affected, 1) > 0
            LIMIT 5;
        """))
        
        count_result = db.execute(text("""
            SELECT COUNT(*)
            FROM unified_vulnerabilities
            WHERE type = 'cnvd'
            AND affected IS NOT NULL
            AND array_length(affected, 1) > 0;
        """))
        
        count_with_affected = count_result.scalar()
        
        print(f'有非空 affected 字段的记录数: {count_with_affected}')
        print(f'\n样例数据:')
        for row in result:
            print(f'\n  vuln_id: {row[0]}')
            print(f'  title: {row[1]}')
            print(f'  affected: {row[2]}')
            print(f'  fixes: {row[3]}')
        
    except Exception as e:
        print(f'Error: {e}')
        import traceback
        traceback.print_exc()
    finally:
        db.close()

if __name__ == "__main__":
    check()
