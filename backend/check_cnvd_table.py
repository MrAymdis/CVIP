#!/usr/bin/env python3
"""检查 CNVD 表结构"""

from app.database import SessionLocal, engine
from sqlalchemy import text

def check_table():
    db = SessionLocal()
    try:
        # 查询表结构
        result = db.execute(text("""
            SELECT column_name, data_type, is_nullable
            FROM information_schema.columns
            WHERE table_name = 'cnvd_vulnerabilities'
            ORDER BY ordinal_position;
        """))
        
        print("cnvd_vulnerabilities 表结构：")
        print("-" * 80)
        for row in result:
            print(f"{row[0]:<30} {row[1]:<15} {row[2]}")
        
        # 查看一条数据
        print("\n" + "=" * 80)
        print("样例数据：")
        result = db.execute(text("SELECT * FROM cnvd_vulnerabilities LIMIT 1;"))
        if result.rowcount > 0:
            row = result.first()
            print(row)
    except Exception as e:
        print(f"错误: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    check_table()
