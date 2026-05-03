#!/usr/bin/env python3
"""添加数据库索引优化脚本"""
from sqlalchemy import text
from app.database import SessionLocal

def add_indexes():
    db = SessionLocal()
    try:
        print("正在添加索引...")
        
        # 添加 view_count 索引
        print("1. 添加 view_count 索引...")
        db.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_unified_view_count 
            ON unified_vulnerabilities (view_count);
        """))
        
        print("2. 添加 view_count 降序索引...")
        db.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_unified_view_count_desc 
            ON unified_vulnerabilities (view_count DESC);
        """))
        
        # 优化统计查询的复合索引
        print("3. 添加统计查询复合索引...")
        db.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_unified_stats_composite 
            ON unified_vulnerabilities (published_date, modified_date, severity, cisa_kev, exploits_count);
        """))
        
        db.commit()
        print("\n索引添加完成！")
        
        # 验证索引
        print("\n验证索引...")
        result = db.execute(text("""
            SELECT indexname, indexdef 
            FROM pg_indexes 
            WHERE tablename = 'unified_vulnerabilities'
            ORDER BY indexname;
        """))
        print("\n当前表索引:")
        for row in result:
            print(f"  - {row[0]}")
            
    except Exception as e:
        print(f"错误: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    add_indexes()
