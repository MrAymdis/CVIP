#!/usr/bin/env python3
"""Query the number of vulnerabilities updated today - matching API logic."""

from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker
from app.models import UnifiedVulnerability
from datetime import datetime, date, timedelta
import os

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://cve:cvepassword@localhost:5433/cve_db")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def main():
    db = SessionLocal()
    try:
        today = date.today()
        print(f"今日日期: {today}")
        
        print("\n=== 统计API逻辑 (使用modified_date字段) ===")
        # 统计API的逻辑
        stats_api_published = db.query(UnifiedVulnerability).filter(
            func.date(UnifiedVulnerability.published_date) == today
        ).count()
        stats_api_updated = db.query(UnifiedVulnerability).filter(
            func.date(UnifiedVulnerability.modified_date) == today
        ).count()
        print(f"published_today (published_date字段): {stats_api_published}")
        print(f"updated_today (modified_date字段): {stats_api_updated}")
        
        print("\n=== 搜索API逻辑 (modified_after/modified_before) ===")
        # 搜索API的逻辑 - 当用户选择今天日期时
        search_api_updated = db.query(UnifiedVulnerability).filter(
            UnifiedVulnerability.modified_date >= today,
            UnifiedVulnerability.modified_date < today + timedelta(days=1)
        ).count()
        print(f"搜索今日更新 (modified_date >= today): {search_api_updated}")
        
        print("\n=== 使用updated_at字段 ===")
        # 使用updated_at字段
        updated_at_count = db.query(UnifiedVulnerability).filter(
            func.date(UnifiedVulnerability.updated_at) == today
        ).count()
        print(f"updated_today (updated_at字段): {updated_at_count}")
        
        print("\n=== 使用created_at字段 ===")
        # 使用created_at字段
        created_at_count = db.query(UnifiedVulnerability).filter(
            func.date(UnifiedVulnerability.created_at) == today
        ).count()
        print(f"published_today (created_at字段): {created_at_count}")
        
        print("\n=== 检查字段差异 ===")
        # 检查哪些记录的modified_date和updated_at不同
        diff_count = db.query(UnifiedVulnerability).filter(
            func.date(UnifiedVulnerability.modified_date) != func.date(UnifiedVulnerability.updated_at)
        ).count()
        print(f"modified_date和updated_at日期不同的记录数: {diff_count}")
        
        # 检查modified_date为空的记录
        null_modified = db.query(UnifiedVulnerability).filter(
            UnifiedVulnerability.modified_date.is_(None)
        ).count()
        print(f"modified_date为空的记录数: {null_modified}")
        
        # 检查updated_at为空的记录
        null_updated = db.query(UnifiedVulnerability).filter(
            UnifiedVulnerability.updated_at.is_(None)
        ).count()
        print(f"updated_at为空的记录数: {null_updated}")

    finally:
        db.close()

if __name__ == "__main__":
    main()
