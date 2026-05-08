"""
直接数据库操作的增量同步工具
不通过API接口，直接操作数据库获取并解析增量数据
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hashlib
import re
from datetime import datetime, timedelta
from sqlalchemy import text
from sqlalchemy.dialects.postgresql import insert

from app.database import SessionLocal
from app.models import UnifiedVulnerability, Component
from app.services.component_parser import (
    parse_affected_data,
    infer_category,
    truncate
)


def sync_incremental_by_date_direct(date: str = None):
    """
    直接数据库操作：按日期同步增量数据
    不通过API接口，直接操作数据库
    
    参数：
    - date: 指定日期（格式：YYYY-MM-DD），默认昨天
    """
    if date is None:
        date = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
    
    print(f"[{datetime.now()}] Starting DIRECT incremental sync for date: {date}")
    
    db = SessionLocal()
    try:
        # 解析日期范围
        date_obj = datetime.strptime(date, '%Y-%m-%d')
        start_of_day = datetime(date_obj.year, date_obj.month, date_obj.day)
        end_of_day = datetime(date_obj.year, date_obj.month, date_obj.day, 23, 59, 59)
        
        print(f"[{datetime.now()}] Date range: {start_of_day} - {end_of_day}")
        
        # Step 1: 直接SQL查询获取增量漏洞数据
        sql = """
            SELECT vuln_id, type, affected, updated_at 
            FROM unified_vulnerabilities 
            WHERE affected IS NOT NULL 
              AND updated_at >= :start_time 
              AND updated_at <= :end_time
        """
        
        results = db.execute(
            text(sql),
            {
                'start_time': start_of_day,
                'end_time': end_of_day
            }
        ).fetchall()
        
        print(f"[{datetime.now()}] Found {len(results)} vulnerabilities to process")
        
        if not results:
            print(f"[{datetime.now()}] No vulnerabilities found for date {date}")
            return {'added': 0, 'updated': 0, 'processed': 0}
        
        # Step 2: 解析数据，生成组件映射
        component_data_map = {}
        component_vuln_map = {}
        
        for row in results:
            vuln_id = row[0]
            vuln_type = row[1]
            affected_data = row[2]
            
            affected_items = parse_affected_data(affected_data, vuln_type)
            
            for item in affected_items:
                vendor = item.get('vendor')
                product = item.get('product')
                version = item.get('version')
                ecosystem = item.get('ecosystem')
                
                if not product:
                    continue
                
                component_id_base = re.sub(r'[^a-zA-Z0-9_-]', '-', product.lower())[:50]
                stable_hash = hashlib.md5(product.encode()).hexdigest()[:8]
                component_id = f"cmp-{component_id_base}-{stable_hash}"
                
                category = infer_category(product, ecosystem)
                
                if component_id not in component_data_map:
                    component_data_map[component_id] = {
                        'name': truncate(product),
                        'vendor_name': truncate(vendor) if vendor else None,
                        'category': category,
                        'product_name': truncate(product),
                        'product_version': truncate(version) if version else None,
                        'ecosystem': truncate(ecosystem) if ecosystem else None,
                        'data_source': vuln_type.upper(),
                    }
                
                if component_id not in component_vuln_map:
                    component_vuln_map[component_id] = set()
                component_vuln_map[component_id].add(vuln_id)
        
        print(f"[{datetime.now()}] Parsed {len(component_data_map)} unique components")
        
        # Step 3: 批量获取现有组件ID
        if component_data_map:
            existing_ids = set(
                c[0] for c in db.query(Component.component_id).filter(
                    Component.component_id.in_(list(component_data_map.keys()))
                ).all()
            )
        else:
            existing_ids = set()
        
        print(f"[{datetime.now()}] Found {len(existing_ids)} existing components")
        
        # Step 4: 批量插入新组件
        new_components = []
        for component_id in component_data_map.keys():
            if component_id not in existing_ids:
                component = Component(
                    component_id=component_id,
                    related_vuln_ids=list(component_vuln_map[component_id]),
                    **component_data_map[component_id]
                )
                new_components.append(component)
        
        if new_components:
            db.bulk_save_objects(new_components)
            print(f"[{datetime.now()}] Inserted {len(new_components)} new components")
        
        # Step 5: 批量更新现有组件
        updated_count = 0
        for component_id in component_data_map.keys():
            if component_id in existing_ids:
                component = db.query(Component).filter(Component.component_id == component_id).first()
                if component:
                    current_vuln_ids = set(component.related_vuln_ids or [])
                    new_vuln_ids = component_vuln_map[component_id]
                    to_add = new_vuln_ids - current_vuln_ids
                    
                    if to_add:
                        component.related_vuln_ids = list(current_vuln_ids | to_add)
                        updated_count += 1
                    
                    for key, value in component_data_map[component_id].items():
                        if value and hasattr(component, key):
                            setattr(component, key, value)
        
        db.commit()
        
        print(f"[{datetime.now()}] Updated {updated_count} existing components")
        print(f"[{datetime.now()}] DIRECT incremental sync completed!")
        
        return {
            'added': len(new_components),
            'updated': updated_count,
            'processed': len(results)
        }
    
    except Exception as e:
        db.rollback()
        print(f"[{datetime.now()}] DIRECT incremental sync failed: {e}")
        raise
    finally:
        db.close()


def sync_incremental_by_time_direct(last_sync_time: datetime = None):
    """
    直接数据库操作：按时间戳同步增量数据
    
    参数：
    - last_sync_time: 上次同步时间，默认从Redis获取或处理全部数据
    """
    from app.services.sync_state import get_last_sync_timestamp, update_last_sync_timestamp
    
    print(f"[{datetime.now()}] Starting DIRECT incremental sync by timestamp")
    
    db = SessionLocal()
    try:
        if last_sync_time is None:
            last_sync_str = get_last_sync_timestamp()
            if last_sync_str:
                last_sync_time = datetime.fromisoformat(last_sync_str.replace('Z', '+00:00'))
                print(f"[{datetime.now()}] Last sync time: {last_sync_time}")
            else:
                print(f"[{datetime.now()}] No previous sync time found, processing all data")
        
        # 构建查询
        sql = "SELECT vuln_id, type, affected, updated_at FROM unified_vulnerabilities WHERE affected IS NOT NULL"
        
        params = {}
        if last_sync_time:
            sql += " AND updated_at > :last_sync_time"
            params['last_sync_time'] = last_sync_time
        
        results = db.execute(text(sql), params).fetchall()
        
        print(f"[{datetime.now()}] Found {len(results)} vulnerabilities to process")
        
        if not results:
            print(f"[{datetime.now()}] No new vulnerabilities found")
            return {'added': 0, 'updated': 0, 'processed': 0}
        
        # 解析数据
        component_data_map = {}
        component_vuln_map = {}
        
        for row in results:
            vuln_id = row[0]
            vuln_type = row[1]
            affected_data = row[2]
            
            affected_items = parse_affected_data(affected_data, vuln_type)
            
            for item in affected_items:
                vendor = item.get('vendor')
                product = item.get('product')
                version = item.get('version')
                ecosystem = item.get('ecosystem')
                
                if not product:
                    continue
                
                component_id_base = re.sub(r'[^a-zA-Z0-9_-]', '-', product.lower())[:50]
                stable_hash = hashlib.md5(product.encode()).hexdigest()[:8]
                component_id = f"cmp-{component_id_base}-{stable_hash}"
                
                category = infer_category(product, ecosystem)
                
                if component_id not in component_data_map:
                    component_data_map[component_id] = {
                        'name': truncate(product),
                        'vendor_name': truncate(vendor) if vendor else None,
                        'category': category,
                        'product_name': truncate(product),
                        'product_version': truncate(version) if version else None,
                        'ecosystem': truncate(ecosystem) if ecosystem else None,
                        'data_source': vuln_type.upper(),
                    }
                
                if component_id not in component_vuln_map:
                    component_vuln_map[component_id] = set()
                component_vuln_map[component_id].add(vuln_id)
        
        # 获取现有组件
        existing_ids = set(
            c[0] for c in db.query(Component.component_id).filter(
                Component.component_id.in_(list(component_data_map.keys()))
            ).all()
        ) if component_data_map else set()
        
        # 插入新组件
        new_components = []
        for component_id in component_data_map.keys():
            if component_id not in existing_ids:
                component = Component(
                    component_id=component_id,
                    related_vuln_ids=list(component_vuln_map[component_id]),
                    **component_data_map[component_id]
                )
                new_components.append(component)
        
        if new_components:
            db.bulk_save_objects(new_components)
        
        # 更新现有组件
        updated_count = 0
        for component_id in component_data_map.keys():
            if component_id in existing_ids:
                component = db.query(Component).filter(Component.component_id == component_id).first()
                if component:
                    current_vuln_ids = set(component.related_vuln_ids or [])
                    new_vuln_ids = component_vuln_map[component_id]
                    to_add = new_vuln_ids - current_vuln_ids
                    
                    if to_add:
                        component.related_vuln_ids = list(current_vuln_ids | to_add)
                        updated_count += 1
                    
                    for key, value in component_data_map[component_id].items():
                        if value and hasattr(component, key):
                            setattr(component, key, value)
        
        db.commit()
        update_last_sync_timestamp(datetime.utcnow().isoformat())
        
        print(f"[{datetime.now()}] DIRECT incremental sync completed!")
        
        return {
            'added': len(new_components),
            'updated': updated_count,
            'processed': len(results)
        }
    
    except Exception as e:
        db.rollback()
        print(f"[{datetime.now()}] DIRECT incremental sync failed: {e}")
        raise
    finally:
        db.close()


def sync_yesterday_direct():
    """直接同步昨天的数据（最常用场景）"""
    date = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
    return sync_incremental_by_date_direct(date)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="直接数据库操作的增量同步工具")
    parser.add_argument("--date", type=str, help="指定日期同步（格式：YYYY-MM-DD）")
    parser.add_argument("--yesterday", action="store_true", help="同步昨天的数据")
    parser.add_argument("--all", action="store_true", help="同步所有数据（全量同步）")
    
    args = parser.parse_args()
    
    if args.yesterday:
        result = sync_yesterday_direct()
    elif args.date:
        result = sync_incremental_by_date_direct(args.date)
    elif args.all:
        result = sync_incremental_by_time_direct()
    else:
        print("请指定同步方式：--date, --yesterday, 或 --all")
        exit(1)
    
    print(f"\n同步结果:")
    print(f"  新增组件: {result['added']}")
    print(f"  更新组件: {result['updated']}")
    print(f"  处理漏洞: {result['processed']}")
