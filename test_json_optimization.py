#!/usr/bin/env python3
import psycopg2
import time

DB_CONFIG = {
    "host": "localhost",
    "port": 5433,
    "database": "cve_db",
    "user": "cve",
    "password": "cvepassword"
}

def test_json_query(search_term: str = "kubernetes"):
    """测试不同的JSON查询方法"""
    print(f"\n=== 测试JSON查询优化: '{search_term}' ===\n")

    conn = None
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()

        # 方法1: 转成text再ILIKE (当前方法)
        print("方法1: affected::text ILIKE")
        start = time.time()
        cursor.execute("""
            SELECT COUNT(*)
            FROM unified_vulnerabilities
            WHERE affected::text ILIKE %s
        """, (f'%{search_term}%',))
        count1 = cursor.fetchone()[0]
        duration1 = (time.time() - start) * 1000
        print(f"  结果: {duration1:.2f}ms ({count1} 条)")

        # 方法2: JSON数组元素查询
        print("\n方法2: JSON数组遍历查询")
        start = time.time()
        cursor.execute("""
            SELECT COUNT(DISTINCT uv.id)
            FROM unified_vulnerabilities uv,
                 jsonb_array_elements(uv.affected) AS affected_item
            WHERE affected_item->'package'->>'name' ILIKE %s
               OR affected_item->'package'->>'purl' ILIKE %s
        """, (f'%{search_term}%', f'%{search_term}%'))
        count2 = cursor.fetchone()[0]
        duration2 = (time.time() - start) * 1000
        print(f"  结果: {duration2:.2f}ms ({count2} 条)")

        # 方法3: 限制返回条数
        print("\n方法3: 带LIMIT的查询 (前100条)")
        start = time.time()
        cursor.execute("""
            SELECT uv.id, uv.vuln_id
            FROM unified_vulnerabilities uv
            WHERE affected::text ILIKE %s
            LIMIT 100
        """, (f'%{search_term}%',))
        rows = cursor.fetchall()
        duration3 = (time.time() - start) * 1000
        print(f"  结果: {duration3:.2f}ms ({len(rows)} 条)")

        # 方法4: 使用全文检索
        print("\n方法4: 使用GIN索引的JSONB查询")
        start = time.time()
        cursor.execute("""
            SELECT COUNT(*)
            FROM unified_vulnerabilities
            WHERE to_tsvector('english', affected::text) @@ to_tsquery('english', %s)
        """, (search_term,))
        count4 = cursor.fetchone()[0]
        duration4 = (time.time() - start) * 1000
        print(f"  结果: {duration4:.2f}ms ({count4} 条)")

        print(f"\n性能对比: 方法1={duration1:.0f}ms, 方法2={duration2:.0f}ms, 方法3={duration3:.0f}ms, 方法4={duration4:.0f}ms")

    except Exception as e:
        print(f"错误: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    test_json_query("kubernetes")
    test_json_query("microsoft")
    test_json_query("linux")
