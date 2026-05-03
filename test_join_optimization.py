#!/usr/bin/env python3
import psycopg2
import time
import statistics

DB_CONFIG = {
    "host": "localhost",
    "port": 5433,
    "database": "cve_db",
    "user": "cve",
    "password": "cvepassword"
}

def test_optimization_approaches(search_term: str = "Microsoft", num_tests: int = 3):
    """测试不同的优化方案"""
    print(f"\n=== 测试 '{search_term}' 的不同查询方法 ===\n")

    conn = None
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()

        # 方法1: 直接ILIKE查询 (原始方法)
        print("方法1: 直接 ILIKE 查询")
        for i in range(num_tests):
            start = time.time()
            cursor.execute("""
                SELECT COUNT(*)
                FROM unified_vulnerabilities
                WHERE affected::text ILIKE %s
            """, (f'%{search_term}%',))
            count1 = cursor.fetchone()[0]
            duration = (time.time() - start) * 1000
            print(f"  测试 {i+1}: {duration:.2f}ms ({count1} 条)")

        # 方法2: 先查components获取相关漏洞ID，再查unified_vulnerabilities
        print("\n方法2: 先从 components 表查找漏洞ID，再查询漏洞")
        for i in range(num_tests):
            start = time.time()

            # 先从components找到相关的漏洞ID
            cursor.execute("""
                SELECT DISTINCT vuln_id
                FROM (
                    SELECT jsonb_array_elements_text(related_vuln_ids::jsonb) as vuln_id
                    FROM components
                    WHERE name ILIKE %s
                       OR vendor_name ILIKE %s
                       OR product_name ILIKE %s
                ) as ids
            """, (f'%{search_term}%', f'%{search_term}%', f'%{search_term}%'))

            vuln_ids = [row[0] for row in cursor.fetchall()]

            # 再查询unified_vulnerabilities
            if vuln_ids:
                cursor.execute("""
                    SELECT COUNT(*)
                    FROM unified_vulnerabilities
                    WHERE vuln_id = ANY(%s)
                """, (vuln_ids,))
                count2 = cursor.fetchone()[0]
            else:
                count2 = 0

            duration = (time.time() - start) * 1000
            print(f"  测试 {i+1}: {duration:.2f}ms ({count2} 条)")

        # 方法3: 使用GIN索引的JSON查询
        print("\n方法3: 使用JSONB包含查询优化")
        for i in range(num_tests):
            start = time.time()
            cursor.execute("""
                SELECT COUNT(*)
                FROM unified_vulnerabilities
                WHERE affected @> %s::jsonb
                   OR affected::text ILIKE %s
            """, (f'"{search_term}"', f'%{search_term}%'))
            count3 = cursor.fetchone()[0]
            duration = (time.time() - start) * 1000
            print(f"  测试 {i+1}: {duration:.2f}ms ({count3} 条)")

    except Exception as e:
        print(f"错误: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    print("测试不同查询方法的性能...")
    test_optimization_approaches("Microsoft", num_tests=3)
