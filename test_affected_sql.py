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

def test_affected_query_sql(search_term: str = "Microsoft", num_tests: int = 5):
    """直接用SQL测试受影响产品查询速度"""
    print(f"\n=== 测试SQL受影响产品查询: '%{search_term}%' ===")

    conn = None
    durations = []
    total_records = 0

    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()

        # 先检查查询计划
        cursor.execute("""
            EXPLAIN ANALYZE
            SELECT COUNT(*)
            FROM unified_vulnerabilities
            WHERE affected::text ILIKE %s
        """, (f'%{search_term}%',))

        print("查询计划:")
        for row in cursor.fetchall():
            print(f"  {row[0]}")

        print("\n执行测试:")
        for i in range(num_tests):
            start = time.time()
            cursor.execute("""
                SELECT COUNT(*)
                FROM unified_vulnerabilities
                WHERE affected::text ILIKE %s
            """, (f'%{search_term}%',))

            count = cursor.fetchone()[0]
            total_records = count

            end = time.time()
            duration = (end - start) * 1000
            durations.append(duration)

            print(f"测试 {i+1}: {duration:.2f}ms (找到 {count} 条记录)")

        print(f"\n统计结果:")
        print(f"  平均: {statistics.mean(durations):.2f}ms")
        print(f"  最小: {min(durations):.2f}ms")
        print(f"  最大: {max(durations):.2f}ms")
        print(f"  中位数: {statistics.median(durations):.2f}ms")

    except Exception as e:
        print(f"错误: {e}")

    finally:
        if conn:
            conn.close()

    return durations

if __name__ == "__main__":
    print("开始SQL受影响产品查询速度测试...")

    test_affected_query_sql("Microsoft", num_tests=3)
    test_affected_query_sql("Linux", num_tests=3)
