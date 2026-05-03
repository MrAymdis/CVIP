#!/usr/bin/env python3
import requests
import time
import statistics

BASE_URL = "http://localhost:8006"

def test_affected_query(search_term: str = "Microsoft", num_tests: int = 5):
    """测试受影响产品查询速度"""
    print(f"\n=== 测试受影响产品查询: '{search_term}' ===")
    
    durations = []
    for i in range(num_tests):
        try:
            start = time.time()
            response = requests.get(
                f"{BASE_URL}/api/v1/search",
                params={"affected_product": search_term},
                timeout=60
            )
            end = time.time()
            duration = (end - start) * 1000
            durations.append(duration)
            
            result = response.json()
            print(f"测试 {i+1}: {duration:.2f}ms (找到 {result.get('total', 0)} 条记录, 状态码: {response.status_code})")
        except Exception as e:
            print(f"测试 {i+1}: 失败 - {e}")
    
    if durations:
        print(f"\n统计结果:")
        print(f"  平均: {statistics.mean(durations):.2f}ms")
        print(f"  最小: {min(durations):.2f}ms")
        print(f"  最大: {max(durations):.2f}ms")
        print(f"  中位数: {statistics.median(durations):.2f}ms")
    return durations

if __name__ == "__main__":
    print("开始受影响产品查询速度测试...")
    
    # 测试几个不同的关键词
    test_affected_query("Microsoft", num_tests=5)
    test_affected_query("Linux", num_tests=5)
    test_affected_query("Apple", num_tests=5)
