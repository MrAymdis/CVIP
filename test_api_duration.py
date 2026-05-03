#!/usr/bin/env python3
import requests
import time
import statistics

BASE_URL = "http://localhost:8006"

def test_api_endpoint(endpoint, description, num_tests=5):
    """测试API端点响应时间"""
    print(f"\n=== 测试: {description} ===")
    print(f"端点: {BASE_URL}{endpoint}")
    
    durations = []
    for i in range(num_tests):
        try:
            start = time.time()
            response = requests.get(f"{BASE_URL}{endpoint}", timeout=30)
            end = time.time()
            duration = (end - start) * 1000  # 转换为毫秒
            durations.append(duration)
            print(f"测试 {i+1}: {duration:.2f}ms (状态码: {response.status_code})")
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
    print("开始API响应时间测试...")
    
    # 测试统计概览API
    test_api_endpoint("/api/v1/stats/overview", "统计数据概览")
    
    # 测试热门漏洞API
    test_api_endpoint("/api/v1/search/top-viewed?limit=10", "热门漏洞列表")
    
    # 同时测试两个API的总时长（模拟页面加载）
    print(f"\n=== 同时加载两个API（模拟页面初始加载） ===")
    start_total = time.time()
    try:
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future1 = executor.submit(requests.get, f"{BASE_URL}/api/v1/stats/overview", timeout=30)
            future2 = executor.submit(requests.get, f"{BASE_URL}/api/v1/search/top-viewed?limit=10", timeout=30)
            response1 = future1.result()
            response2 = future2.result()
        end_total = time.time()
        total_duration = (end_total - start_total) * 1000
        print(f"同时加载两个API总时长: {total_duration:.2f}ms")
    except Exception as e:
        print(f"测试失败: {e}")
