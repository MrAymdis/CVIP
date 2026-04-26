"""
测试爬虫数据格式展示
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.crawlers.packetstorm_crawler import PacketStormCrawler

# 模拟的测试数据
TEST_DATA = [
    {
        'title': 'CVE-2024-12345 WordPress Plugin Remote Code Execution',
        'url': 'https://packetstormsecurity.com/files/178000/CVE-2024-12345.txt',
        'cve_ids': ['CVE-2024-12345']
    },
    {
        'title': 'CVE-2024-67890 PHP File Upload Vulnerability',
        'url': 'https://packetstormsecurity.com/files/178001/CVE-2024-67890.php',
        'cve_ids': ['CVE-2024-67890']
    },
    {
        'title': 'Apache Struts Remote Command Execution',
