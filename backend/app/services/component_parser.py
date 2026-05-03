"""
组件信息解析服务
从 unified_vulnerabilities.affected 字段提取厂商、产品、组件信息
"""
import re
import json
from typing import Dict, List, Optional, Tuple
from sqlalchemy.orm import Session
from app.models import UnifiedVulnerability, Component
from app.models.component import COMPONENT_CATEGORIES

# 厂商名称映射字典
VENDOR_MAP = {
    # 国际厂商
    'ibm': 'IBM',
    'microsoft': 'Microsoft',
    'linux': 'Linux',
    'apple': 'Apple',
    'cisco': 'Cisco',
    'adobe': 'Adobe',
    'oracle': 'Oracle',
    'google': 'Google',
    'amazon': 'Amazon',
    'sap': '德国思爱普（SAP）公司',
    'vmware': 'VMware, Inc.',
    'intel': 'Intel',
    'amd': 'AMD',
    'nvidia': 'NVIDIA',
    'hp': 'HP',
    'dell': 'Dell',
    'lenovo': '联想',
    'sony': 'Sony',
    'samsung': 'Samsung',
    'panasonic': 'Panasonic',
    'canon': 'Canon',
    'epson': 'Epson',
    'xerox': 'Xerox',
    'symantec': 'Symantec',
    'mcafee': 'McAfee',
    'kaspersky': '卡巴斯基',
    'fortinet': 'Fortinet',
    'paloalto': 'Palo Alto Networks',
    'juniper': 'Juniper Networks',
    'netapp': 'NetApp',
    'citrix': 'Citrix',
    'redhat': 'Red Hat',
    'suse': 'SUSE',
    'debian': 'Debian',
    'ubuntu': 'Ubuntu',
    'mozilla': 'Mozilla',
    'opera': 'Opera',
    'openbsd': 'OpenBSD',
    'freebsd': 'FreeBSD',
    'ibm': 'IBM',
    'hp': 'HP',
    'dell': 'Dell',
    'huawei': '华为',
    'zte': '中兴',
    'h3c': 'H3C',
    'tp-link': 'TP-Link',
    'huawei': '华为',
    # 国内厂商
    '深信服': '深信服科技股份有限公司',
    '华为': '华为技术有限公司',
    '浪潮': '浪潮集团',
    '阿里云': '阿里巴巴集团',
    '腾讯': '腾讯科技（深圳）有限公司',
    '百度': '百度在线网络技术（北京）有限公司',
    '小米': '小米科技有限责任公司',
    '奇虎': '奇虎360',
    '金山': '金山软件',
    '网易': '网易',
    '京东': '京东',
    '美团': '美团',
    '滴滴': '滴滴',
    '字节跳动': '字节跳动',
    '快手': '快手',
    '搜狐': '搜狐',
    '新浪': '新浪',
    '携程': '携程',
    '同程': '同程旅行',
    '用友': '用友网络',
    '金蝶': '金蝶软件',
    '东软': '东软集团',
    '中软': '中国软件',
    '神州数码': '神州数码',
    '太极股份': '太极股份',
    '启明星辰': '启明星辰',
    '绿盟科技': '绿盟科技',
    '天融信': '天融信',
    '山石网科': '山石网科',
    '安恒信息': '安恒信息',
    '赛门铁克': '赛门铁克',
    '趋势科技': '趋势科技',
    '福克斯': 'Foxit',
    'foxit': 'Foxit',
}

# 产品分类映射
CATEGORY_MAP = {
    'windows': '操作系统',
    'linux': '操作系统',
    'macos': '操作系统',
    'ios': '操作系统',
    'android': '操作系统',
    'sql': '数据库',
    'mysql': '数据库',
    'oracle': '数据库',
    'postgresql': '数据库',
    'nginx': '应用服务',
    'apache': '应用服务',
    'tomcat': '应用服务',
    'spring': '开发框架',
    'django': '开发框架',
    'node': '开发语言',
    'python': '开发语言',
    'java': '开发语言',
    'javascript': '开发语言',
    'npm': '中间件',
    'maven': '中间件',
    'redis': '数据库',
    'mongodb': '数据库',
    'kubernetes': '云平台设备',
    'docker': '云平台设备',
    'vpn': '网络安全设备',
    'firewall': '网络安全设备',
}

def parse_cnvd_affected(affected_list: List[str]) -> List[Dict]:
    """
    解析 CNVD 类型的 affected 数据
    格式: ["IBM InfoSphere Information Server 11.3", "ofsoft OFCMS <1.1.3"]
    """
    results = []
    
    for item in affected_list:
        if not isinstance(item, str) or not item.strip():
            continue
            
        item = item.strip()
        
        # 尝试提取厂商和产品信息
        vendor, product, version = extract_vendor_product_version(item)
        
        results.append({
            'vendor': vendor,
            'product': product,
            'version': version,
            'full_text': item
        })
    
    return results


def parse_cve_affected(affected_list: List[Dict]) -> List[Dict]:
    """
    解析 CVE 类型的 affected 数据
    格式: [{"vendor": "Linux", "product": "Linux", "versions": [...]}, ...]
    """
    results = []
    
    for item in affected_list:
        if not isinstance(item, dict):
            continue
            
        vendor = item.get('vendor', '').strip()
        product = item.get('product', '').strip()
        
        # 提取版本信息
        versions = []
        if 'versions' in item and isinstance(item['versions'], list):
            for v in item['versions']:
                if isinstance(v, dict):
                    version = v.get('version', '')
                    status = v.get('status', '')
                    versions.append(f"{version} ({status})" if status else version)
                elif isinstance(v, str):
                    versions.append(v)
        
        results.append({
            'vendor': vendor,
            'product': product,
            'version': ', '.join(versions) if versions else None,
            'full_text': json.dumps(item, ensure_ascii=False)
        })
    
    return results


def parse_osv_affected(affected_list: List[Dict]) -> List[Dict]:
    """
    解析 OSV 类型的 affected 数据
    格式: [{"package": {"name": "mistune", "ecosystem": "PyPI"}, "ranges": [...]}, ...]
    """
    results = []
    
    for item in affected_list:
        if not isinstance(item, dict):
            continue
            
        vendor = None
        product = None
        version = None
        ecosystem = None
        
        # 提取包信息
        if 'package' in item and isinstance(item['package'], dict):
            product = item['package'].get('name', '')
            ecosystem = item['package'].get('ecosystem', '')
        
        # 提取版本范围信息
        versions = []
        if 'versions' in item and isinstance(item['versions'], list):
            versions.extend(item['versions'])
        
        if 'ranges' in item and isinstance(item['ranges'], list):
            for r in item['ranges']:
                if isinstance(r, dict) and 'events' in r:
                    for event in r['events']:
                        if isinstance(event, dict):
                            if 'introduced' in event:
                                versions.append(f"introduced: {event['introduced']}")
                            if 'fixed' in event:
                                versions.append(f"fixed: {event['fixed']}")
                            if 'last_affected' in event:
                                versions.append(f"last_affected: {event['last_affected']}")
        
        results.append({
            'vendor': vendor,
            'product': product,
            'version': ', '.join(versions) if versions else None,
            'ecosystem': ecosystem,
            'full_text': json.dumps(item, ensure_ascii=False)
        })
    
    return results


def parse_ghsa_affected(affected_packages: List[Dict]) -> List[Dict]:
    """
    解析 GHSA 类型的 affected 数据
    格式: [{"package": {"name": "xxx", "ecosystem": "xxx"}, "versions": {...}}]
    """
    results = []
    
    for item in affected_packages:
        if not isinstance(item, dict):
            continue
            
        vendor = None
        product = None
        version = None
        ecosystem = None
        
        if 'package' in item and isinstance(item['package'], dict):
            product = item['package'].get('name', '')
            ecosystem = item['package'].get('ecosystem', '')
        
        if 'versions' in item and isinstance(item['versions'], dict):
            version_info = []
            if 'introduced' in item['versions']:
                version_info.append(f"introduced: {item['versions']['introduced']}")
            if 'fixed' in item['versions']:
                version_info.append(f"fixed: {item['versions']['fixed']}")
            if 'affected' in item['versions']:
                version_info.append(f"affected: {', '.join(item['versions']['affected'])}")
            version = ', '.join(version_info)
        
        results.append({
            'vendor': vendor,
            'product': product,
            'version': version,
            'ecosystem': ecosystem,
            'full_text': json.dumps(item, ensure_ascii=False)
        })
    
    return results


def extract_vendor_product_version(text: str) -> Tuple[str, str, str]:
    """
    从文本中提取厂商、产品和版本信息
    """
    vendor = None
    product = text
    version = None
    
    # 先尝试匹配已知厂商
    text_lower = text.lower()
    for vendor_key, vendor_name in VENDOR_MAP.items():
        if vendor_key.lower() in text_lower:
            vendor = vendor_name
            break
    
    # 提取版本信息
    version_patterns = [
        r'(\d+\.\d+(\.\d+)*)',           # 1.0, 1.1.3
        r'(<=|>=|<|>)\s*[\d.]+',          # <=1.1.3, >=2.0
        r'v?\d+\.\d+(\.\d+)*',           # v1.0, 2.3.4
        r'版本\s*[\d.]+',                 # 版本1.0
    ]
    
    for pattern in version_patterns:
        match = re.search(pattern, text)
        if match:
            version = match.group(0)
            product = text.replace(version, '').strip()
            break
    
    # 如果没有找到版本，尝试匹配 "版本" 关键词
    if version is None:
        version_match = re.search(r'版本\s*([\d.]+)', text)
        if version_match:
            version = version_match.group(1)
            product = text.replace(version_match.group(0), '').strip()
    
    # 清理产品名称
    product = product.strip().replace('  ', ' ')
    
    return (vendor, product, version)


def infer_category(product: str, ecosystem: str = None) -> str:
    """
    根据产品名称推断分类
    """
    if not product:
        return "未知"
    
    product_lower = product.lower()
    
    # 优先根据生态系统判断
    if ecosystem:
        if ecosystem.lower() in ['npm', 'npm registry']:
            return "中间件"
        elif ecosystem.lower() in ['pypi', 'python package index']:
            return "开发框架"
        elif ecosystem.lower() in ['maven', 'maven central']:
            return "中间件"
        elif ecosystem.lower() in ['go', 'golang']:
            return "开发语言"
    
    # 根据产品名称判断
    for keyword, category in CATEGORY_MAP.items():
        if keyword in product_lower:
            return category
    
    return "未知"


def parse_affected_data(affected_data, vuln_type: str) -> List[Dict]:
    """
    根据漏洞类型解析 affected 字段
    """
    if affected_data is None:
        return []
    
    if not isinstance(affected_data, list):
        return []
    
    if vuln_type == 'cnvd':
        return parse_cnvd_affected(affected_data)
    elif vuln_type == 'cve':
        return parse_cve_affected(affected_data)
    elif vuln_type == 'osv':
        return parse_osv_affected(affected_data)
    elif vuln_type == 'ghsa':
        return parse_ghsa_affected(affected_data)
    else:
        return parse_cnvd_affected(affected_data)


def sync_components_from_vulnerabilities(db: Session, limit: int = 10000):
    """
    从漏洞数据同步组件信息
    """
    print('=' * 60)
    print('Starting component sync from vulnerabilities...')
    print('=' * 60)
    
    # 获取有 affected 数据的漏洞
    query = db.query(UnifiedVulnerability).filter(
        UnifiedVulnerability.affected.isnot(None)
    ).limit(limit)
    
    processed = 0
    added = 0
    updated = 0
    processed_component_ids = set()
    
    for vuln in query:
        if processed % 1000 == 0:
            print(f'  Processed: {processed}, Added: {added}, Updated: {updated}')
        
        affected_items = parse_affected_data(vuln.affected, vuln.type)
        
        for item in affected_items:
            vendor = item.get('vendor')
            product = item.get('product')
            version = item.get('version')
            ecosystem = item.get('ecosystem')
            
            if not product:
                continue
            
            component_id_base = re.sub(r'[^a-zA-Z0-9_-]', '-', product.lower())[:50]
            component_id = f"cmp-{component_id_base}-{hash(product) % 10000:04d}"
            
            # 跳过已处理过的组件（跨漏洞）
            if component_id in processed_component_ids:
                continue
            processed_component_ids.add(component_id)
            
            existing = db.query(Component).filter(
                Component.component_id == component_id
            ).first()
            
            category = infer_category(product, ecosystem)
            
            component_data = {
                'name': product,
                'component_id': component_id,
                'vendor_name': vendor,
                'category': category,
                'product_name': product,
                'product_version': version,
                'ecosystem': ecosystem,
                'data_source': vuln.type.upper(),
                'related_vuln_ids': [],
            }
            
            if existing:
                for key, value in component_data.items():
                    if value:
                        setattr(existing, key, value)
                
                if vuln.vuln_id not in (existing.related_vuln_ids or []):
                    existing.related_vuln_ids = (existing.related_vuln_ids or []) + [vuln.vuln_id]
                
                updated += 1
            else:
                component_data['related_vuln_ids'] = [vuln.vuln_id]
                new_component = Component(**component_data)
                db.add(new_component)
                added += 1
        
        processed += 1
        
        if processed % 100 == 0:
            db.commit()
    
    db.commit()
    
    print('=' * 60)
    print(f'Component sync completed!')
    print(f'  Total processed vulnerabilities: {processed}')
    print(f'  Added components: {added}')
    print(f'  Updated components: {updated}')
    print('=' * 60)
    
    return added, updated


if __name__ == "__main__":
    from app.database import SessionLocal
    
    db = SessionLocal()
    try:
        sync_components_from_vulnerabilities(db, limit=50000)
    finally:
        db.close()
