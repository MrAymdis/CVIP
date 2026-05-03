import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models.cnvd import CNVDVulnerability, CNVDVulnerabilityReference
from app.database import Base

def parse_severity(severity_str):
    """转换中文严重程度为标准格式"""
    severity_map = {
        '严重': 'critical',
        '高': 'high',
        '中': 'medium',
        '低': 'low',
        '信息': 'info'
    }
    return severity_map.get(severity_str, severity_str.lower())

def import_cnvd_xml(xml_file_path, db_url):
    """导入CNVD XML文件到数据库"""
    engine = create_engine(db_url)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    
    try:
        tree = ET.parse(xml_file_path)
        root = tree.getroot()
        
        imported_count = 0
        skipped_count = 0
        
        for vulnerability_elem in root.findall('vulnerability'):
            vuln_id = vulnerability_elem.findtext('number', '').strip()
            
            if not vuln_id:
                skipped_count += 1
                continue
            
            existing = db.query(CNVDVulnerability).filter(CNVDVulnerability.vuln_id == vuln_id).first()
            if existing:
                skipped_count += 1
                continue
            
            title = vulnerability_elem.findtext('title', '').strip()
            description = vulnerability_elem.findtext('description', '').strip()
            severity = parse_severity(vulnerability_elem.findtext('serverity', '').strip())
            
            cve_ids = []
            cves_elem = vulnerability_elem.find('cves')
            if cves_elem is not None:
                for cve_elem in cves_elem.findall('cve'):
                    cve_number = cve_elem.findtext('cveNumber', '').strip()
                    if cve_number:
                        cve_ids.append(cve_number)
            
            references = []
            reference_link = vulnerability_elem.findtext('referenceLink', '').strip()
            if reference_link:
                references.append(reference_link)
            
            submit_time_str = vulnerability_elem.findtext('submitTime', '').strip()
            open_time_str = vulnerability_elem.findtext('openTime', '').strip()
            
            published_date = None
            if submit_time_str:
                try:
                    published_date = datetime.strptime(submit_time_str, '%Y-%m-%d')
                except:
                    pass
            
            modified_date = None
            if open_time_str:
                try:
                    modified_date = datetime.strptime(open_time_str, '%Y-%m-%d')
                except:
                    pass
            
            products = []
            products_elem = vulnerability_elem.find('products')
            if products_elem is not None:
                for product_elem in products_elem.findall('product'):
                    product_name = product_elem.text.strip() if product_elem.text else ''
                    if product_name:
                        products.append(product_name)
            
            solution = vulnerability_elem.findtext('formalWay', '').strip()
            
            new_vuln = CNVDVulnerability(
                vuln_id=vuln_id,
                title=title,
                description=description,
                source='CNVD',
                severity=severity,
                published_date=published_date,
                modified_date=modified_date,
                related_cve_ids=cve_ids if cve_ids else None,
                references=references if references else None,
                tags=products if products else None,
                affected_products=products if products else None,
                solution=solution if solution else None,
                data_sources=['CNVD']
            )
            
            db.add(new_vuln)
            imported_count += 1
            
            if imported_count % 50 == 0:
                db.commit()
                print(f"已导入 {imported_count} 条记录...")
        
        db.commit()
        print(f"\n导入完成！")
        print(f"成功导入: {imported_count} 条")
        print(f"跳过(已存在或无效): {skipped_count} 条")
        
    except Exception as e:
        db.rollback()
        print(f"导入失败: {str(e)}")
        raise
    finally:
        db.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("用法: python import_cnvd.py <xml_file_path>")
        sys.exit(1)
    
    xml_file = sys.argv[1]
    
    if not os.path.exists(xml_file):
        print(f"错误: 文件不存在 {xml_file}")
        sys.exit(1)
    
    db_url = os.getenv("DATABASE_URL", "postgresql://cve:cvepassword@localhost:5432/cve_db")
    import_cnvd_xml(xml_file, db_url)