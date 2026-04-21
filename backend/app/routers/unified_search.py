"""
统一搜索API
支持同时搜索CVE和非CVE漏洞
"""
from fastapi import APIRouter, Query, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, or_
from typing import Optional, List, Union
from datetime import date

from app.database import get_db
from app.models import CVE, CNVDVulnerability, OSVVulnerability

router = APIRouter()


class UnifiedVulnerability:
    """统一漏洞数据结构"""
    def __init__(self, cve=None, vuln=None, osv=None):
        if cve:
            self.type = "cve"
            self.id = cve.cve_id
            self.title = cve.title
            self.description = cve.description
            self.source = "cvelistv5"
            self.severity = cve.cvss_v3_severity or cve.cvss_v4_severity
            self.cvss_score = cve.cvss_v3_score or cve.cvss_v4_score
            self.published_date = cve.published_date
            self.modified_date = cve.modified_date
            self.cwe_ids = cve.cwes
            self.references_count = cve.references_count
            self.exploits_count = cve.exploits_count
        elif vuln:
            self.type = "vulnerability"
            self.id = vuln.vuln_id
            self.title = vuln.title
            self.description = vuln.description
            self.source = vuln.source
            self.severity = vuln.severity
            self.cvss_score = vuln.cvss_v3_score
            self.published_date = vuln.published_date
            self.modified_date = vuln.modified_date
            self.cwe_ids = vuln.cwe_ids
            self.references_count = len(vuln.references) if vuln.references else 0
            self.exploits_count = 0
        elif osv:
            self.type = "osv"
            self.id = osv.osv_id
            self.title = osv.summary
            self.description = osv.details
            self.source = "osv"
            self.severity = osv.database_specific.get("severity") if isinstance(osv.database_specific, dict) else None
            self.cvss_score = None
            if isinstance(osv.severity, list) and len(osv.severity) > 0:
                for sev in osv.severity:
                    if isinstance(sev, dict) and "score" in sev:
                        score_str = sev["score"]
                        if score_str.startswith("CVSS:"):
                            import re
                            match = re.search(r'/AV:(\w)/AC:(\w)/', score_str)
                            if match:
                                pass
            self.published_date = osv.published
            self.modified_date = osv.modified
            self.cwe_ids = osv.database_specific.get("cwe_ids") if isinstance(osv.database_specific, dict) else None
            self.references_count = len(osv.references) if osv.references else 0
            self.exploits_count = 0


@router.get("/")
@router.get("")
def unified_search(
    q: Optional[str] = Query(None, description="搜索关键词"),
    type: Optional[str] = Query(None, description="漏洞类型: cve, cnvd, osv, all"),
    severity: Optional[str] = Query(None, description="严重程度筛选"),
    has_exploit: Optional[bool] = Query(None, description="是否有exploit"),
    published_after: Optional[date] = Query(None, description="发布日期开始"),
    published_before: Optional[date] = Query(None, description="发布日期结束"),
    sort_by: str = Query("published_date", description="排序字段: published_date, modified_date"),
    sort_order: str = Query("desc", description="排序方向: asc, desc"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """统一搜索漏洞（同时搜索CVE和非CVE漏洞）"""
    results = []
    
    # 确定排序字段和方向
    sort_desc = sort_order.lower() == "desc"
    
    # 搜索CVE漏洞
    if type is None or type == "all" or type == "cve":
        cve_query = db.query(CVE)
        
        if q:
            cve_query = cve_query.filter(
                or_(
                    CVE.cve_id.ilike(f"%{q}%"),
                    CVE.title.ilike(f"%{q}%"),
                    CVE.description.ilike(f"%{q}%")
                )
            )
        
        if severity:
            cve_query = cve_query.filter(CVE.cvss_v3_severity == severity.upper())
        
        if has_exploit is not None:
            if has_exploit:
                cve_query = cve_query.filter(CVE.exploits_count > 0)
            else:
                cve_query = cve_query.filter(CVE.exploits_count == 0)
        
        if published_after:
            cve_query = cve_query.filter(CVE.published_date >= published_after)
        
        if published_before:
            cve_query = cve_query.filter(CVE.published_date <= published_before)
        
        # 添加排序
        if sort_by == "modified_date":
            cve_query = cve_query.order_by(CVE.modified_date.desc() if sort_desc else CVE.modified_date.asc())
        else:
            cve_query = cve_query.order_by(CVE.published_date.desc() if sort_desc else CVE.published_date.asc())
        
        cve_results = cve_query.offset((page - 1) * page_size // 2).limit(page_size // 2).all()
        for cve in cve_results:
            results.append(UnifiedVulnerability(cve=cve))
    
    # 搜索CNVD漏洞
    if type is None or type == "all" or type == "cnvd":
        vuln_query = db.query(CNVDVulnerability)
        
        if q:
            vuln_query = vuln_query.filter(
                or_(
                    CNVDVulnerability.vuln_id.ilike(f"%{q}%"),
                    CNVDVulnerability.title.ilike(f"%{q}%"),
                    CNVDVulnerability.description.ilike(f"%{q}%")
                )
            )
        
        # 当明确选择CNVD类型时，只显示source=CNVD的数据
        if type == "cnvd":
            vuln_query = vuln_query.filter(CNVDVulnerability.source == "CNVD")
        
        if severity:
            vuln_query = vuln_query.filter(CNVDVulnerability.severity == severity.lower())
        
        if published_after:
            vuln_query = vuln_query.filter(CNVDVulnerability.published_date >= published_after)
        
        if published_before:
            vuln_query = vuln_query.filter(CNVDVulnerability.published_date <= published_before)
        
        # 添加排序
        if sort_by == "modified_date":
            vuln_query = vuln_query.order_by(CNVDVulnerability.modified_date.desc() if sort_desc else CNVDVulnerability.modified_date.asc())
        else:
            vuln_query = vuln_query.order_by(CNVDVulnerability.published_date.desc() if sort_desc else CNVDVulnerability.published_date.asc())
        
        vuln_results = vuln_query.offset((page - 1) * page_size // 3).limit(page_size // 3).all()
        for vuln in vuln_results:
            results.append(UnifiedVulnerability(vuln=vuln))
    
    # 搜索OSV漏洞
    if type is None or type == "all" or type == "osv":
        osv_query = db.query(OSVVulnerability)
        
        if q:
            osv_query = osv_query.filter(
                or_(
                    OSVVulnerability.osv_id.ilike(f"%{q}%"),
                    OSVVulnerability.summary.ilike(f"%{q}%"),
                    OSVVulnerability.details.ilike(f"%{q}%")
                )
            )
        
        if published_after:
            osv_query = osv_query.filter(OSVVulnerability.published >= published_after)
        
        if published_before:
            osv_query = osv_query.filter(OSVVulnerability.published <= published_before)
        
        # 添加排序
        if sort_by == "modified_date":
            osv_query = osv_query.order_by(OSVVulnerability.modified.desc() if sort_desc else OSVVulnerability.modified.asc())
        else:
            osv_query = osv_query.order_by(OSVVulnerability.published.desc() if sort_desc else OSVVulnerability.published.asc())
        
        osv_results = osv_query.offset((page - 1) * page_size // 3).limit(page_size // 3).all()
        for osv in osv_results:
            results.append(UnifiedVulnerability(osv=osv))
    
    # 合并后再次排序（确保跨类型排序正确）
    if sort_by == "modified_date":
        results.sort(key=lambda x: x.modified_date or "", reverse=sort_desc)
    else:
        results.sort(key=lambda x: x.published_date or "", reverse=sort_desc)
    
    # 获取总数
    cve_total_query = db.query(CVE)
    if q:
        cve_total_query = cve_total_query.filter(
            or_(
                CVE.cve_id.ilike(f"%{q}%"),
                CVE.title.ilike(f"%{q}%"),
                CVE.description.ilike(f"%{q}%")
            )
        )
    if severity:
        cve_total_query = cve_total_query.filter(CVE.cvss_v3_severity == severity.upper())
    if has_exploit is not None:
        if has_exploit:
            cve_total_query = cve_total_query.filter(CVE.exploits_count > 0)
        else:
            cve_total_query = cve_total_query.filter(CVE.exploits_count == 0)
    if published_after:
        cve_total_query = cve_total_query.filter(CVE.published_date >= published_after)
    if published_before:
        cve_total_query = cve_total_query.filter(CVE.published_date <= published_before)
    
    vuln_total_query = db.query(CNVDVulnerability)
    if q:
        vuln_total_query = vuln_total_query.filter(
            or_(
                CNVDVulnerability.vuln_id.ilike(f"%{q}%"),
                CNVDVulnerability.title.ilike(f"%{q}%"),
                CNVDVulnerability.description.ilike(f"%{q}%")
            )
        )
    if severity:
        vuln_total_query = vuln_total_query.filter(CNVDVulnerability.severity == severity.lower())
    if published_after:
        vuln_total_query = vuln_total_query.filter(CNVDVulnerability.published_date >= published_after)
    if published_before:
        vuln_total_query = vuln_total_query.filter(CNVDVulnerability.published_date <= published_before)
    
    # OSV总数查询
    osv_total_query = db.query(OSVVulnerability)
    if q:
        osv_total_query = osv_total_query.filter(
            or_(
                OSVVulnerability.osv_id.ilike(f"%{q}%"),
                OSVVulnerability.summary.ilike(f"%{q}%"),
                OSVVulnerability.details.ilike(f"%{q}%")
            )
        )
    if published_after:
        osv_total_query = osv_total_query.filter(OSVVulnerability.published >= published_after)
    if published_before:
        osv_total_query = osv_total_query.filter(OSVVulnerability.published <= published_before)
    
    cve_total = cve_total_query.count() if type is None or type == "all" or type == "cve" else 0
    vuln_total = vuln_total_query.count() if type is None or type == "all" or type == "cnvd" else 0
    osv_total = osv_total_query.count() if type is None or type == "all" or type == "osv" else 0
    total = cve_total + vuln_total + osv_total
    
    return {
        "data": [
            {
                "type": r.type,
                "id": r.id,
                "title": r.title,
                "description": r.description[:200] + "..." if r.description and len(r.description) > 200 else r.description,
                "source": r.source,
                "severity": r.severity,
                "cvss_score": r.cvss_score,
                "published_date": r.published_date,
                "references_count": r.references_count,
                "exploits_count": r.exploits_count
            }
            for r in results
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
        "cve_count": cve_total,
        "vulnerability_count": vuln_total,
        "osv_count": osv_total
    }


@router.get("/stats")
def get_unified_stats(db: Session = Depends(get_db)):
    """获取统一统计信息"""
    cve_count = db.query(CVE).count()
    vuln_count = db.query(CNVDVulnerability).count()
    osv_count = db.query(OSVVulnerability).count()
    
    # CVE按严重程度统计
    cve_severity_stats = db.query(CVE.cvss_v3_severity, func.count(CVE.id)) \
                          .group_by(CVE.cvss_v3_severity) \
                          .all()
    
    # 非CVE漏洞按来源统计
    vuln_source_stats = db.query(CNVDVulnerability.source, func.count(CNVDVulnerability.id)) \
                          .group_by(CNVDVulnerability.source) \
                          .order_by(func.count(CNVDVulnerability.id).desc()) \
                          .all()
    
    return {
        "total_cves": cve_count,
        "total_vulnerabilities": vuln_count,
        "total_osv": osv_count,
        "total": cve_count + vuln_count + osv_count,
        "cve_severity_distribution": {severity: count for severity, count in cve_severity_stats},
        "vulnerability_source_distribution": {source: count for source, count in vuln_source_stats}
    }