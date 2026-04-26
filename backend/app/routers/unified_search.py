"""
统一搜索API
支持同时搜索CVE和非CVE漏洞
"""
from fastapi import APIRouter, Query, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, or_, text
from typing import Optional, List, Union
from datetime import date, datetime

from app.database import get_db
from app.models import CVE, CNVDVulnerability, OSVVulnerability, GitHubAdvisory

router = APIRouter()


class UnifiedVulnerability:
    """统一漏洞数据结构"""
    def __init__(self, cve=None, vuln=None, osv=None, github_advisory=None):
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
            self.references_count = len(vuln.references) if vuln.references else 0
            self.exploits_count = vuln.exploits_count if hasattr(vuln, 'exploits_count') else 0
        elif osv:
            self.type = "osv"
            self.id = osv.osv_id
            self.title = osv.summary
            self.description = osv.details
            self.source = "osv"
            self.severity = None
            self.cvss_score = None
            self.published_date = osv.published
            self.modified_date = osv.modified
            self.references_count = len(osv.references) if osv.references else 0
            self.exploits_count = osv.exploits_count if hasattr(osv, 'exploits_count') else 0
        elif github_advisory:
            self.type = "github_advisory"
            self.id = github_advisory.ghsa_id
            self.title = github_advisory.summary
            self.description = github_advisory.description
            self.source = "github_advisory"
            self.severity = github_advisory.severity
            self.cvss_score = github_advisory.cvss_score
            self.published_date = github_advisory.published_at
            self.modified_date = github_advisory.updated_at
            self.references_count = len(github_advisory.references) if isinstance(github_advisory.references, list) else 0
            self.exploits_count = 0


def build_full_text_search(query_str: str):
    """构建全文搜索查询"""
    if not query_str:
        return None
    
    words = query_str.replace("'", " ").split()
    tsquery_parts = []
    for word in words:
        if len(word) >= 3:
            tsquery_parts.append(f"'{word}:*'")
    
    if tsquery_parts:
        return " & ".join(tsquery_parts)
    return None


def estimate_count(db: Session, table_name: str, filter_query=None):
    """估算表的记录数"""
    if filter_query is None:
        # 使用reltuples估算
        result = db.execute(text(f"SELECT reltuples::bigint FROM pg_class WHERE relname = '{table_name}'"))
        return result.scalar() or 0
    
    # 如果有过滤器，执行实际计数但设置超时
    try:
        return filter_query.scalar() or 0
    except:
        # 如果计数超时，返回估算值
        result = db.execute(text(f"SELECT reltuples::bigint FROM pg_class WHERE relname = '{table_name}'"))
        return result.scalar() or 0


@router.get("/")
@router.get("")
def unified_search(
    q: Optional[str] = Query(None, description="搜索关键词"),
    type: Optional[str] = Query(None, description="漏洞类型: cve, cnvd, osv, github_advisory, all"),
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
    """统一搜索漏洞（同时搜索CVE、CNVD、OSV和GitHub Advisory漏洞）"""
    results = []
    sort_desc = sort_order.lower() == "desc"
    
    ts_query_str = build_full_text_search(q)
    
    cve_total = 0
    vuln_total = 0
    osv_total = 0
    gh_total = 0
    
    # 搜索CVE漏洞
    if type is None or type == "all" or type == "cve":
        cve_query = db.query(CVE)
        
        if q:
            if ts_query_str:
                cve_query = cve_query.filter(
                    text("to_tsvector('english', cve_id || ' ' || COALESCE(title, '') || ' ' || COALESCE(description, '')) @@ to_tsquery(:ts_query)")
                ).params(ts_query=ts_query_str)
            else:
                cve_query = cve_query.filter(
                    or_(
                        CVE.cve_id.ilike(f"%{q}%"),
                        CVE.title.ilike(f"%{q}%")
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
            if ts_query_str:
                vuln_query = vuln_query.filter(
                    text("to_tsvector('english', vuln_id || ' ' || COALESCE(title, '') || ' ' || COALESCE(description, '')) @@ to_tsquery(:ts_query)")
                ).params(ts_query=ts_query_str)
            else:
                vuln_query = vuln_query.filter(
                    or_(
                        CNVDVulnerability.vuln_id.ilike(f"%{q}%"),
                        CNVDVulnerability.title.ilike(f"%{q}%")
                    )
                )
        
        if type == "cnvd":
            vuln_query = vuln_query.filter(CNVDVulnerability.source == "CNVD")
        
        if severity:
            vuln_query = vuln_query.filter(CNVDVulnerability.severity == severity.lower())
        
        if has_exploit is not None:
            if has_exploit:
                vuln_query = vuln_query.filter(CNVDVulnerability.exploits_count > 0)
            else:
                vuln_query = vuln_query.filter(CNVDVulnerability.exploits_count == 0)
        
        if published_after:
            vuln_query = vuln_query.filter(CNVDVulnerability.published_date >= published_after)
        
        if published_before:
            vuln_query = vuln_query.filter(CNVDVulnerability.published_date <= published_before)
        
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
            if ts_query_str:
                osv_query = osv_query.filter(
                    text("to_tsvector('english', osv_id || ' ' || COALESCE(summary, '') || ' ' || COALESCE(details, '')) @@ to_tsquery(:ts_query)")
                ).params(ts_query=ts_query_str)
            else:
                osv_query = osv_query.filter(OSVVulnerability.osv_id.ilike(f"%{q}%"))
        
        if has_exploit is not None:
            if has_exploit:
                osv_query = osv_query.filter(OSVVulnerability.exploits_count > 0)
            else:
                osv_query = osv_query.filter(OSVVulnerability.exploits_count == 0)
        
        if published_after:
            osv_query = osv_query.filter(OSVVulnerability.published >= published_after)
        
        if published_before:
            osv_query = osv_query.filter(OSVVulnerability.published <= published_before)
        
        if sort_by == "modified_date":
            osv_query = osv_query.order_by(OSVVulnerability.modified.desc() if sort_desc else OSVVulnerability.modified.asc())
        else:
            osv_query = osv_query.order_by(OSVVulnerability.published.desc() if sort_desc else OSVVulnerability.published.asc())
        
        osv_results = osv_query.offset((page - 1) * page_size // 4).limit(page_size // 4).all()
        for osv in osv_results:
            results.append(UnifiedVulnerability(osv=osv))
    
    # 搜索GitHub Advisory漏洞
    if type is None or type == "all" or type == "github_advisory":
        gh_query = db.query(GitHubAdvisory)
        
        if q:
            if ts_query_str:
                gh_query = gh_query.filter(
                    text("to_tsvector('english', ghsa_id || ' ' || COALESCE(cve_id, '') || ' ' || COALESCE(summary, '') || ' ' || COALESCE(description, '')) @@ to_tsquery(:ts_query)")
                ).params(ts_query=ts_query_str)
            else:
                gh_query = gh_query.filter(
                    or_(
                        GitHubAdvisory.ghsa_id.ilike(f"%{q}%"),
                        GitHubAdvisory.cve_id.ilike(f"%{q}%")
                    )
                )
        
        if severity:
            gh_query = gh_query.filter(GitHubAdvisory.severity == severity.lower())
        
        if published_after:
            gh_query = gh_query.filter(GitHubAdvisory.published_at >= published_after)
        
        if published_before:
            gh_query = gh_query.filter(GitHubAdvisory.published_at <= published_before)
        
        if sort_by == "modified_date":
            gh_query = gh_query.order_by(GitHubAdvisory.updated_at.desc() if sort_desc else GitHubAdvisory.updated_at.asc())
        else:
            gh_query = gh_query.order_by(GitHubAdvisory.published_at.desc() if sort_desc else GitHubAdvisory.published_at.asc())
        
        gh_results = gh_query.offset((page - 1) * page_size // 4).limit(page_size // 4).all()
        for gh in gh_results:
            results.append(UnifiedVulnerability(github_advisory=gh))
    
    # 合并后排序
    if sort_by == "modified_date":
        results.sort(key=lambda x: x.modified_date if x.modified_date else datetime.min, reverse=sort_desc)
    else:
        results.sort(key=lambda x: x.published_date if x.published_date else datetime.min, reverse=sort_desc)
    
    # 获取总数（使用估算方式，不进行全文搜索计数）
    if type is None or type == "all" or type == "cve":
        cve_total = estimate_count(db, 'cves')
    
    if type is None or type == "all" or type == "cnvd":
        vuln_total = estimate_count(db, 'cnvd_vulnerabilities')
    
    if type is None or type == "all" or type == "osv":
        osv_total = estimate_count(db, 'osv_vulnerabilities')
    
    if type is None or type == "all" or type == "github_advisory":
        gh_total = estimate_count(db, 'github_advisories')
    
    total = cve_total + vuln_total + osv_total + gh_total
    
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
                "exploits_count": r.exploits_count if hasattr(r, 'exploits_count') else 0
            }
            for r in results
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
        "cve_count": cve_total,
        "vulnerability_count": vuln_total,
        "osv_count": osv_total,
        "github_advisory_count": gh_total
    }


@router.get("/stats")
def get_unified_stats(db: Session = Depends(get_db)):
    """获取统一统计信息"""
    cve_count = db.query(CVE).count()
    vuln_count = db.query(CNVDVulnerability).count()
    osv_count = db.query(OSVVulnerability).count()
    gh_count = db.query(GitHubAdvisory).count()
    
    cve_severity_stats = db.query(CVE.cvss_v3_severity, func.count(CVE.id)) \
                          .group_by(CVE.cvss_v3_severity) \
                          .all()
    
    gh_severity_stats = db.query(GitHubAdvisory.severity, func.count(GitHubAdvisory.id)) \
                          .group_by(GitHubAdvisory.severity) \
                          .all()
    
    vuln_source_stats = db.query(CNVDVulnerability.source, func.count(CNVDVulnerability.id)) \
                          .group_by(CNVDVulnerability.source) \
                          .order_by(func.count(CNVDVulnerability.id).desc()) \
                          .all()
    
    return {
        "total_cves": cve_count,
        "total_vulnerabilities": vuln_count,
        "total_osv": osv_count,
        "total_github_advisory": gh_count,
        "total": cve_count + vuln_count + osv_count + gh_count,
        "cve_severity_distribution": {severity: count for severity, count in cve_severity_stats},
        "github_advisory_severity_distribution": {severity: count for severity, count in gh_severity_stats},
        "vulnerability_source_distribution": {source: count for source, count in vuln_source_stats}
    }
