"""
统一搜索API
支持同时搜索CVE、CNVD、OSV和GitHub Advisory漏洞
使用统一漏洞数据表进行搜索
"""
from fastapi import APIRouter, Query, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, or_, text, String
from typing import Optional, List, Dict
from datetime import date, datetime, timedelta

from app.database import get_db
from app.models import UnifiedVulnerability

router = APIRouter()


@router.get("/")
@router.get("")
def unified_search(
    q: Optional[str] = Query(None, description="搜索关键词"),
    type: Optional[str] = Query(None, description="漏洞源类型: cve, cnvd, osv, ghsa, all"),
    severity: Optional[str] = Query(None, description="严重程度筛选"),
    cwe: Optional[str] = Query(None, description="CWE漏洞类型筛选（如CWE-284）"),
    affected_product: Optional[str] = Query(None, description="受影响产品筛选"),
    has_exploit: Optional[bool] = Query(None, description="是否有exploit"),
    cisa_kev: Optional[bool] = Query(None, description="是否CISA KEV"),
    published_after: Optional[date] = Query(None, description="发布日期开始"),
    published_before: Optional[date] = Query(None, description="发布日期结束"),
    cvss_min: Optional[float] = Query(None, description="CVSS最低评分"),
    cvss_max: Optional[float] = Query(None, description="CVSS最高评分"),
    sort_by: str = Query("published_date", description="排序字段: published_date, modified_date, cvss_v3_score"),
    sort_order: str = Query("desc", description="排序方向: asc, desc"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """统一搜索漏洞（使用统一漏洞数据表）"""
    query = db.query(UnifiedVulnerability)
    
    sort_desc = sort_order.lower() == "desc"
    
    if q:
        words = q.replace("'", " ").split()
        tsquery_parts = []
        for word in words:
            if len(word) >= 2:
                tsquery_parts.append(f"'{word}:*'")
        
        if tsquery_parts:
            ts_query_str = " & ".join(tsquery_parts)
            query = query.filter(
                text("to_tsvector('english', vuln_id || ' ' || COALESCE(title, '') || ' ' || COALESCE(description, '')) @@ to_tsquery(:ts_query)")
            ).params(ts_query=ts_query_str)
        else:
            query = query.filter(
                or_(
                    UnifiedVulnerability.vuln_id.ilike(f"%{q}%"),
                    UnifiedVulnerability.title.ilike(f"%{q}%"),
                    UnifiedVulnerability.description.ilike(f"%{q}%")
                )
            )
    
    if type and type != "all":
        query = query.filter(UnifiedVulnerability.type == type.lower())
    
    if severity:
        query = query.filter(UnifiedVulnerability.severity == severity.upper())
    
    if has_exploit is not None:
        if has_exploit:
            query = query.filter(UnifiedVulnerability.exploits_count > 0)
        else:
            query = query.filter(UnifiedVulnerability.exploits_count == 0)
    
    if cisa_kev is not None:
        query = query.filter(UnifiedVulnerability.cisa_kev == cisa_kev)
    
    if cwe:
        cwe_pattern = cwe.upper()
        query = query.filter(UnifiedVulnerability.cwes.any(cwe_pattern))

    if affected_product:
        query = query.filter(UnifiedVulnerability.affected.cast(String).ilike(f"%{affected_product}%"))

    if published_after:
        query = query.filter(UnifiedVulnerability.published_date >= published_after)

    if published_before:
        query = query.filter(UnifiedVulnerability.published_date <= published_before)

    if cvss_min is not None:
        query = query.filter(UnifiedVulnerability.cvss_v3_score >= cvss_min)

    if cvss_max is not None:
        query = query.filter(UnifiedVulnerability.cvss_v3_score <= cvss_max)

    total = query.count()
    
    if sort_by == "modified_date":
        query = query.order_by(UnifiedVulnerability.modified_date.desc() if sort_desc else UnifiedVulnerability.modified_date.asc())
    elif sort_by == "cvss_v3_score":
        query = query.order_by(UnifiedVulnerability.cvss_v3_score.desc() if sort_desc else UnifiedVulnerability.cvss_v3_score.asc())
    else:
        query = query.order_by(UnifiedVulnerability.published_date.desc() if sort_desc else UnifiedVulnerability.published_date.asc())
    
    query = query.offset((page - 1) * page_size).limit(page_size)
    results = query.all()

    has_filters = any([q, type and type != "all", severity, cwe, affected_product, has_exploit is not None, cisa_kev is not None, published_after, published_before, cvss_min is not None, cvss_max is not None])

    if not has_filters:
        type_counts = db.query(
            UnifiedVulnerability.type,
            func.count(UnifiedVulnerability.id)
        ).group_by(UnifiedVulnerability.type).all()
        type_counts_dict = {t: c for t, c in type_counts}
    else:
        type_counts_dict = {}
    
    return {
        "data": [
            {
                "type": r.type,
                "id": r.vuln_id,
                "title": r.title,
                "title_zh": r.title_zh,
                "description": r.description[:200] + "..." if r.description and len(r.description) > 200 else r.description,
                "description_zh": r.description_zh[:200] + "..." if r.description_zh and len(r.description_zh) > 200 else r.description_zh,
                "severity": r.severity,
                "cvss_scores": r.cvss_scores,
                "cvss_v3_score": r.cvss_v3_score,
                "cvss_v3_severity": r.severity if r.type == "cve" or r.type == "cnvd" or r.type == "ghsa" else None,
                "cvss_v3_vector": r.cvss_v3_vector,
                "cvss_v4_score": r.cvss_v4_score,
                "cvss_v4_severity": None,
                "cvss_v4_vector": r.cvss_v4_vector,
                "epss_score": r.epss_score,
                "cisa_kev": r.cisa_kev,
                "fixes": r.fixes,
                "published_date": r.published_date,
                "modified_date": r.modified_date,
                "exploits_count": r.exploits_count or 0,
                "view_count": r.view_count or 0,
                "cwes": r.cwes,
                "related_cve_ids": r.related_cve_ids,
                "source": r.source or (r.data_sources[0] if r.data_sources and len(r.data_sources) > 0 else None)
            }
            for r in results
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
        "type_counts": type_counts_dict
    }


@router.get("/stats")
def get_unified_stats(db: Session = Depends(get_db)):
    """获取统一统计信息"""
    total = db.query(UnifiedVulnerability).count()
    
    type_counts = db.query(
        UnifiedVulnerability.type,
        func.count(UnifiedVulnerability.id)
    ).group_by(UnifiedVulnerability.type).all()
    
    severity_counts = db.query(
        UnifiedVulnerability.severity,
        func.count(UnifiedVulnerability.id)
    ).group_by(UnifiedVulnerability.severity).all()
    
    kev_count = db.query(UnifiedVulnerability).filter(UnifiedVulnerability.cisa_kev == True).count()
    
    avg_cvss = db.query(func.avg(UnifiedVulnerability.cvss_v3_score)).filter(UnifiedVulnerability.cvss_v3_score.isnot(None)).scalar()
    
    today = datetime.now().date()
    today_start = datetime.combine(today, datetime.min.time())
    thirty_days_ago = today - timedelta(days=30)
    
    today_published_count = db.query(UnifiedVulnerability).filter(
        UnifiedVulnerability.published_date >= today_start
    ).count()
    
    today_modified_count = db.query(UnifiedVulnerability).filter(
        UnifiedVulnerability.modified_date >= today_start
    ).count()
    
    recent_published_count = db.query(UnifiedVulnerability).filter(
        UnifiedVulnerability.published_date >= thirty_days_ago
    ).count()
    
    recent_modified_count = db.query(UnifiedVulnerability).filter(
        UnifiedVulnerability.modified_date >= thirty_days_ago
    ).count()
    
    return {
        "total": total,
        "type_distribution": {t: c for t, c in type_counts},
        "severity_distribution": {s: c for s, c in severity_counts},
        "cisa_kev_count": kev_count,
        "average_cvss_score": round(avg_cvss, 2) if avg_cvss else None,
        "today_published": today_published_count,
        "today_modified": today_modified_count,
        "recent_30_days_published": recent_published_count,
        "recent_30_days_modified": recent_modified_count
    }


@router.get("/top-viewed")
def get_top_viewed_vulnerabilities(
    limit: int = Query(10, ge=1, le=100, description="返回数量"),
    db: Session = Depends(get_db)
):
    """获取查看量最高的漏洞列表"""
    results = db.query(UnifiedVulnerability).filter(
        UnifiedVulnerability.view_count > 0
    ).order_by(
        UnifiedVulnerability.view_count.desc()
    ).limit(limit).all()

    vulnerabilities = []
    for v in results:
        vulnerabilities.append({
            "id": v.vuln_id,
            "type": v.type,
            "title": v.title or v.vuln_id,
            "severity": v.severity,
            "published_date": v.published_date.isoformat() if v.published_date else None,
            "source": v.source,
            "view_count": v.view_count or 0,
            "exploits_count": v.exploits_count or 0,
            "cvss_v3_score": v.cvss_v3_score
        })

    return vulnerabilities


@router.get("/{vuln_id}")
def get_vulnerability_detail(
    vuln_id: str,
    type: Optional[str] = Query(None, description="漏洞类型"),
    db: Session = Depends(get_db)
):
    """获取漏洞详情"""
    query = db.query(UnifiedVulnerability).filter(UnifiedVulnerability.vuln_id == vuln_id)
    
    if type:
        query = query.filter(UnifiedVulnerability.type == type.lower())
    
    result = query.first()
    
    if not result:
        return {"error": "Vulnerability not found"}
    
    return {
        "type": result.type,
        "id": result.vuln_id,
        "title": result.title,
        "title_zh": result.title_zh,
        "description": result.description,
        "description_zh": result.description_zh,
        "severity": result.severity,
        "cvss_v3_score": result.cvss_v3_score,
        "cvss_v3_severity": result.severity,
        "cvss_v3_vector": result.cvss_v3_vector,
        "cvss_v4_score": result.cvss_v4_score,
        "cvss_v4_severity": result.severity,
        "cvss_v4_vector": result.cvss_v4_vector,
        "epss_score": result.epss_score,
        "epss_percentile": result.epss_percentile,
        "cwes": result.cwes,
        "cisa_kev": result.cisa_kev,
        "cisa_kev_date_added": result.cisa_kev_date_added,
        "cisa_due_date": result.cisa_due_date,
        "cisa_required_action": result.cisa_required_action,
        "published_date": result.published_date,
        "modified_date": result.modified_date,
        "withdrawn_date": result.withdrawn_date,
        "aliases": result.aliases,
        "related": result.related,
        "affected": result.affected,
        "references": result.references,
        "source": result.source or (result.data_sources[0] if result.data_sources and len(result.data_sources) > 0 else None),
        "data_sources": result.data_sources,
        "tags": result.tags,
        "related_cve_ids": result.related_cve_ids,
        "exploits_count": result.exploits_count,
        "view_count": result.view_count,
        "created_at": result.created_at,
        "updated_at": result.updated_at
    }


@router.post("/{vuln_id}/view")
def increment_view_count(
    vuln_id: str,
    type: Optional[str] = Query(None, description="漏洞类型"),
    db: Session = Depends(get_db)
):
    """增加漏洞查看量"""
    query = db.query(UnifiedVulnerability).filter(UnifiedVulnerability.vuln_id == vuln_id)

    if type:
        query = query.filter(UnifiedVulnerability.type == type.lower())

    result = query.first()

    if not result:
        return {"error": "Vulnerability not found"}

    result.view_count = (result.view_count or 0) + 1
    db.commit()

    return {"vuln_id": vuln_id, "view_count": result.view_count}