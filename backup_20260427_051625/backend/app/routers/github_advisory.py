"""
GitHub Advisory漏洞API接口
支持GitHub Advisory漏洞的查询、搜索和统计功能
"""
from fastapi import APIRouter, Query, HTTPException, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, or_
from typing import Optional, List
import json

from app.database import get_db
from app.models import GitHubAdvisory
from app.schemas.github_advisory import (
    GitHubAdvisoryResponse,
    GitHubAdvisoryListResponse,
    GitHubAdvisoryStatsResponse,
)

router = APIRouter(tags=["GitHub Advisory"])


@router.get("/", response_model=GitHubAdvisoryListResponse)
def search_advisories(
    q: Optional[str] = Query(None, description="搜索关键词"),
    severity: Optional[str] = Query(None, description="严重程度筛选 (critical, high, medium, low)"),
    ecosystem: Optional[str] = Query(None, description="生态系统筛选 (npm, pip, go, maven等)"),
    has_cve: Optional[bool] = Query(None, description="是否关联CVE"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """搜索GitHub Advisory漏洞"""
    query = db.query(GitHubAdvisory)

    if q:
        query = query.filter(
            or_(
                GitHubAdvisory.ghsa_id.ilike(f"%{q}%"),
                GitHubAdvisory.cve_id.ilike(f"%{q}%"),
                GitHubAdvisory.summary.ilike(f"%{q}%"),
                GitHubAdvisory.description.ilike(f"%{q}%"),
            )
        )

    if severity:
        query = query.filter(GitHubAdvisory.severity == severity.lower())

    if ecosystem:
        query = query.filter(
            GitHubAdvisory.affected_packages.ilike(f"%{ecosystem.lower()}%")
        )

    if has_cve is not None:
        if has_cve:
            query = query.filter(GitHubAdvisory.cve_id.isnot(None))
        else:
            query = query.filter(GitHubAdvisory.cve_id.is_(None))

    total = query.count()

    vulnerabilities = query.order_by(GitHubAdvisory.published_at.desc()).offset(
        (page - 1) * page_size
    ).limit(page_size).all()

    return {
        "data": vulnerabilities,
        "total": total,
        "page": page,
        "page_size": page_size
    }


@router.get("/{ghsa_id}", response_model=GitHubAdvisoryResponse)
def get_advisory(ghsa_id: str, db: Session = Depends(get_db)):
    """获取单个GitHub Advisory漏洞详情"""
    advisory = db.query(GitHubAdvisory).filter(GitHubAdvisory.ghsa_id == ghsa_id).first()
    
    if not advisory:
        raise HTTPException(status_code=404, detail="GitHub Advisory not found")

    return advisory


@router.get("/stats/overview", response_model=GitHubAdvisoryStatsResponse)
def get_advisory_stats(db: Session = Depends(get_db)):
    """获取GitHub Advisory统计概览"""
    total_count = db.query(GitHubAdvisory).count()
    
    critical_count = db.query(GitHubAdvisory).filter(
        GitHubAdvisory.severity == "critical"
    ).count()
    
    high_count = db.query(GitHubAdvisory).filter(
        GitHubAdvisory.severity == "high"
    ).count()
    
    medium_count = db.query(GitHubAdvisory).filter(
        GitHubAdvisory.severity == "medium"
    ).count()
    
    low_count = db.query(GitHubAdvisory).filter(
        GitHubAdvisory.severity == "low"
    ).count()
    
    avg_cvss = db.query(func.avg(GitHubAdvisory.cvss_score)).filter(
        GitHubAdvisory.cvss_score.isnot(None)
    ).scalar()
    
    with_cve_count = db.query(GitHubAdvisory).filter(
        GitHubAdvisory.cve_id.isnot(None)
    ).count()
    
    without_cve_count = db.query(GitHubAdvisory).filter(
        GitHubAdvisory.cve_id.is_(None)
    ).count()

    return {
        "total_count": total_count,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "avg_cvss_score": round(avg_cvss, 2) if avg_cvss else None,
        "with_cve_count": with_cve_count,
        "without_cve_count": without_cve_count,
    }


@router.get("/stats/severity-distribution")
def get_severity_distribution(db: Session = Depends(get_db)):
    """获取严重程度分布统计"""
    result = db.query(
        GitHubAdvisory.severity,
        func.count(GitHubAdvisory.id).label("count")
    ).group_by(GitHubAdvisory.severity).all()

    distribution = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "unknown": 0
    }

    for severity, count in result:
        if severity in distribution:
            distribution[severity] = count
        else:
            distribution["unknown"] += count

    return distribution


@router.get("/stats/ecosystem-distribution")
def get_ecosystem_distribution(db: Session = Depends(get_db)):
    """获取生态系统分布统计"""
    advisories = db.query(GitHubAdvisory.affected_packages).all()
    
    ecosystem_counts = {}
    
    for (packages_json,) in advisories:
        if packages_json:
            try:
                packages = json.loads(packages_json) if isinstance(packages_json, str) else packages_json
                for pkg in packages:
                    ecosystem = pkg.get("ecosystem")
                    if ecosystem:
                        ecosystem_counts[ecosystem] = ecosystem_counts.get(ecosystem, 0) + 1
            except Exception:
                continue
    
    sorted_ecosystems = sorted(ecosystem_counts.items(), key=lambda x: x[1], reverse=True)
    return dict(sorted_ecosystems[:10])


@router.get("/cve/{cve_id}")
def get_advisories_by_cve(cve_id: str, db: Session = Depends(get_db)):
    """根据CVE ID查询关联的GitHub Advisory"""
    advisories = db.query(GitHubAdvisory).filter(
        GitHubAdvisory.cve_id == cve_id
    ).all()
    
    if not advisories:
        raise HTTPException(status_code=404, detail="No GitHub Advisory found for this CVE")

    return {"data": advisories, "total": len(advisories)}


@router.get("/recent")
def get_recent_advisories(
    limit: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """获取最近更新的漏洞"""
    advisories = db.query(GitHubAdvisory).order_by(
        GitHubAdvisory.published_at.desc()
    ).limit(limit).all()

    return {"data": advisories, "total": len(advisories)}