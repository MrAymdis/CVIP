"""
OSV漏洞API接口
支持OSV漏洞的查询和详情查看功能
"""
from fastapi import APIRouter, Query, HTTPException, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, or_
from typing import Optional

from app.database import get_db
from app.models import OSVVulnerability

router = APIRouter()


@router.get("/")
def search_osv(
    q: Optional[str] = Query(None, description="搜索关键词"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """搜索OSV漏洞"""
    query = db.query(OSVVulnerability)

    if q:
        query = query.filter(
            or_(
                OSVVulnerability.osv_id.ilike(f"%{q}%"),
                OSVVulnerability.summary.ilike(f"%{q}%"),
                OSVVulnerability.details.ilike(f"%{q}%")
            )
        )

    # 总数
    total = query.count()

    # 分页
    vulnerabilities = query.offset((page - 1) * page_size).limit(page_size).all()

    return {
        "data": vulnerabilities,
        "total": total,
        "page": page,
        "page_size": page_size
    }


@router.get("/{osv_id}")
def get_osv(osv_id: str, db: Session = Depends(get_db)):
    """获取单个OSV漏洞详情"""
    vulnerability = db.query(OSVVulnerability).filter(OSVVulnerability.osv_id == osv_id).first()
    
    if not vulnerability:
        raise HTTPException(status_code=404, detail="OSV vulnerability not found")

    return vulnerability


@router.get("/stats/count")
def get_osv_count(db: Session = Depends(get_db)):
    """获取OSV漏洞总数"""
    count = db.query(OSVVulnerability).count()
    return {"count": count}