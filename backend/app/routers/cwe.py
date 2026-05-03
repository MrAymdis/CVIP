"""
CWE API接口
支持CWE弱点数据的CRUD操作和搜索功能
"""
from fastapi import APIRouter, Query, HTTPException, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, or_
from datetime import datetime
from typing import Optional, List

from app.database import get_db
from app.models import CWE as CWEModel, CVE as CVEModel
from app.schemas import cwe as schemas

router = APIRouter()


@router.get("/", response_model=schemas.CWEListResponse)
def search_cwes(
    q: Optional[str] = Query(None, description="搜索关键词"),
    weakness_type: Optional[str] = Query(None, description="弱点类型筛选"),
    severity: Optional[str] = Query(None, description="严重程度筛选"),
    category: Optional[str] = Query(None, description="分类筛选"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """搜索CWE弱点列表"""
    query = db.query(CWEModel)

    if q:
        query = query.filter(
            or_(
                CWEModel.cwe_id.ilike(f"%{q}%"),
                CWEModel.name.ilike(f"%{q}%"),
                CWEModel.name_zh.ilike(f"%{q}%"),
                CWEModel.description.ilike(f"%{q}%")
            )
        )

    if weakness_type:
        query = query.filter(CWEModel.weakness_type == weakness_type)

    if severity:
        query = query.filter(CWEModel.base_severity == severity)

    if category:
        query = query.filter(CWEModel.cwe_category.ilike(f"%{category}%"))

    total = query.count()
    cwes = query.offset((page - 1) * page_size).limit(page_size).all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": cwes
    }


@router.get("/{cwe_id}", response_model=schemas.CWEResponse)
def get_cwe(cwe_id: str, db: Session = Depends(get_db)):
    """获取单个CWE弱点详情"""
    cwe = db.query(CWEModel).filter(CWEModel.cwe_id == cwe_id).first()
    
    if not cwe:
        raise HTTPException(status_code=404, detail="CWE not found")

    return cwe


@router.post("/", response_model=schemas.CWEResponse)
def create_cwe(
    cwe_data: schemas.CWECreate,
    db: Session = Depends(get_db)
):
    """创建新CWE弱点"""
    existing = db.query(CWEModel).filter(CWEModel.cwe_id == cwe_data.cwe_id).first()
    if existing:
        raise HTTPException(status_code=400, detail="CWE already exists")

    cwe = CWEModel(
        cwe_id=cwe_data.cwe_id,
        name=cwe_data.name,
        name_zh=cwe_data.name_zh,
        description=cwe_data.description,
        description_zh=cwe_data.description_zh,
        weakness_type=cwe_data.weakness_type,
        status=cwe_data.status,
        attack_vector=cwe_data.attack_vector,
        attack_complexity=cwe_data.attack_complexity,
        privileges_required=cwe_data.privileges_required,
        user_interaction=cwe_data.user_interaction,
        scope=cwe_data.scope,
        confidentiality_impact=cwe_data.confidentiality_impact,
        integrity_impact=cwe_data.integrity_impact,
        availability_impact=cwe_data.availability_impact,
        base_score=cwe_data.base_score,
        base_severity=cwe_data.base_severity,
        likelihood_of_exploit=cwe_data.likelihood_of_exploit,
        detection_difficulty=cwe_data.detection_difficulty,
        mitigation=cwe_data.mitigation,
        mitigation_zh=cwe_data.mitigation_zh,
        related_weaknesses=cwe_data.related_weaknesses,
        parent_weaknesses=cwe_data.parent_weaknesses,
        child_weaknesses=cwe_data.child_weaknesses,
        taxonomy_mappings=cwe_data.taxonomy_mappings,
        references=cwe_data.references,
        cve_count=cwe_data.cve_count,
        cwe_category=cwe_data.cwe_category,
        cwe_subcategory=cwe_data.cwe_subcategory
    )

    db.add(cwe)
    db.commit()
    db.refresh(cwe)

    return cwe


@router.put("/{cwe_id}", response_model=schemas.CWEResponse)
def update_cwe(
    cwe_id: str,
    cwe_data: schemas.CWEUpdate,
    db: Session = Depends(get_db)
):
    """更新CWE弱点信息"""
    cwe = db.query(CWEModel).filter(CWEModel.cwe_id == cwe_id).first()
    
    if not cwe:
        raise HTTPException(status_code=404, detail="CWE not found")

    update_data = cwe_data.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(cwe, key, value)

    cwe.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(cwe)

    return cwe


@router.delete("/{cwe_id}")
def delete_cwe(cwe_id: str, db: Session = Depends(get_db)):
    """删除CWE弱点"""
    cwe = db.query(CWEModel).filter(CWEModel.cwe_id == cwe_id).first()
    
    if not cwe:
        raise HTTPException(status_code=404, detail="CWE not found")

    db.delete(cwe)
    db.commit()

    return {"message": "CWE deleted successfully"}


@router.get("/{cwe_id}/cves", response_model=schemas.CWECVEResponse)
def get_cwe_cves(
    cwe_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """获取CWE关联的CVE列表"""
    cwe = db.query(CWEModel).filter(CWEModel.cwe_id == cwe_id).first()
    
    if not cwe:
        raise HTTPException(status_code=404, detail="CWE not found")

    query = db.query(CVEModel).filter(CVEModel.cwes.any(cwe_id))
    total = query.count()
    cves = query.offset((page - 1) * page_size).limit(page_size).all()

    return {
        "total": total,
        "cwe_id": cwe_id,
        "cwe_name": cwe.name,
        "items": cves
    }


@router.post("/batch", response_model=schemas.CWEBatchResponse)
def batch_create_cwes(
    batch_data: schemas.CWEBatchCreate,
    db: Session = Depends(get_db)
):
    """批量创建CWE弱点"""
    success_count = 0
    failed_count = 0
    failed_items = []

    for item in batch_data.items:
        try:
            existing = db.query(CWEModel).filter(CWEModel.cwe_id == item.cwe_id).first()
            if existing:
                failed_count += 1
                failed_items.append({"cwe_id": item.cwe_id, "reason": "CWE already exists"})
                continue
            
            cwe = CWEModel(
                cwe_id=item.cwe_id,
                name=item.name,
                name_zh=item.name_zh,
                description=item.description,
                description_zh=item.description_zh,
                weakness_type=item.weakness_type,
                status=item.status,
                attack_vector=item.attack_vector,
                attack_complexity=item.attack_complexity,
                privileges_required=item.privileges_required,
                user_interaction=item.user_interaction,
                scope=item.scope,
                confidentiality_impact=item.confidentiality_impact,
                integrity_impact=item.integrity_impact,
                availability_impact=item.availability_impact,
                base_score=item.base_score,
                base_severity=item.base_severity,
                likelihood_of_exploit=item.likelihood_of_exploit,
                detection_difficulty=item.detection_difficulty,
                mitigation=item.mitigation,
                mitigation_zh=item.mitigation_zh,
                related_weaknesses=item.related_weaknesses,
                parent_weaknesses=item.parent_weaknesses,
                child_weaknesses=item.child_weaknesses,
                taxonomy_mappings=item.taxonomy_mappings,
                references=item.references,
                cve_count=item.cve_count,
                cwe_category=item.cwe_category,
                cwe_subcategory=item.cwe_subcategory
            )
            db.add(cwe)
            success_count += 1
        except Exception as e:
            failed_count += 1
            failed_items.append({"cwe_id": item.cwe_id, "reason": str(e)})
            db.rollback()
    
    db.commit()

    return {
        "success_count": success_count,
        "failed_count": failed_count,
        "failed_items": failed_items
    }


@router.get("/categories/list")
def list_categories(db: Session = Depends(get_db)):
    """获取所有CWE分类列表"""
    categories = db.query(CWEModel.cwe_category, func.count(CWEModel.id)) \
                  .filter(CWEModel.cwe_category.isnot(None)) \
                  .group_by(CWEModel.cwe_category) \
                  .order_by(func.count(CWEModel.id).desc()) \
                  .all()

    return [{"category": cat, "count": count} for cat, count in categories]


@router.get("/severity/list")
def list_severity(db: Session = Depends(get_db)):
    """获取所有严重程度统计"""
    severities = db.query(CWEModel.base_severity, func.count(CWEModel.id)) \
                   .filter(CWEModel.base_severity.isnot(None)) \
                   .group_by(CWEModel.base_severity) \
                   .order_by(func.count(CWEModel.id).desc()) \
                   .all()

    return [{"severity": severity, "count": count} for severity, count in severities]
