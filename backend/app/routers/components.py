"""
组件信息 API 路由
参考深信服安全平台组件信息页面设计
支持按分类、厂商、名称搜索
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from app.database import get_db
from app.models import Component, COMPONENT_CATEGORIES
from app.services.component_parser import sync_components_from_vulnerabilities

router = APIRouter(prefix="/components", tags=["组件信息"])

@router.get("/categories", summary="获取所有组件分类")
def get_categories(db: Session = Depends(get_db)):
    """获取所有组件分类及其数量"""
    categories = []

    for category in COMPONENT_CATEGORIES:
        count = db.query(Component).filter(Component.category == category).count()
        categories.append({
            "name": category,
            "count": count
        })

    return {"categories": categories}


@router.get("/list", summary="查询组件列表")
def search_components(
    keyword: Optional[str] = Query(None, description="组件名称或厂商关键词"),
    category: Optional[str] = Query(None, description="组件分类"),
    vendor: Optional[str] = Query(None, description="厂商名称"),
    page: int = Query(1, ge=1, description="页码"),
    page_size: int = Query(20, ge=1, le=100, description="每页数量"),
    db: Session = Depends(get_db)
):
    """查询组件列表，支持按分类、厂商、名称搜索"""

    query = db.query(Component)

    if category:
        if category not in COMPONENT_CATEGORIES:
            raise HTTPException(status_code=400, detail=f"无效的分类: {category}")
        query = query.filter(Component.category == category)

    if vendor:
        query = query.filter(Component.vendor_name.ilike(f"%{vendor}%"))

    if keyword:
        query = query.filter(
            (Component.name.ilike(f"%{keyword}%")) |
            (Component.vendor_name.ilike(f"%{keyword}%"))
        )

    total = query.count()
    components = query.offset((page - 1) * page_size).limit(page_size).all()

    result = []
    for comp in components:
        result.append({
            "id": comp.id,
            "name": comp.name,
            "component_id": comp.component_id,
            "vendor_name": comp.vendor_name,
            "category": comp.category,
            "product_version": comp.product_version,
            "ecosystem": comp.ecosystem,
            "recognition_support": comp.recognition_support,
            "vuln_count": len(comp.related_vuln_ids) if comp.related_vuln_ids else 0
        })

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "data": result
    }


@router.get("/{component_id}", summary="获取组件详情")
def get_component_detail(component_id: str, db: Session = Depends(get_db)):
    """获取组件详细信息，包括关联的漏洞列表"""

    component = db.query(Component).filter(Component.component_id == component_id).first()

    if not component:
        raise HTTPException(status_code=404, detail="组件不存在")

    return {
        "id": component.id,
        "name": component.name,
        "name_en": component.name_en,
        "component_id": component.component_id,
        "vendor_name": component.vendor_name,
        "vendor_name_en": component.vendor_name_en,
        "vendor_country": component.vendor_country,
        "category": component.category,
        "sub_category": component.sub_category,
        "product_name": component.product_name,
        "product_version": component.product_version,
        "version_range": component.version_range,
        "ecosystem": component.ecosystem,
        "affected_versions": component.affected_versions,
        "recognition_support": component.recognition_support,
        "data_source": component.data_source,
        "source_url": component.source_url,
        "related_vuln_ids": component.related_vuln_ids,
        "vuln_count": len(component.related_vuln_ids) if component.related_vuln_ids else 0,
        "description": component.description,
        "created_at": component.created_at,
        "updated_at": component.updated_at
    }


@router.post("/sync", summary="同步组件数据")
def sync_components(
    limit: Optional[int] = Query(10000, description="同步漏洞数量限制"),
    db: Session = Depends(get_db)
):
    """从漏洞数据同步组件信息"""

    try:
        added, updated = sync_components_from_vulnerabilities(db, limit=limit)
        return {
            "status": "success",
            "message": f"组件同步完成",
            "added": added,
            "updated": updated
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"同步失败: {str(e)}")


@router.get("/stats", summary="获取组件统计信息")
def get_component_stats(db: Session = Depends(get_db)):
    """获取组件统计信息"""

    total = db.query(Component).count()

    category_stats = []
    for category in COMPONENT_CATEGORIES:
        count = db.query(Component).filter(Component.category == category).count()
        if count > 0:
            category_stats.append({
                "category": category,
                "count": count
            })

    vendor_stats = db.query(
        Component.vendor_name,
        Component.vendor_name,
        db.query(Component).filter(Component.vendor_name == Component.vendor_name).count().label('count')
    ).filter(Component.vendor_name.isnot(None)).group_by(Component.vendor_name).order_by(db.text('count DESC')).limit(20).all()

    vendor_top = []
    for v in vendor_stats:
        if v[0]:
            vendor_top.append({
                "vendor_name": v[0],
                "count": v[1]
            })

    return {
        "total": total,
        "categories": category_stats,
        "top_vendors": vendor_top
    }
