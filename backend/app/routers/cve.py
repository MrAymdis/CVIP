from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, or_, and_
from typing import Optional, List
from app.database import get_db
from app.models import CVE, Exploit, Vendor, Product, Reference
from app.schemas import CVEResponse, CVEListResponse, ExploitResponse, ReferenceResponse

router = APIRouter(prefix="/cve", tags=["CVE"])


@router.get("", response_model=CVEListResponse)
@router.get("/", response_model=CVEListResponse)
def list_cves(
    q: Optional[str] = Query(None, description="Search query"),
    severity: Optional[str] = Query(None, description="Severity level (Critical/High/Medium/Low)"),
    vendor: Optional[str] = Query(None, description="Vendor name"),
    product: Optional[str] = Query(None, description="Product name"),
    ecosystem: Optional[str] = Query(None, description="Ecosystem (npm/pypi/maven/etc)"),
    cwe: Optional[str] = Query(None, description="CWE ID"),
    year: Optional[int] = Query(None, description="Published year"),
    min_cvss: Optional[float] = Query(None, ge=0, le=10, description="Min CVSS score"),
    max_cvss: Optional[float] = Query(None, ge=0, le=10, description="Max CVSS score"),
    min_epss: Optional[float] = Query(None, ge=0, le=1, description="Min EPSS score"),
    max_epss: Optional[float] = Query(None, ge=0, le=1, description="Max EPSS score"),
    cisa_kev: Optional[bool] = Query(None, description="CISA KEV only"),
    has_exploit: Optional[bool] = Query(None, description="Has exploit only"),
    sort_by: str = Query("published_date", description="Sort field"),
    sort_order: str = Query("desc", description="Sort order (asc/desc)"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    db: Session = Depends(get_db)
):
    """List CVEs with search and filter support."""
    # Start with just CVE table for performance
    query = db.query(CVE)
    
    # Only join when needed for filtering
    need_vendor_join = vendor is not None
    need_product_join = product is not None or ecosystem is not None
    
    if need_vendor_join and not need_product_join:
        query = query.outerjoin(Vendor)
    elif need_product_join:
        query = query.outerjoin(Vendor).outerjoin(Product)
    
    # Search - optimized for CVE ID exact match first
    if q:
        q_upper = q.upper()
        # If query looks like a CVE ID (CVE-YYYY-NNNNN), use exact match
        if q_upper.startswith('CVE-'):
            query = query.filter(CVE.cve_id.ilike(f"%{q}%"))
        else:
            # For other queries, search in title and description only
            search_filter = or_(
                CVE.cve_id.ilike(f"%{q}%"),
                CVE.title.ilike(f"%{q}%"),
                CVE.description.ilike(f"%{q}%"),
            )
            query = query.filter(search_filter)
    
    # Filters
    if severity:
        query = query.filter(
            or_(
                CVE.cvss_v3_severity == severity,
                CVE.cvss_v4_severity == severity
            )
        )
    
    if vendor and need_vendor_join:
        query = query.filter(Vendor.name.ilike(f"%{vendor}%"))
    
    if product and need_product_join:
        query = query.filter(Product.name.ilike(f"%{product}%"))
    
    if ecosystem and need_product_join:
        query = query.filter(Product.ecosystem == ecosystem)
    
    if cwe:
        query = query.filter(CVE.cwes.contains([cwe]))
    
    if year:
        query = query.filter(func.extract('year', CVE.published_date) == year)
    
    if min_cvss is not None:
        query = query.filter(
            or_(
                CVE.cvss_v3_score >= min_cvss,
                CVE.cvss_v4_score >= min_cvss
            )
        )
    
    if max_cvss is not None:
        query = query.filter(
            or_(
                CVE.cvss_v3_score <= max_cvss,
                CVE.cvss_v4_score <= max_cvss
            )
        )
    
    if min_epss is not None:
        query = query.filter(CVE.epss_score >= min_epss)
    
    if max_epss is not None:
        query = query.filter(CVE.epss_score <= max_epss)
    
    if cisa_kev is not None:
        query = query.filter(CVE.cisa_kev == cisa_kev)
    
    if has_exploit is not None:
        if has_exploit:
            query = query.filter(CVE.exploits_count > 0)
        else:
            query = query.filter(CVE.exploits_count == 0)
    
    # Sorting
    sort_field = getattr(CVE, sort_by, CVE.published_date)
    if sort_order.lower() == "desc":
        query = query.order_by(sort_field.desc())
    else:
        query = query.order_by(sort_field.asc())
    
    # Get items first
    items = query.offset((page - 1) * page_size).limit(page_size).all()
    
    # Determine total count
    if not items and page == 1:
        # No results on first page
        total = 0
    elif len(items) < page_size and page == 1:
        # We have all results on first page
        total = len(items)
    elif not need_vendor_join and not need_product_join and not q:
        # No filters, no search - use approximate count or skip count
        # For large datasets, skip count for better performance
        if page == 1:
            total = len(items) + 1 if len(items) == page_size else len(items)
        else:
            # For subsequent pages, estimate
            total = page * page_size
    else:
        # Only perform count when necessary and limit to first page
        try:
            if page == 1:
                # Count only for first page
                total = query.limit(10000).count()  # Cap at 10k to prevent timeouts
            else:
                # For subsequent pages, just estimate
                total = page * page_size
        except:
            # Fallback if count fails
            total = page * page_size
    
    # Format response - rejoin to get vendor and product names
    vendor_map = {}
    product_map = {}
    
    if items:
        # Fetch vendors and products separately for efficiency
        vendor_ids = [item.vendor_id for item in items if item.vendor_id]
        product_ids = [item.product_id for item in items if item.product_id]
        
        if vendor_ids:
            vendors = db.query(Vendor).filter(Vendor.id.in_(vendor_ids)).all()
            vendor_map = {v.id: v for v in vendors}
        
        if product_ids:
            products = db.query(Product).filter(Product.id.in_(product_ids)).all()
            product_map = {p.id: p for p in products}
    
    # Format response
    response_items = []
    for item in items:
        vendor = vendor_map.get(item.vendor_id)
        product = product_map.get(item.product_id)
        
        item_dict = {
            **item.__dict__,
            "vendor_name": vendor.name if vendor else None,
            "product_name": product.name if product else None,
        }
        response_items.append(item_dict)
    
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": response_items
    }


@router.get("/{cve_id}", response_model=CVEResponse)
def get_cve(cve_id: str, db: Session = Depends(get_db)):
    """Get CVE details by ID."""
    cve = db.query(CVE).filter(CVE.cve_id == cve_id.upper()).first()
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")
    
    result = {
        **cve.__dict__,
        "vendor_name": cve.vendor.name if cve.vendor else None,
        "product_name": cve.product.name if cve.product else None,
    }
    return result


@router.get("/{cve_id}/exploits", response_model=List[ExploitResponse])
def get_cve_exploits(cve_id: str, db: Session = Depends(get_db)):
    """Get exploits for a CVE."""
    cve = db.query(CVE).filter(CVE.cve_id == cve_id.upper()).first()
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")
    
    exploits = db.query(Exploit).filter(Exploit.cve_id == cve_id.upper()).all()
    return exploits


@router.get("/{cve_id}/references", response_model=List[ReferenceResponse])
def get_cve_references(cve_id: str, db: Session = Depends(get_db)):
    """Get references for a CVE."""
    cve = db.query(CVE).filter(CVE.cve_id == cve_id.upper()).first()
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")
    
    references = db.query(Reference).filter(Reference.cve_id == cve_id.upper()).all()
    return references
