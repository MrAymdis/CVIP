from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, extract, case, and_
from datetime import datetime, timedelta, date
from app.database import get_db
from app.models import CVE, Exploit, Vendor, CWE, GitHubAdvisory, CNVDVulnerability, OSVVulnerability, UnifiedVulnerability
from app.schemas import StatsResponse, StatsOverview, TrendData, VendorRank, CWERank
from app.cache import cache_sync_result

router = APIRouter(prefix="/stats", tags=["Stats"])


@router.get("/overview", response_model=StatsOverview)
@cache_sync_result(ttl=1800, key_prefix="stats")  # 缓存30分钟
def get_overview(db: Session = Depends(get_db)):
    """Get platform statistics overview."""
    today = datetime.utcnow().date()
    current_year = datetime.utcnow().year
    thirty_days_ago = today - timedelta(days=30)
    one_year_ago = today - timedelta(days=365)
    
    try:
        result = db.query(
            func.count(UnifiedVulnerability.id).label('total_vulns'),
            func.count(case((UnifiedVulnerability.exploits_count > 0, 1))).label('total_exploits'),
            func.count(case((UnifiedVulnerability.severity.in_(['CRITICAL', 'HIGH']), 1))).label('high_severity_count'),
            func.count(case((UnifiedVulnerability.cisa_kev == True, 1))).label('cisa_kev_count'),
            func.count(case((func.date_part('year', UnifiedVulnerability.published_date) == current_year, 1))).label('cves_this_year'),
            func.count(case((and_(UnifiedVulnerability.exploits_count > 0, UnifiedVulnerability.published_date >= one_year_ago), 1))).label('exploits_this_year'),
            func.count(case((func.date(UnifiedVulnerability.published_date) == today, 1))).label('published_today'),
            func.count(case((func.date(UnifiedVulnerability.modified_date) == today, 1))).label('updated_today'),
        ).first()
        
        return StatsOverview(
            total_vulns=result.total_vulns or 0,
            total_exploits=result.total_exploits or 0,
            total_vendors=0,
            total_products=0,
            total_github_advisory=0,
            cves_this_year=result.cves_this_year or 0,
            exploits_this_year=result.exploits_this_year or 0,
            cisa_kev_count=result.cisa_kev_count or 0,
            high_severity_count=result.high_severity_count or 0,
            published_today=result.published_today or 0,
            updated_today=result.updated_today or 0
        )
    except Exception as e:
        print(f"Error in get_overview: {e}")
        return StatsOverview(
            total_vulns=0,
            total_exploits=0,
            total_vendors=0,
            total_products=0,
            total_github_advisory=0,
            cves_this_year=0,
            exploits_this_year=0,
            cisa_kev_count=0,
            high_severity_count=0,
            published_today=0,
            updated_today=0
        )


@router.get("/trends")
@cache_sync_result(ttl=3600, key_prefix="stats")  # 缓存1小时
def get_trends(months: int = 12, db: Session = Depends(get_db)):
    """Get CVE trends over time."""
    end_date = datetime.now()
    start_date = end_date - timedelta(days=30 * months)
    
    results = db.query(
        func.date_trunc('month', CVE.published_date).label('month'),
        func.count(CVE.id).label('count')
    ).filter(
        CVE.published_date >= start_date
    ).group_by(
        func.date_trunc('month', CVE.published_date)
    ).order_by('month').all()
    
    trends = []
    for row in results:
        trends.append(TrendData(
            date=row.month.strftime("%Y-%m"),
            count=row.count
        ))
    
    return trends


@router.get("/vendors")
@cache_sync_result(ttl=3600, key_prefix="stats")  # 缓存1小时
def get_top_vendors(limit: int = 10, db: Session = Depends(get_db)):
    """Get top vendors by CVE count."""
    results = db.query(
        Vendor.name,
        func.count(CVE.id).label('cve_count')
    ).join(CVE).group_by(
        Vendor.name
    ).order_by(
        func.count(CVE.id).desc()
    ).limit(limit).all()
    
    vendors = []
    for row in results:
        exploited_count = db.query(CVE).join(Vendor).filter(
            Vendor.name == row.name,
            CVE.exploits_count > 0
        ).count()
        
        vendors.append(VendorRank(
            name=row.name,
            cve_count=row.cve_count,
            exploited_count=exploited_count
        ))
    
    return vendors


@router.get("/cwes")
@cache_sync_result(ttl=3600, key_prefix="stats")  # 缓存1小时
def get_top_cwes(limit: int = 10, db: Session = Depends(get_db)):
    """Get top CWEs by CVE count."""
    from sqlalchemy import text
    
    result = db.execute(text("""
        SELECT unnest(cwes) as cwe_id, count(*) as cve_count
        FROM cves
        WHERE cwes IS NOT NULL
        GROUP BY cwe_id
        ORDER BY cve_count DESC
        LIMIT :limit
    """), {"limit": limit})
    
    cwes = []
    for row in result:
        cwe_record = db.query(CWE).filter(CWE.cwe_id == row.cwe_id).first()
        name = cwe_record.name if cwe_record else None
        
        cwes.append(CWERank(
            cwe_id=row.cwe_id,
            name=name,
            cve_count=row.cve_count
        ))
    
    return cwes


@router.get("/all", response_model=StatsResponse)
def get_all_stats(db: Session = Depends(get_db)):
    """Get all statistics in one request."""
    return StatsResponse(
        overview=get_overview(db),
        monthly_trends=get_trends(db=db),
        top_vendors=get_top_vendors(db=db),
        top_cwes=get_top_cwes(db=db)
    )
