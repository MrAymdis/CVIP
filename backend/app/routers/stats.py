from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, extract
from datetime import datetime, timedelta
from app.database import get_db
from app.models import CVE, Exploit, Vendor, CWE, GitHubAdvisory, CNVDVulnerability, OSVVulnerability
from app.schemas import StatsResponse, StatsOverview, TrendData, VendorRank, CWERank

router = APIRouter(prefix="/stats", tags=["Stats"])


@router.get("/overview", response_model=StatsOverview)
def get_overview(db: Session = Depends(get_db)):
    """Get platform statistics overview."""
    total_cves = db.query(CVE).count()
    total_cnvd = db.query(CNVDVulnerability).count()
    total_osv = db.query(OSVVulnerability).count()
    total_github_advisory = db.query(GitHubAdvisory).count()
    total_vulnerabilities = total_cves + total_cnvd + total_osv + total_github_advisory

    total_exploits = db.query(Exploit).count()
    total_vendors = db.query(Vendor).count()

    from app.models import Product
    total_products = db.query(Product).count()

    gh_critical_count = db.query(GitHubAdvisory).filter(
        GitHubAdvisory.severity == "critical"
    ).count()
    gh_high_count = db.query(GitHubAdvisory).filter(
        GitHubAdvisory.severity == "high"
    ).count()
    gh_medium_count = db.query(GitHubAdvisory).filter(
        GitHubAdvisory.severity == "medium"
    ).count()
    gh_low_count = db.query(GitHubAdvisory).filter(
        GitHubAdvisory.severity == "low"
    ).count()

    cnvd_critical_count = db.query(CNVDVulnerability).filter(
        CNVDVulnerability.severity == "critical"
    ).count()
    cnvd_high_count = db.query(CNVDVulnerability).filter(
        CNVDVulnerability.severity == "high"
    ).count()

    current_year = datetime.now().year
    cves_this_year = db.query(CVE).filter(
        extract('year', CVE.published_date) == current_year
    ).count()

    exploits_this_year = db.query(Exploit).filter(
        extract('year', Exploit.published_date) == current_year
    ).count()

    cisa_kev_count = db.query(CVE).filter(CVE.cisa_kev == True).count()

    cve_high_count = db.query(CVE).filter(
        (CVE.cvss_v3_score >= 7.0) | (CVE.cvss_v4_score >= 7.0)
    ).count()

    critical_count = gh_critical_count + cnvd_critical_count + cve_high_count

    return StatsOverview(
        total_cves=total_vulnerabilities,
        total_exploits=total_exploits,
        total_vendors=total_vendors,
        total_products=total_products,
        total_github_advisory=total_github_advisory,
        cves_this_year=cves_this_year,
        exploits_this_year=exploits_this_year,
        cisa_kev_count=cisa_kev_count,
        high_severity_count=critical_count,
        github_advisory_critical_count=gh_critical_count,
        github_advisory_high_count=gh_high_count,
        github_advisory_medium_count=gh_medium_count,
        github_advisory_low_count=gh_low_count
    )


@router.get("/trends")
def get_trends(months: int = 12, db: Session = Depends(get_db)):
    """Get CVE trends over time."""
    end_date = datetime.now()
    start_date = end_date - timedelta(days=30 * months)
    
    # Monthly CVE counts
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
        # Count exploited CVEs for this vendor
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
def get_top_cwes(limit: int = 10, db: Session = Depends(get_db)):
    """Get top CWEs by CVE count."""
    # Get all CVEs and count CWE occurrences
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
        # Get CWE name if available
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
