"""
统一漏洞数据写入辅助函数
用于将各种数据源的漏洞同步到 unified_vulnerability 表
"""
import json
from datetime import datetime
from typing import Dict, Optional
from sqlalchemy.orm import Session
from app.models import UnifiedVulnerability


def normalize_severity(severity: Optional[str]) -> Optional[str]:
    """
    标准化 severity 字段
    
    Args:
        severity: 原始严重程度
        
    Returns:
        标准化后的严重程度（大写）或 None
    """
    if not severity:
        return None
    
    severity = severity.upper().strip()
    
    if not severity or severity in ['NONE', 'UNKNOWN', '']:
        return None
    
    # 处理常见的拼写和缩写
    if severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'MODERATE']:
        return severity
    if severity.startswith('CRIT'):
        return 'CRITICAL'
    if severity.startswith('MED'):
        return 'MEDIUM'
    if severity.startswith('HIGH'):
        return 'HIGH'
    if severity.startswith('LOW'):
        return 'LOW'
    if 'MODERATE' in severity:
        return 'MEDIUM'
    
    return severity


def save_to_unified(db: Session, vuln_data: Dict, source_type: str) -> bool:
    """
    将漏洞数据保存到 unified_vulnerability 表

    Args:
        db: 数据库会话
        vuln_data: 漏洞数据字典
        source_type: 数据源类型 ('ghsa', 'osv', 'cve', 'cnvd')

    Returns:
        bool: 保存是否成功
    """
    try:
        vuln_id = vuln_data.get("vuln_id")
        if not vuln_id:
            return False

        existing = db.query(UnifiedVulnerability).filter(
            UnifiedVulnerability.vuln_id == vuln_id,
            UnifiedVulnerability.type == source_type
        ).first()

        unified_data = {
            "vuln_id": vuln_id,
            "type": source_type,
            "title": vuln_data.get("title"),
            "title_zh": vuln_data.get("title_zh"),
            "description": vuln_data.get("description"),
            "description_zh": vuln_data.get("description_zh"),
            "severity": normalize_severity(vuln_data.get("severity")),
            "cvss_scores": vuln_data.get("cvss_scores"),
            "cvss_v3_score": vuln_data.get("cvss_v3_score"),
            "cvss_v3_vector": vuln_data.get("cvss_v3_vector"),
            "cvss_v4_score": vuln_data.get("cvss_v4_score"),
            "cvss_v4_vector": vuln_data.get("cvss_v4_vector"),
            "epss_score": vuln_data.get("epss_score"),
            "epss_percentile": vuln_data.get("epss_percentile"),
            "cwes": vuln_data.get("cwes"),
            "cisa_kev": vuln_data.get("cisa_kev"),
            "cisa_kev_date_added": vuln_data.get("cisa_kev_date_added"),
            "cisa_due_date": vuln_data.get("cisa_due_date"),
            "cisa_required_action": vuln_data.get("cisa_required_action"),
            "published_date": vuln_data.get("published_date"),
            "modified_date": vuln_data.get("modified_date"),
            "withdrawn_date": vuln_data.get("withdrawn_date"),
            "aliases": vuln_data.get("aliases"),
            "related": vuln_data.get("related"),
            "affected": vuln_data.get("affected"),
            "references": vuln_data.get("references"),
            "fixes": vuln_data.get("fixes"),
            "source": vuln_data.get("source"),
            "data_sources": vuln_data.get("data_sources"),
            "tags": vuln_data.get("tags"),
            "related_cve_ids": vuln_data.get("related_cve_ids"),
            "exploits_count": vuln_data.get("exploits_count", 0),
            "view_count": vuln_data.get("view_count", 0),
            "original_data": vuln_data.get("original_data"),
        }

        if existing:
            for key, value in unified_data.items():
                if key != "vuln_id" and key != "type":
                    setattr(existing, key, value)
        else:
            vuln = UnifiedVulnerability(**unified_data)
            db.add(vuln)

        db.commit()
        return True

    except Exception as e:
        print(f"Error saving {source_type}:{vuln_id} to unified table: {e}")
        db.rollback()
        return False


def ghsa_to_unified_format(ghsa_data: Dict) -> Dict:
    """将GitHub Advisory数据转换为统一格式"""
    related_cve_ids = []
    if ghsa_data.get("cve_id"):
        related_cve_ids.append(ghsa_data["cve_id"])

    cvss_scores = []
    if ghsa_data.get("cvss_score") is not None:
        cvss_scores.append({
            "version": "3.1",
            "score": ghsa_data["cvss_score"],
            "severity": ghsa_data["severity"],
            "vector": ghsa_data["cvss_vector"]
        })

    return {
        "vuln_id": ghsa_data["ghsa_id"],
        "type": "ghsa",
        "title": ghsa_data.get("summary"),
        "title_zh": None,
        "description": ghsa_data.get("description"),
        "description_zh": None,
        "severity": normalize_severity(ghsa_data.get("severity")),
        "cvss_scores": cvss_scores if cvss_scores else None,
        "cvss_v3_score": ghsa_data.get("cvss_score"),
        "cvss_v3_vector": ghsa_data.get("cvss_vector"),
        "cvss_v4_score": None,
        "cvss_v4_vector": None,
        "epss_score": None,
        "epss_percentile": None,
        "cwes": ghsa_data.get("cwe_ids"),
        "cisa_kev": None,
        "cisa_kev_date_added": None,
        "cisa_due_date": None,
        "cisa_required_action": None,
        "published_date": ghsa_data.get("published_at"),
        "modified_date": ghsa_data.get("updated_at"),
        "withdrawn_date": ghsa_data.get("withdrawn_at"),
        "aliases": ghsa_data.get("aliases"),
        "related": None,
        "affected": ghsa_data.get("affected_packages"),
        "references": ghsa_data.get("references"),
        "fixes": ghsa_data.get("patched_versions"),
        "source": None,
        "data_sources": ghsa_data.get("data_sources"),
        "tags": None,
        "related_cve_ids": related_cve_ids if related_cve_ids else None,
        "exploits_count": 0,
        "view_count": 0,
        "original_data": json.dumps(ghsa_data, default=str),
    }


def osv_to_unified_format(osv_data: Dict) -> Dict:
    """将OSV数据转换为统一格式"""
    severity_info = osv_data.get("severity") or []
    cvss_scores = []
    primary_severity = None
    primary_cvss_v3_score = None
    primary_cvss_v3_vector = None

    for sev in severity_info:
        if isinstance(sev, dict):
            version = sev.get("type", "").replace("CVSS_V", "3.")
            score = sev.get("score")
            vector = sev.get("vector")

            if score is not None and isinstance(score, str):
                try:
                    score = float(score)
                except (ValueError, TypeError):
                    score = None

            severity_label = None
            if score is not None and isinstance(score, (int, float)):
                if score >= 9.0:
                    severity_label = "CRITICAL"
                elif score >= 7.0:
                    severity_label = "HIGH"
                elif score >= 4.0:
                    severity_label = "MEDIUM"
                elif score >= 0.1:
                    severity_label = "LOW"
                else:
                    severity_label = "NONE"

            cvss_scores.append({
                "version": version,
                "score": score,
                "severity": severity_label,
                "vector": vector
            })

            if sev.get("type") == "CVSS_V3":
                primary_severity = severity_label
                primary_cvss_v3_score = score
                primary_cvss_v3_vector = vector

    # 提取相关的 CVE 和 GHSA ID
    related_cve_ids = []
    # 从 upstream、aliases、related 三个字段提取
    for field in ["upstream", "aliases", "related"]:
        values = osv_data.get(field)
        if values and isinstance(values, list):
            for v in values:
                if v and isinstance(v, str):
                    # 只添加看起来像 CVE 或 GHSA 的 ID
                    if v.startswith("CVE-") or v.startswith("GHSA-"):
                        if v not in related_cve_ids:
                            related_cve_ids.append(v)

    return {
        "vuln_id": osv_data["osv_id"],
        "type": "osv",
        "title": osv_data.get("summary"),
        "title_zh": None,
        "description": osv_data.get("details"),
        "description_zh": None,
        "severity": primary_severity,
        "cvss_scores": cvss_scores if cvss_scores else None,
        "cvss_v3_score": primary_cvss_v3_score,
        "cvss_v3_vector": primary_cvss_v3_vector,
        "cvss_v4_score": None,
        "cvss_v4_vector": None,
        "epss_score": None,
        "epss_percentile": None,
        "cwes": None,
        "cisa_kev": None,
        "cisa_kev_date_added": None,
        "cisa_due_date": None,
        "cisa_required_action": None,
        "published_date": osv_data.get("published"),
        "modified_date": osv_data.get("modified"),
        "withdrawn_date": osv_data.get("withdrawn"),
        "aliases": osv_data.get("aliases"),
        "related": osv_data.get("related"),
        "affected": osv_data.get("affected"),
        "references": osv_data.get("references"),
        "fixes": None,
        "source": None,
        "data_sources": ["osv"],
        "tags": None,
        "related_cve_ids": related_cve_ids if related_cve_ids else None,
        "exploits_count": osv_data.get("exploits_count", 0),
        "view_count": 0,
        "original_data": json.dumps(osv_data, default=str),
    }


def cve_to_unified_format(cve_data: Dict) -> Dict:
    """将CVE数据转换为统一格式"""
    cvss_scores = []
    if cve_data.get("cvss_v3_score") is not None:
        cvss_scores.append({
            "version": "3.1",
            "score": cve_data["cvss_v3_score"],
            "severity": cve_data["cvss_v3_severity"],
            "vector": cve_data["cvss_v3_vector"]
        })
    if cve_data.get("cvss_v4_score") is not None:
        cvss_scores.append({
            "version": "4.0",
            "score": cve_data["cvss_v4_score"],
            "severity": cve_data["cvss_v4_severity"],
            "vector": cve_data["cvss_v4_vector"]
        })
    
    # Determine source from data_sources
    source = None
    data_sources = cve_data.get("data_sources")
    if data_sources:
        if len(data_sources) > 0:
            # Prefer official sources first
            for s in ['nvd', 'cvelistv5', 'mitre']:
                if s in data_sources:
                    source = s
                    break
            # If no official source found, use first one
            if source is None:
                source = data_sources[0]

    return {
        "vuln_id": cve_data["cve_id"],
        "type": "cve",
        "title": cve_data.get("title"),
        "title_zh": cve_data.get("title_zh"),
        "description": cve_data.get("description"),
        "description_zh": cve_data.get("description_zh"),
        "severity": normalize_severity(cve_data.get("cvss_v3_severity")),
        "cvss_scores": cvss_scores if cvss_scores else None,
        "cvss_v3_score": cve_data.get("cvss_v3_score"),
        "cvss_v3_vector": cve_data.get("cvss_v3_vector"),
        "cvss_v4_score": cve_data.get("cvss_v4_score"),
        "cvss_v4_vector": cve_data.get("cvss_v4_vector"),
        "epss_score": cve_data.get("epss_score"),
        "epss_percentile": cve_data.get("epss_percentile"),
        "cwes": cve_data.get("cwes"),
        "cisa_kev": cve_data.get("cisa_kev"),
        "cisa_kev_date_added": cve_data.get("cisa_kev_date_added"),
        "cisa_due_date": cve_data.get("cisa_due_date"),
        "cisa_required_action": cve_data.get("cisa_required_action"),
        "published_date": cve_data.get("published_date"),
        "modified_date": cve_data.get("modified_date"),
        "withdrawn_date": None,
        "aliases": None,
        "related": None,
        "affected": cve_data.get("affected_versions"),
        "references": cve_data.get("references"),
        "fixes": None,
        "source": source,
        "data_sources": data_sources,
        "tags": None,
        "related_cve_ids": None,
        "exploits_count": cve_data.get("exploits_count", 0),
        "view_count": 0,
        "original_data": json.dumps(cve_data, default=str),
    }


def cnvd_to_unified_format(cnvd_data: Dict) -> Dict:
    """将CNVD数据转换为统一格式"""
    cvss_scores = []
    if cnvd_data.get("cvss_v3_score") is not None:
        cvss_scores.append({
            "version": "3.1",
            "score": cnvd_data["cvss_v3_score"],
            "severity": cnvd_data["cvss_v3_severity"],
            "vector": cnvd_data["cvss_v3_vector"]
        })

    return {
        "vuln_id": cnvd_data["vuln_id"],
        "type": "cnvd",
        "title": cnvd_data.get("title"),
        "title_zh": None,
        "description": cnvd_data.get("description"),
        "description_zh": None,
        "severity": normalize_severity(cnvd_data.get("severity")),
        "cvss_scores": cvss_scores if cvss_scores else None,
        "cvss_v3_score": cnvd_data.get("cvss_v3_score"),
        "cvss_v3_vector": cnvd_data.get("cvss_v3_vector"),
        "cvss_v4_score": None,
        "cvss_v4_vector": None,
        "epss_score": None,
        "epss_percentile": None,
        "cwes": cnvd_data.get("cwe_ids"),
        "cisa_kev": None,
        "cisa_kev_date_added": None,
        "cisa_due_date": None,
        "cisa_required_action": None,
        "published_date": cnvd_data.get("published_date"),
        "modified_date": cnvd_data.get("modified_date"),
        "withdrawn_date": None,
        "aliases": None,
        "related": None,
        "affected": cnvd_data.get("affected_products"),
        "references": cnvd_data.get("references"),
        "fixes": [cnvd_data["solution"]] if cnvd_data.get("solution") else None,
        "source": cnvd_data.get("source"),
        "data_sources": cnvd_data.get("data_sources"),
        "tags": cnvd_data.get("tags"),
        "related_cve_ids": cnvd_data.get("related_cve_ids"),
        "exploits_count": cnvd_data.get("exploits_count", 0),
        "view_count": 0,
        "original_data": json.dumps(cnvd_data, default=str),
    }
