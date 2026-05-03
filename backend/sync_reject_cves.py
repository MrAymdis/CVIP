#!/usr/bin/env python3
"""
同步 cvelistV5 中 REJECT 状态的 CVE 到 unified_vulnerabilities 表
"""
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.database import SessionLocal
from app.models import UnifiedVulnerability


class RejectCVESyncer:
    """同步 cvelistV5 中 REJECT 状态的 CVE"""

    def __init__(self, repo_path: Optional[str] = None):
        if repo_path is None:
            backend_dir = Path(__file__).parent.parent.parent
            self.repo_path = backend_dir / "cvelistV5"
        else:
            self.repo_path = Path(repo_path)

        self.cves_dir = self.repo_path / "cves"

    def get_available_years(self) -> list:
        if not self.cves_dir.exists():
            return []

        years = []
        for d in self.cves_dir.iterdir():
            if d.is_dir() and d.name.isdigit():
                years.append(int(d.name))
        return sorted(years, reverse=True)

    def parse_reject_cve(self, cve_data: Dict) -> Optional[Dict[str, Any]]:
        """解析 REJECT CVE JSON 5.x 格式"""
        try:
            cve_metadata = cve_data.get("cveMetadata", {})
            containers = cve_data.get("containers", {})
            cna_container = containers.get("cna", {})

            cve_id = cve_metadata.get("cveId")
            if not cve_id:
                return None

            cve_state = cve_metadata.get("state")
            if cve_state != "REJECTED":
                return None

            date_reserved = cve_metadata.get("dateReserved")
            date_rejected = cve_metadata.get("dateRejected")
            date_updated = cve_metadata.get("dateUpdated")
            date_published = cve_metadata.get("datePublished")

            if not date_published:
                date_published = date_updated

            rejected_reasons = cna_container.get("rejectedReasons", [])
            description = ""
            title = ""

            for reason in rejected_reasons:
                lang = reason.get("lang", "")
                value = reason.get("value", "")
                if lang == "en" and value:
                    description = value
                    title = value[:500] if len(value) > 500 else value
                    break

            if not title and description:
                title = description[:500]

            return {
                "vuln_id": cve_id,
                "type": "cve",
                "title": title,
                "title_zh": None,
                "description": description,
                "description_zh": None,
                "severity": None,
                "cvss_scores": None,
                "cvss_v3_score": None,
                "cvss_v3_vector": None,
                "cvss_v4_score": None,
                "cvss_v4_vector": None,
                "epss_score": None,
                "epss_percentile": None,
                "cwes": None,
                "cisa_kev": False,
                "cisa_kev_date_added": None,
                "cisa_due_date": None,
                "cisa_required_action": None,
                "published_date": datetime.fromisoformat(date_published.replace("Z", "+00:00")) if date_published else None,
                "modified_date": datetime.fromisoformat(date_updated.replace("Z", "+00:00")) if date_updated else None,
                "withdrawn_date": datetime.fromisoformat(date_rejected.replace("Z", "+00:00")) if date_rejected else None,
                "aliases": None,
                "related": None,
                "affected": None,
                "references": None,
                "fixes": None,
                "source": "cvelistv5",
                "data_sources": ["cvelistv5"],
                "tags": ["rejected"],
                "related_cve_ids": None,
                "exploits_count": 0,
                "view_count": 0,
                "original_data": cve_data,
            }
        except Exception as e:
            print(f"Error parsing REJECT CVE: {e}")
            import traceback
            traceback.print_exc()
            return None

    def sync_reject_cves(self, years: Optional[list] = None, batch_size: int = 1000) -> int:
        """同步 REJECT CVE 到数据库"""
        if years is None:
            years = self.get_available_years()

        if not years:
            print("No years found in repository")
            return 0

        print(f"Found {len(years)} years to process: {years}")

        db = SessionLocal()
        total_synced = 0
        total_errors = 0
        total_skipped = 0

        try:
            for year in years:
                year_dir = self.cves_dir / str(year)
                if not year_dir.exists():
                    print(f"Year directory not found: {year}")
                    continue

                print(f"\nProcessing year: {year}")
                year_synced = 0
                year_errors = 0
                year_skipped = 0

                subdirs = sorted([d for d in year_dir.iterdir() if d.is_dir()])

                for subdir in subdirs:
                    json_files = list(subdir.glob("*.json"))

                    for json_file in json_files:
                        try:
                            with open(json_file, 'r', encoding='utf-8') as f:
                                cve_data = json.load(f)

                            parsed = self.parse_reject_cve(cve_data)
                            if not parsed:
                                year_skipped += 1
                                continue

                            vuln_id = parsed["vuln_id"]

                            existing = db.query(UnifiedVulnerability).filter(
                                UnifiedVulnerability.vuln_id == vuln_id
                            ).first()

                            if existing:
                                for key, value in parsed.items():
                                    if key == "original_data":
                                        existing.original_data = value
                                    elif key not in ["vuln_id", "type"] and hasattr(existing, key):
                                        if value is not None or key in ["tags"]:
                                            setattr(existing, key, value)
                                year_synced += 1
                            else:
                                vuln = UnifiedVulnerability(**parsed)
                                db.add(vuln)
                                year_synced += 1

                            total_synced += 1

                            if total_synced % batch_size == 0:
                                db.commit()
                                print(f"  Synced {total_synced} REJECT CVEs...")

                        except Exception as e:
                            print(f"Error processing {json_file}: {e}")
                            year_errors += 1
                            total_errors += 1

                print(f"  Year {year}: {year_synced} synced, {year_errors} errors, {year_skipped} skipped (non-REJECT)")

            db.commit()
            print(f"\n✅ Sync completed: {total_synced} REJECT CVEs synced, {total_errors} errors")
            return total_synced

        except Exception as e:
            db.rollback()
            print(f"Error during sync: {e}")
            import traceback
            traceback.print_exc()
            return total_synced
        finally:
            db.close()


if __name__ == "__main__":
    syncer = RejectCVESyncer("/tmp/cvelistV5")

    years = syncer.get_available_years()
    print(f"Available years: {years}")

    print("\nStarting REJECT CVE sync...")
    count = syncer.sync_reject_cves()
    print(f"\nSync complete: {count} REJECT CVEs synced to unified_vulnerabilities table")