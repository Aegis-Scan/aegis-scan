#!/usr/bin/env python3
"""
Analyze batch scan reports for clarity, missing info, wrong assumptions.
Surfaces patterns to inform taxonomy and logic fixes.
"""

from __future__ import annotations

import json
from pathlib import Path
from collections import defaultdict

REPO_ROOT = Path(__file__).resolve().parent.parent
BATCH_DIR = REPO_ROOT / "batch_scan_results"
SUMMARY_PATH = BATCH_DIR / "summary.json"


def load_summary() -> list[dict]:
    with open(SUMMARY_PATH, encoding="utf-8") as f:
        return json.load(f)


def main():
    items = load_summary()
    ok_items = [i for i in items if i.get("status") == "ok" and i.get("report")]

    print(f"Analyzing {len(ok_items)} successful scans\n")
    print("=" * 70)

    # 1. Skill category distribution
    categories: dict[str, int] = defaultdict(int)
    general_count = 0
    permission_overreach_by_category: dict[str, list[str]] = defaultdict(list)
    no_skill_md = 0
    risk_score_dist: list[tuple[str, int]] = []

    for item in ok_items:
        r = item.get("report", {})
        det = r.get("deterministic", {})
        # We don't have skill_category in the JSON report - it's computed at runtime
        # But we have capabilities, persona, meta_insights
        caps = det.get("capabilities", {})
        persona = det.get("persona", {})
        meta = det.get("meta_insights", [])
        risk = r.get("ephemeral", {}).get("risk_score_final") or det.get("risk_score_static", 0)

        if not any(m.get("category") for m in meta):
            pass  # no meta
        risk_score_dist.append((item.get("slug", ""), risk))

        # Check for common issues in meta_insights
        for m in meta:
            if m.get("category") == "purpose" and m.get("severity") in ("warning", "danger"):
                pass  # doc mismatch

    # 2. Read a few full reports to inspect structure and spot issues
    # We need to add skill_category and permission_overreach to the report
    # For now, re-scan a subset or parse from report path
    # The report JSON doesn't include integrity/taxonomy - that's only in console
    # So we need to either add those to the report, or run a lightweight analysis
    # that re-computes taxonomy from SKILL.md in each skill dir

    # Parse reports for patterns
    personas: dict[str, int] = defaultdict(int)
    cap_categories_used: dict[str, int] = defaultdict(int)
    combo_risks_count = 0
    path_violations_count = 0
    high_risk_count = 0
    prohibited_count = 0

    for item in ok_items:
        r = item.get("report", {})
        det = r.get("deterministic", {})
        caps = det.get("capabilities", {})
        persona = det.get("persona", {}) or {}
        combos = det.get("combination_risks", [])
        pv = det.get("path_violations", [])
        proh = det.get("prohibited_findings", [])
        risk = r.get("ephemeral", {}).get("risk_score_final") or det.get("risk_score_static", 0)

        personas[persona.get("persona", "unknown")] += 1
        for c in caps:
            cap_categories_used[c] += 1
        combo_risks_count += len(combos)
        path_violations_count += len(pv)
        if risk >= 50:
            high_risk_count += 1
        prohibited_count += len(proh)

    print("\n1. PERSONA DISTRIBUTION")
    for p, n in sorted(personas.items(), key=lambda x: -x[1]):
        print(f"   {p}: {n}")

    print("\n2. CAPABILITY CATEGORIES (skills using each)")
    for c, n in sorted(cap_categories_used.items(), key=lambda x: -x[1]):
        print(f"   {c}: {n}")

    print(f"\n3. RISK")
    print(f"   High risk (>=50): {high_risk_count}")
    print(f"   Prohibited findings: {prohibited_count} skills")
    print(f"   Combination risks: {combo_risks_count} total")
    print(f"   Path violations: {path_violations_count} total")

    # 4. Sample reports that are "general" (no SKILL.md or weak signal)
    # and have permission_overreach - we'd need to add that to the report
    # For now, list skills with no/few meta_insights
    skills_with_purpose_issues = []
    skills_with_scope_issues = []
    for item in ok_items:
        r = item.get("report", {})
        meta = r.get("deterministic", {}).get("meta_insights", [])
        for m in meta:
            if m.get("category") == "purpose" and m.get("severity") in ("warning", "danger"):
                skills_with_purpose_issues.append(item.get("slug"))
                break
            if m.get("category") == "scope":
                skills_with_scope_issues.append(item.get("slug"))
                break

    print(f"\n4. DOCUMENTATION ISSUES")
    print(f"   Purpose/capability mismatch: {len(set(skills_with_purpose_issues))} skills")
    print(f"   Scope (missing files) issues: {len(set(skills_with_scope_issues))} skills")

    # 5. Skills by risk bucket
    buckets = {"0-9": 0, "10-24": 0, "25-49": 0, "50-74": 0, "75-100": 0}
    for item in ok_items:
        r = item.get("report", {})
        risk = r.get("ephemeral", {}).get("risk_score_final") or r.get("deterministic", {}).get("risk_score_static", 0)
        if risk < 10: buckets["0-9"] += 1
        elif risk < 25: buckets["10-24"] += 1
        elif risk < 50: buckets["25-49"] += 1
        elif risk < 75: buckets["50-74"] += 1
        else: buckets["75-100"] += 1
    print(f"\n5. RISK SCORE BUCKETS")
    for k, v in buckets.items():
        print(f"   {k}: {v}")

    # 6. Taxonomy analysis (skill_category, permission_overreach)
    taxonomy_categories: dict[str, int] = defaultdict(int)
    overreach_count = 0
    general_with_overreach = []
    overreach_by_category: dict[str, list[tuple[str, list[str]]]] = defaultdict(list)

    for item in ok_items:
        r = item.get("report", {})
        tax = (r.get("ephemeral", {}) or {}).get("taxonomy") or {}
        cat = tax.get("skill_category", "general")
        overreach = tax.get("permission_overreach") or []
        taxonomy_categories[cat] += 1
        if overreach:
            overreach_count += 1
            slug = item.get("slug", "")
            overreach_by_category[cat].append((slug, overreach))
            if cat == "general":
                general_with_overreach.append((slug, overreach))

    print("\n6. TAXONOMY")
    print(f"   Categories: {dict(taxonomy_categories)}")
    print(f"   Skills with permission_overreach: {overreach_count}")
    print(f"   General + overreach: {len(general_with_overreach)}")
    for slug, msgs in general_with_overreach[:5]:
        print(f"      {slug}: {[m[:60]+'...' for m in msgs[:2]]}")

    # 7. ISSUES TO FIX (actionable)
    print("\n7. ACTIONABLE FINDINGS")
    # network in 93/93 - should "network" be unusual for many types?
    if cap_categories_used.get("network", 0) >= len(ok_items) * 0.8:
        print("   - Network is near-ubiquitous: consider relaxing 'unusual' for network in types where it's borderline")
    # Too many general?
    if taxonomy_categories.get("general", 0) > len(ok_items) * 0.3:
        print(f"   - {taxonomy_categories.get('general',0)} skills classified as 'general': expand keywords or lower threshold?")
    # Trust me bro + permission goblin dominance
    if (personas.get("trust_me_bro", 0) + personas.get("permission_goblin", 0)) > len(ok_items) * 0.6:
        print("   - High share of trust_me_bro + permission_goblin: may be over-flagging; review persona thresholds")


if __name__ == "__main__":
    main()
