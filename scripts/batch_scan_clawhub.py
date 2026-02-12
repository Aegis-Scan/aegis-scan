#!/usr/bin/env python3
"""
Batch scan ClawHub skills with Aegis.
Fetches the last N skills via clawhub explore, installs each, runs aegis scan,
and collects JSON reports for analysis.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

# Paths
REPO_ROOT = Path(__file__).resolve().parent.parent
AGENT_TOOLS = REPO_ROOT.parent / ".cursor" / "projects" / "c-Users-mhube-aegis-audit-MASTER" / "agent-tools"
SKILLS_DIR = REPO_ROOT / ".clawhub_batch_skills"
OUTPUT_DIR = REPO_ROOT / "batch_scan_results"
SLUG_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-/]*$")


def fetch_skills(limit: int = 100, from_file: Path | None = None) -> list[dict]:
    """Fetch skills via clawhub explore --json, or from a pre-saved JSON file."""
    if from_file and from_file.exists():
        with open(from_file, encoding="utf-8") as f:
            data = json.load(f)
        return data.get("items", [])[:limit]
    cmd = [
        "npx",
        "clawhub@latest",
        "explore",
        "--limit",
        str(limit),
        "--json",
        "--no-input",
    ]
    result = subprocess.run(
        cmd,
        capture_output=True,
        cwd=str(REPO_ROOT),
        timeout=120,
    )
    if result.returncode != 0:
        print((result.stderr or b"").decode("utf-8", errors="replace"), file=sys.stderr)
        raise RuntimeError("clawhub explore failed")
    out = (result.stdout or b"").decode("utf-8", errors="replace")
    start = out.find("{")
    if start == -1:
        raise RuntimeError("No JSON in clawhub output")
    data = json.loads(out[start:])
    return data.get("items", [])


def install_skill(slug: str, workdir: Path) -> Path | None:
    """Install skill to workdir/skills/<slug>. Returns path or None on failure."""
    skills_sub = workdir / "skills"
    skills_sub.mkdir(parents=True, exist_ok=True)
    if not SLUG_PATTERN.fullmatch(slug):
        return None

    cmd = [
        "npx",
        "clawhub@latest",
        "install",
        slug,
        "--no-input",
        "--force",
        "--workdir",
        str(workdir),
    ]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(REPO_ROOT),
        timeout=120,
    )
    if result.returncode != 0:
        return None
    path = skills_sub / slug
    return path if path.exists() else None


def run_aegis_scan(skill_path: Path) -> dict | None:
    """Run aegis scan --no-llm --json and return parsed report."""
    import os
    aegis_core = REPO_ROOT / "aegis-core"
    cmd = [
        sys.executable, "-m", "aegis.cli",
        "scan", str(skill_path), "--no-llm", "--json", "-q",
    ]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(aegis_core)
    env["PYTHONIOENCODING"] = env.get("PYTHONIOENCODING", "utf-8")
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(aegis_core),
        timeout=90,
        env=env,
    )
    if result.returncode != 0:
        # Still try to parse JSON (aegis exits 1 on hard_fail but prints JSON)
        pass
    try:
        return json.loads(result.stdout) if result.stdout else None
    except json.JSONDecodeError:
        if result.stderr:
            print(f"  [stderr] {result.stderr[:200]}...", file=sys.stderr)
        return None


def main():
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    max_scan = int(sys.argv[2]) if len(sys.argv) > 2 else 100
    explore_file = Path(sys.argv[3]) if len(sys.argv) > 3 else None

    SKILLS_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    if explore_file:
        print(f"Loading skills from {explore_file}...")
        items = fetch_skills(limit=limit, from_file=explore_file)
    else:
        print("Fetching skills from ClawHub...")
        items = fetch_skills(limit=limit)
    slugs = [i["slug"] for i in items]
    item_by_slug = {i["slug"]: i for i in items}
    print(f"Got {len(slugs)} skills")

    results = []
    for i, slug in enumerate(slugs[:max_scan]):
        print(f"[{i+1}/{min(len(slugs), max_scan)}] {slug}...", end=" ", flush=True)
        meta = item_by_slug.get(slug, {})
        path = install_skill(slug, SKILLS_DIR)
        if not path:
            print("INSTALL_FAIL")
            results.append({"slug": slug, "status": "install_fail", "report": None})
            continue
        report = run_aegis_scan(path)
        if report:
            out_path = OUTPUT_DIR / f"{slug}.json"
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            print("OK")
            results.append({
                "slug": slug,
                "displayName": meta.get("displayName", slug),
                "summary": meta.get("summary"),
                "status": "ok",
                "report_path": str(out_path),
                "report": report,
            })
        else:
            print("SCAN_FAIL")
            results.append({"slug": slug, "status": "scan_fail", "report": None})

    # Summary JSON
    summary_path = OUTPUT_DIR / "summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\nWrote {summary_path}")
    ok = sum(1 for r in results if r["status"] == "ok")
    print(f"Successfully scanned: {ok}/{len(results)}")


if __name__ == "__main__":
    main()
