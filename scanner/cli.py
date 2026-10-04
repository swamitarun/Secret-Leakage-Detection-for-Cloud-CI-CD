"""
CLI & Directory Scanner for Context-Aware Secret Leakage Detection.

Supports:
- Scanning single files or entire directory trees
- Filtering by supported file extensions
- JSON report export (reports/scan_report.json)
- HTML interactive visual report export (reports/scan_report.html)
- Clean, formatted CLI terminal summary
- Configurable exit code for CI/CD pipelines
"""

import os
import sys
import json
import argparse
import html
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scanner.scanner import scan_file
from scanner.iac_analyzer import analyze_file
from scanner.risk_engine import assess_risk, format_report, to_json_dict, _load_config, RiskAssessment
from scanner.hybrid import enrich_with_transformer

SUPPORTED_EXTENSIONS = {
    ".tf", ".tfvars", ".yaml", ".yml", ".json", ".py", ".env", ".txt", ".md", ".sh"
}

IGNORE_DIRS = {
    ".git", "venv", ".venv", "__pycache__", ".pytest_cache", "node_modules", ".idea", ".vscode"
}


def discover_files(target_path: str) -> list[str]:
    """Recursively discover supported files in target_path."""
    path = Path(target_path)
    if path.is_file():
        return [str(path)]
    
    discovered = []
    for root, dirs, files in os.walk(path):
        # Prune ignored directories
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            name_lower = file.lower()
            # Special case for .env, Dockerfile, etc.
            if ext in SUPPORTED_EXTENSIONS or name_lower.startswith(".env") or name_lower == "jenkinsfile":
                discovered.append(os.path.join(root, file))
                
    return sorted(discovered)


def scan_directory(target_path: str, transformer: bool = False, model_path: str | None = None,
                   gpu_id: int | None = None) -> list[RiskAssessment]:
    """Scan all files in target_path and produce risk assessments."""
    files = discover_files(target_path)
    assessments = []
    for f in files:
        try:
            findings = scan_file(f)
            ctx = analyze_file(f)
            assessment = assess_risk(f, findings, ctx)
            if transformer:
                with open(f, "r", encoding="utf-8", errors="replace") as source:
                    assessment = enrich_with_transformer(assessment, source.read(), model_path, gpu_id)
            assessments.append(assessment)
        except Exception as e:
            print(f"[!] Error scanning {f}: {e}", file=sys.stderr)
    return assessments


def generate_html_report(assessments: list[RiskAssessment], output_html: str):
    """Generate a modern, standalone HTML report with rich styling."""
    total_files = len(assessments)
    counts = {"SAFE": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for a in assessments:
        counts[a.risk_level] = counts.get(a.risk_level, 0) + 1
        
    critical_high = [a for a in assessments if a.risk_level in ("HIGH", "CRITICAL")]
    
    rows_html = []
    for a in assessments:
        badge_color = {
            "SAFE": "#10b981",
            "LOW": "#3b82f6",
            "MEDIUM": "#f59e0b",
            "HIGH": "#f97316",
            "CRITICAL": "#ef4444"
        }.get(a.risk_level, "#6b7280")
        
        findings_summary = ", ".join([f.secret_type for f in a.findings]) if a.findings else "None"
        resources_summary = ", ".join(a.aws_resources) if a.aws_resources else "None"
        safe_filepath = html.escape(os.path.normpath(a.filepath))
        safe_file_type = html.escape(a.file_type)
        safe_iac_type = html.escape(a.iac_type)
        safe_resources = html.escape(resources_summary)
        safe_cicd = html.escape(f"Yes ({a.ci_cd_platform})" if a.ci_cd_context else "No")
        safe_findings = html.escape(findings_summary)
        safe_transformer = html.escape(
            "Unavailable" if not a.transformer_available
            else f"{a.transformer_probability:.1%} ({a.hybrid_decision})"
        )
        safe_explanation = html.escape(a.explanation)
        
        factors_html = "".join([
            f"<li><span style='color:{'#ef4444' if f.points > 0 else '#10b981'}'>{'+' if f.points > 0 else ''}{f.points}</span> {html.escape(f.description)}</li>"
            for f in a.factors
        ])
        
        rows_html.append(f"""
        <tr>
            <td><strong>{safe_filepath}</strong></td>
            <td><span class="badge" style="background-color: {badge_color}">{a.risk_level} ({a.risk_score})</span></td>
            <td>{safe_file_type} {f'({safe_iac_type})' if a.iac_type != 'none' else ''}</td>
            <td>{safe_resources}</td>
            <td>{safe_cicd}</td>
            <td>{safe_findings}</td>
            <td>{safe_transformer}</td>
            <td>
                <p style="margin: 0 0 6px 0; font-size: 0.9em;"><em>{safe_explanation}</em></p>
                <ul style="margin: 0; padding-left: 18px; font-size: 0.85em; color: #475569;">
                    {factors_html}
                </ul>
            </td>
        </tr>
        """)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Context-Aware Secret Leakage Security Scan</title>
    <style>
        :root {{
            --bg: #0f172a;
            --card-bg: #1e293b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --border: #334155;
            --safe: #10b981;
            --low: #3b82f6;
            --med: #f59e0b;
            --high: #f97316;
            --crit: #ef4444;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #f1f5f9;
            color: #1e293b;
            margin: 0;
            padding: 24px;
        }}
        .header {{
            background: linear-gradient(135deg, #1e293b, #0f172a);
            color: #ffffff;
            padding: 28px;
            border-radius: 12px;
            margin-bottom: 24px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }}
        .header h1 {{ margin: 0 0 8px 0; font-size: 1.8rem; font-weight: 700; }}
        .header p {{ margin: 0; color: #94a3b8; font-size: 1rem; }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .stat-card {{
            background: white;
            padding: 18px;
            border-radius: 10px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.08);
            border-top: 4px solid #cbd5e1;
            text-align: center;
        }}
        .stat-card .val {{ font-size: 1.8rem; font-weight: bold; margin: 4px 0; }}
        .stat-card .lbl {{ font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; color: #64748b; }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.08);
        }}
        th, td {{
            padding: 14px 16px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
            vertical-align: top;
        }}
        th {{
            background: #f8fafc;
            color: #475569;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        tr:hover {{ background-color: #f8fafc; }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            color: white;
            font-weight: 600;
            font-size: 0.75rem;
            border-radius: 9999px;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Context-Aware Secret Leakage Security Report</h1>
        <p>Novelty: Evaluates secret exposure severity via IaC (Terraform / CloudFormation), AWS Resources & CI/CD contexts.</p>
    </div>

    <div class="stats-grid">
        <div class="stat-card" style="border-top-color: #64748b;">
            <div class="lbl">Total Files</div>
            <div class="val" style="color: #1e293b;">{total_files}</div>
        </div>
        <div class="stat-card" style="border-top-color: #ef4444;">
            <div class="lbl">Critical</div>
            <div class="val" style="color: #ef4444;">{counts['CRITICAL']}</div>
        </div>
        <div class="stat-card" style="border-top-color: #f97316;">
            <div class="lbl">High</div>
            <div class="val" style="color: #f97316;">{counts['HIGH']}</div>
        </div>
        <div class="stat-card" style="border-top-color: #f59e0b;">
            <div class="lbl">Medium</div>
            <div class="val" style="color: #f59e0b;">{counts['MEDIUM']}</div>
        </div>
        <div class="stat-card" style="border-top-color: #3b82f6;">
            <div class="lbl">Low</div>
            <div class="val" style="color: #3b82f6;">{counts['LOW']}</div>
        </div>
        <div class="stat-card" style="border-top-color: #10b981;">
            <div class="lbl">Safe</div>
            <div class="val" style="color: #10b981;">{counts['SAFE']}</div>
        </div>
    </div>

    <table>
        <thead>
            <tr>
                <th>File Path</th>
                <th>Risk Level</th>
                <th>Type / IaC</th>
                <th>AWS Resources</th>
                <th>CI/CD</th>
                <th>Secrets</th>
                <th>Transformer</th>
                <th>Explainable Breakdown & Rationale</th>
            </tr>
        </thead>
        <tbody>
            {''.join(rows_html)}
        </tbody>
    </table>
</body>
</html>
"""
    os.makedirs(os.path.dirname(output_html), exist_ok=True)
    with open(output_html, "w", encoding="utf-8") as f:
        f.write(html_content)


def print_cli_summary(target_path: str, assessments: list[RiskAssessment]):
    """Print terminal summary output."""
    counts = {"SAFE": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    total_secrets = 0
    for a in assessments:
        counts[a.risk_level] = counts.get(a.risk_level, 0) + 1
        total_secrets += len([f for f in a.findings if not f.is_placeholder])

    print("\n" + "=" * 64)
    print(f"  CONTEXT-AWARE SECRET LEAKAGE SCANNER")
    print("=" * 64)
    print(f"  Target:            {target_path}")
    print(f"  Files Scanned:     {len(assessments)}")
    print(f"  Secrets Detected:  {total_secrets}")
    print("-" * 64)
    print("  RISK DISTRIBUTION:")
    print(f"    SAFE:     {counts['SAFE']:3d}")
    print(f"    LOW:      {counts['LOW']:3d}")
    print(f"    MEDIUM:   {counts['MEDIUM']:3d}")
    print(f"    HIGH:     {counts['HIGH']:3d}")
    print(f"    CRITICAL: {counts['CRITICAL']:3d}")
    print("=" * 64)

    critical_and_high = [a for a in assessments if a.risk_level in ("CRITICAL", "HIGH")]
    if critical_and_high:
        print("\n[!] CRITICAL & HIGH FINDINGS:")
        for idx, a in enumerate(critical_and_high, 1):
            print(f"\n  [{idx}] File:       {a.filepath}")
            print(f"      Risk:       {a.risk_score}/100 [{a.risk_level}]")
            print(f"      IaC:        {a.iac_type.capitalize()} (AWS Resource: {', '.join(a.aws_resources) or 'none'})")
            print(f"      CI/CD:      {a.ci_cd_context} ({a.ci_cd_platform})")
            print(f"      Reason:     {a.explanation}")
            print(f"      Transformer: {'unavailable' if not a.transformer_available else f'{a.transformer_probability:.1%} secret probability ({a.hybrid_decision})'}")
            print("      Factors:")
            for fac in a.factors:
                sign = "+" if fac.points >= 0 else ""
                print(f"        {sign}{fac.points:3d} {fac.description}")
        print("\n" + "=" * 64)
    else:
        print("\n[+] No CRITICAL or HIGH risk findings discovered.")


def generate_sarif_report(assessments: list[RiskAssessment], output_sarif: str) -> None:
    """Write a GitHub Code Scanning-compatible SARIF report without secret values."""
    results = []
    for assessment in assessments:
        for finding in assessment.findings:
            if finding.is_placeholder:
                continue
            rule_id = f"secret/{finding.secret_type}"
            results.append({
                "ruleId": rule_id,
                "level": "error" if assessment.risk_level in ("HIGH", "CRITICAL") else "warning",
                "message": {
                    "text": (
                        f"{finding.secret_type} detected; risk {assessment.risk_level} "
                        f"({assessment.risk_score}/100)."
                    )
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": assessment.filepath},
                        "region": {"startLine": finding.line_number},
                    }
                }],
                "properties": {
                    "risk_level": assessment.risk_level,
                    "risk_score": assessment.risk_score,
                    "iac_type": assessment.iac_type,
                    "ci_cd_context": assessment.ci_cd_context,
                },
            })

    report = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Context-Aware Secret Leakage Scanner",
                "informationUri": "https://github.com/security/secret-leakage-detector",
                "rules": [],
            }},
            "results": results,
        }],
    }
    output_dir = os.path.dirname(output_sarif) or "."
    os.makedirs(output_dir, exist_ok=True)
    with open(output_sarif, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="Context-Aware Secret Leakage Detection for Cloud CI/CD & IaC"
    )
    parser.add_argument("path", help="File or directory path to scan", default=".", nargs="?")
    parser.add_argument("--json", dest="json_out", help="Path to save JSON report", default="reports/scan_report.json")
    parser.add_argument("--html", dest="html_out", help="Path to save HTML report", default="reports/scan_report.html")
    parser.add_argument("--sarif", dest="sarif_out", help="Path to save GitHub Code Scanning SARIF report")
    parser.add_argument("--fail-on", choices=["HIGH", "CRITICAL", "MEDIUM", "NEVER"], default="HIGH",
                        help="Exit code 1 if findings meet or exceed this risk level (for CI/CD)")
    parser.add_argument("--transformer", action="store_true",
                        help="Fuse an available trained transformer checkpoint with deterministic rules")
    parser.add_argument("--model-path", help="Transformer checkpoint path (used with --transformer)")
    parser.add_argument("--gpu-id", type=int, help="CUDA device index for transformer inference")
    
    args = parser.parse_args()
    
    target = os.path.abspath(args.path)
    if not os.path.exists(target):
        print(f"Error: Path '{target}' does not exist.", file=sys.stderr)
        sys.exit(2)
        
    assessments = scan_directory(target, args.transformer, args.model_path, args.gpu_id)
    print_cli_summary(target, assessments)
    
    # Export reports
    if args.json_out:
        os.makedirs(os.path.dirname(args.json_out), exist_ok=True)
        summary = {
            level: sum(1 for a in assessments if a.risk_level == level)
            for level in ("SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL")
        }
        report_data = {
            "summary": {key: value for key, value in summary.items() if value},
            "assessments": [to_json_dict(a) for a in assessments]
        }
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
        print(f"\n[+] JSON report saved to: {args.json_out}")
        
    if args.html_out:
        generate_html_report(assessments, args.html_out)
        print(f"[+] HTML report saved to: {args.html_out}")

    if args.sarif_out:
        generate_sarif_report(assessments, args.sarif_out)
        print(f"[+] SARIF report saved to: {args.sarif_out}")
        
    # CI exit code check
    if args.fail_on != "NEVER":
        levels = ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        cutoff_idx = levels.index(args.fail_on)
        violation = any(levels.index(a.risk_level) >= cutoff_idx for a in assessments)
        if violation:
            print(f"\n[!] CI/CD Policy Check: FAILED due to findings at or above {args.fail_on} risk.", file=sys.stderr)
            sys.exit(1)
            
    print("\n[+] Scan completed successfully.")
    sys.exit(0)


if __name__ == "__main__":
    main()
