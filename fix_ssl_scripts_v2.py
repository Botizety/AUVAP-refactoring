#!/usr/bin/env python3
"""Simple SSL script fixer - only does safe single-line replacements.

This version avoids multi-line replacements to prevent indentation errors.

Usage:
    python fix_ssl_scripts_v2.py reports/classification_report.json
"""

import argparse
import json
import re
import sys
from pathlib import Path


def fix_ssl_script(script: str) -> tuple[str, list[str]]:
    """Fix deprecated SSL code in exploit script (safe version).

    Returns:
        (fixed_script, list_of_changes_made)
    """
    changes = []
    fixed = script

    # Fix 1: Replace PROTOCOL_SSLv3 with PROTOCOL_TLS_CLIENT
    if "ssl.PROTOCOL_SSLv3" in fixed:
        fixed = fixed.replace("ssl.PROTOCOL_SSLv3", "ssl.PROTOCOL_TLS_CLIENT")
        changes.append("Replaced ssl.PROTOCOL_SSLv3 → ssl.PROTOCOL_TLS_CLIENT")

    # Fix 2: Replace PROTOCOL_SSLv23 with PROTOCOL_TLS_CLIENT
    if "ssl.PROTOCOL_SSLv23" in fixed:
        fixed = fixed.replace("ssl.PROTOCOL_SSLv23", "ssl.PROTOCOL_TLS_CLIENT")
        changes.append("Replaced ssl.PROTOCOL_SSLv23 → ssl.PROTOCOL_TLS_CLIENT")

    # Fix 3: Remove lines with deprecated OP_NO_TLSv1_X options
    lines = fixed.split('\n')
    new_lines = []
    removed_count = 0
    for line in lines:
        if 'ssl.OP_NO_TLS' in line and 'context.options' in line:
            # Comment out instead of removing to preserve line numbers
            new_lines.append(line.replace(line.strip(), '# ' + line.strip() + '  # Removed by fixer'))
            removed_count += 1
        else:
            new_lines.append(line)
    if removed_count > 0:
        fixed = '\n'.join(new_lines)
        changes.append(f"Commented out {removed_count} deprecated OP_NO_TLS lines")

    # Fix 4: Replace cipher[1] with ssl_sock.version()
    if "cipher[1]" in fixed:
        # This is safe because it's always a simple expression
        fixed = fixed.replace("cipher[1]", "ssl_sock.version()")
        changes.append("Fixed cipher[1] → ssl_sock.version()")

    # Fix 5: Update f-strings to work with both Python 3.6+
    # (Already works in your environment, but noting for compatibility)

    return fixed, changes


def process_vulnerability_file(filepath: Path, dry_run: bool = False) -> dict:
    """Process vulnerability JSON file and fix all exploit scripts.

    Args:
        filepath: Path to classification_report.json or similar
        dry_run: If True, don't write changes, just report what would be done

    Returns:
        Statistics about fixes applied
    """
    # Load JSON
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)

    stats = {
        "total_vulnerabilities": 0,
        "scripts_fixed": 0,
        "total_changes": 0,
        "vulnerabilities_processed": []
    }

    # Process each vulnerability with a script
    vulns = data.get("vulnerabilities_with_scripts", [])
    stats["total_vulnerabilities"] = len(vulns)

    for vuln in vulns:
        vuln_id = vuln.get("vuln_id", "UNKNOWN")
        script_gen = vuln.get("script_generation", {})
        original_script = script_gen.get("exploit_script", "")

        if not original_script:
            continue

        # Apply fixes
        fixed_script, changes = fix_ssl_script(original_script)

        if changes:
            stats["scripts_fixed"] += 1
            stats["total_changes"] += len(changes)

            vuln_info = {
                "vuln_id": vuln_id,
                "changes": changes,
                "original_length": len(original_script),
                "fixed_length": len(fixed_script)
            }
            stats["vulnerabilities_processed"].append(vuln_info)

            # Update the script in the data structure
            if not dry_run:
                script_gen["exploit_script"] = fixed_script
                # Update notes
                note = "\n\nNOTE: Auto-patched by fix_ssl_scripts_v2.py to replace deprecated SSL protocols."
                script_gen["execution_notes"] = script_gen.get("execution_notes", "") + note

    # Write back to file if not dry run
    if not dry_run and stats["scripts_fixed"] > 0:
        # Backup original
        backup_path = filepath.with_suffix('.json.backup')
        with open(backup_path, 'w', encoding='utf-8') as f:
            # Re-read original to backup
            with open(filepath, 'r', encoding='utf-8') as orig:
                f.write(orig.read())
        print(f"✅ Backup created: {backup_path}")

        # Write fixed version
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"✅ Fixed scripts written to: {filepath}")

    return stats


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Fix deprecated SSL protocols in AUVAP exploit scripts (safe version)"
    )
    parser.add_argument(
        "input_file",
        type=Path,
        help="Path to classification_report.json or vulnerabilities file"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be changed without modifying files"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed changes for each vulnerability"
    )

    args = parser.parse_args(argv)

    if not args.input_file.exists():
        print(f"❌ Error: File not found: {args.input_file}")
        return 1

    print(f"{'🔍 DRY RUN MODE - No changes will be made' if args.dry_run else '🔧 Fixing SSL scripts (safe mode)...'}")
    print(f"Processing: {args.input_file}")
    print()

    # Process the file
    stats = process_vulnerability_file(args.input_file, dry_run=args.dry_run)

    # Print results
    print("=" * 70)
    print("📊 SUMMARY")
    print("=" * 70)
    print(f"Total vulnerabilities: {stats['total_vulnerabilities']}")
    print(f"Scripts fixed: {stats['scripts_fixed']}")
    print(f"Total changes applied: {stats['total_changes']}")
    print()

    if args.verbose and stats["vulnerabilities_processed"]:
        print("=" * 70)
        print("📝 DETAILED CHANGES")
        print("=" * 70)
        for vuln_info in stats["vulnerabilities_processed"]:
            print(f"\n{vuln_info['vuln_id']}:")
            for change in vuln_info['changes']:
                print(f"  • {change}")
            print(f"  Script size: {vuln_info['original_length']} → {vuln_info['fixed_length']} bytes")

    if not args.dry_run and stats['scripts_fixed'] > 0:
        print()
        print("✅ All scripts have been fixed!")
        print("\nNext steps:")
        print("  1. Test compilation: python3 -c 'import ast; ast.parse(open(\"fixed_script.py\").read())'")
        print("  2. Run training: python main.py --nessus ... --rl-mode train")
        print("  3. Monitor rewards in tensorboard")
    elif args.dry_run:
        print()
        print("ℹ️  This was a dry run. To apply fixes, run without --dry-run")
    else:
        print()
        print("ℹ️  No SSL issues found in scripts.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
