#!/usr/bin/env python3
"""AuthDesk Unified E2E Test Suite Runner.

Executes and reports on the multi-tier test suite (Tiers 1-4).
Supports tier selection, milestone filtering, verbose output, and structured reporting.

Usage:
    python3 tests/e2e/runner.py [--tier {1,2,3,4,all}] [--milestone {M0,M1,M2,M3,M4,all}] [-v]
"""

import argparse
import os
import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest


def main() -> int:
    parser = argparse.ArgumentParser(
        description="AuthDesk E2E Multi-Tier Test Suite Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--tier",
        choices=["1", "2", "3", "4", "all"],
        default="all",
        help="Run tests in a specific tier or all tiers (default: all)",
    )
    parser.add_argument(
        "--milestone",
        choices=["M0", "M1", "M2", "M3", "M4", "all"],
        default="all",
        help="Filter tests by milestone marker (default: all)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose pytest output",
    )
    parser.add_argument(
        "-x",
        "--fail-fast",
        action="store_true",
        help="Stop on first failure",
    )
    parser.add_argument(
        "--json-report",
        type=str,
        default=None,
        help="Path to output JSON test execution report",
    )

    args = parser.parse_args()

    # Determine test directories or files based on tier
    test_root = Path(__file__).resolve().parent
    pytest_args = []

    if args.verbose:
        pytest_args.append("-v")
    else:
        pytest_args.append("-q")

    if args.fail_fast:
        pytest_args.append("-x")

    # Tier filtering
    if args.tier == "1":
        pytest_args.append(str(test_root / "tier1_feature_coverage"))
    elif args.tier == "2":
        pytest_args.append(str(test_root / "tier2_boundary_corner"))
    elif args.tier == "3":
        pytest_args.append(str(test_root / "tier3_cross_feature"))
    elif args.tier == "4":
        pytest_args.append(str(test_root / "tier4_real_world_scenarios"))
    else:
        pytest_args.append(str(test_root))

    # Milestone marker filtering
    marker_expr = []
    if args.milestone != "all":
        marker_expr.append(f"milestone == '{args.milestone}'")

    if marker_expr:
        pytest_args.extend(["-m", " and ".join(marker_expr)])

    # Output banner
    print("=" * 70)
    print("   AuthDesk E2E Multi-Tier Test Runner")
    print(f"   Target: Tier={args.tier.upper()} | Milestone={args.milestone.upper()}")
    print("=" * 70)

    # Execute pytest
    exit_code = pytest.main(pytest_args)

    print("=" * 70)
    if exit_code == 0:
        print("   >>> ALL EXECUTED TESTS PASSED SUCCESSFULLY <<<")
    else:
        print(f"   >>> TEST RUN FINISHED WITH EXIT CODE {exit_code} <<<")
    print("=" * 70)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
