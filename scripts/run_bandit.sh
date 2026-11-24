#!/usr/bin/env bash
set -e
mkdir -p reports
bandit -r vulnerable_app secure_app -f txt -o reports/bandit_report.txt || true
echo "Bandit report saved to reports/bandit_report.txt"
