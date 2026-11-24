#!/usr/bin/env bash
set -e
mkdir -p reports
semgrep scan --config p/python secure_app
