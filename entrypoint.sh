#!/bin/bash
set -eu

if [ -z "${GITHUB_TOKEN-}" ]; then
	echo "GITHUB_TOKEN must be set."
	exit 1
fi

# Run Trivy and generate results
trivy rootfs --format json --scanners misconfig --ignorefile .circleci/security/.trivyignore.yaml -o report.json .

# Parse and create issues
python /trivy_parser.py report.json
