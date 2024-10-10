#!/bin/bash
set -eu

if [ -z "${GITHUB_TOKEN-}" ]; then
	echo "GITHUB_TOKEN must be set."
	exit 1
fi

scanType="${INPUT_SCAN_TYPE}"

# Run Trivy and generate results
if [ "${scanType}" == "diff" ]; then
  trivy rootfs --format json --scanners misconfig --ignorefile .circleci/security/.trivyignore.yaml -o report.json diff
elif [  "${scanType}" == "branch" ]; then
  trivy rootfs --format json --scanners misconfig --ignorefile .circleci/security/.trivyignore.yaml -o report.json .
fi

# Parse and create issues
python /trivy_parser.py report.json
