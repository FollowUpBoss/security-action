#!/bin/bash
set -eu

# if [ -z "${INPUT_FILENAME-}" ]; then
# 	echo "INPUT_FILENAME must be set."
# 	exit 1
# fi

# if [ -z "${GITHUB_REPOSITORY-}" ]; then
# 	echo "GITHUB_REPOSITORY must be set."
# 	exit 1
# fi
# ${{ github.repository }}
if [ -z "${GITHUB_TOKEN-}" ]; then
	echo "GITHUB_TOKEN must be set."
	exit 1
fi

# if [ -z "${INPUT_LABEL-}" ]; then
# 	echo "INPUT_LABEL must be set."
# 	exit 1
# fi

# Run Trivy and generate results
trivy rootfs --format json --scanners vuln,misconfig,secret -o report.json .

# Parse and create issues
python /trivy_parser.py report.json
