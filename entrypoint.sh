#!/bin/bash
set -eu

if [ -z "${GITHUB_TOKEN-}" ]; then
	echo "GITHUB_TOKEN must be set."
	exit 1
fi

PR=`echo $GITHUB_REF_NAME | cut -d '/' -f1`

# Get list of files changed by the PR Branch
curl -L \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer ${GITHUB_TOKEN}" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  "https://api.github.com/repos/${GITHUB_REPOSITORY}/PULLS/${PR}/files"

# Run Trivy and generate results
trivy rootfs --format json --scanners misconfig --ignorefile .circleci/security/.trivyignore.yaml -o report.json .

# Parse and create issues
python /trivy_parser.py report.json
