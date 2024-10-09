#!/bin/bash
set -eu

if [ -z "${GITHUB_TOKEN-}" ]; then
	echo "GITHUB_TOKEN must be set."
	exit 1
fi

echo $GITHUB_REF
echo $GITHUB_REF_NAME

PR=`echo $GITHUB_REF_NAME | cut -d '/' -f1`

# Get list of files changed by the PR Branch
files='$(curl -L \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer ${GITHUB_TOKEN}" \
  "https://api.github.com/repos/${GITHUB_REPOSITORY}/PULLS/${PR}/files" | jq ".[] | .filename")'

# Copy the modified/added files to a folder
mkdir files
for file in $files; do cp "$file" files; done

# Run Trivy and generate results
trivy rootfs --format json --scanners misconfig --ignorefile .circleci/security/.trivyignore.yaml -o report.json ./files

# Parse and create issues
python /trivy_parser.py report.json
