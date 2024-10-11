# GitHub Action - Security Scanner and Reporter

![GitHub Release](https://img.shields.io/github/v/release/followupboss/security-action)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

![](docs/images/example.png)

## Table of Contents

- [Usage](#usage)
- [Features](#features)

## Usage

### Action Setup

```yaml
name: Security Scan PR

on: 
  pull_request:
    types: [opened, ready_for_review, reopened]

jobs:
  security-scan-pr:
    name: Security Scan PR
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      - name: Run Scans and Comment on PR
        uses: FollowUpBoss/security-action@main
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
```

If you want to scan only the diff from the PR and not the entire branch

```yaml
name: Security Scan PR

on:
  pull_request:
    types: [opened, ready_for_review, reopened]

jobs:
  security_scan_pr:
  name: Security Scan PR
  runs-on: ubuntu-latest
  steps:
    - name: Checkout code
      uses: actions/checkout@v4
      with: fetch-depth: 0
    - name: Generate diff
      run: git diff origin/main origin/${GITHUB_HEAD_REF} > diff
    - name: Run Scans and Comment on PR
      uses: FollowUpBoss/security-action@main
      with:
        token: ${{ secrets.GITHUB_TOKEN }}
        scan-type: "diff"
```

## Features
Action uses [Trivy](https://trivy.dev) to perform scanning. Currently it is configured:
- Run Misconfiguration scanning against Infrastructure as Code
- Output the scan in json format
- Parse and validate scan output
- Generate or Update a PR comment
