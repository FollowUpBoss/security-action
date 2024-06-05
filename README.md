# GitHub Action - Security Scanner and Reporter

![GitHub Release](https://img.shields.io/github/v/release/followupboss/security-action)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

![](docs/images/example.png)

## Table of Contents

- [Usage](#usage)

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

