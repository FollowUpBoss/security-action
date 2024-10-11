#!/usr/bin/env python

import os
import re
import argparse
import json
import sys
import collections
from github import Auth, Github
from operator import itemgetter
from dataclasses import dataclass
from typing import Iterator, List, Union, OrderedDict, TypedDict


class MisconfigDict(TypedDict):
    ID: str
    AVDID: str
    Severity: str
    Description: str
    Resolution: str
    Message: str
    Title: str
    PrimaryURL: str
    CauseMetadata: dict
    Target: str


class ResultDict(TypedDict):
    Type: str
    Target: str
    Misconfigs: List[MisconfigDict]


class ReportDict(TypedDict):
    Results: List[ResultDict]


@dataclass
class Misconfig:
    id: str
    avdid: str
    title: str
    description: str
    severity: str
    resolution: str
    message: str
    url: str


@dataclass
class Report:
    kind: str
    id: str
    target: str
    misconfigs: List[MisconfigDict]


@dataclass
class Issue:
    # Unique ID for issue, based on package name and version
    id: str
    report: Report
    body: str


def abort(text: str):
    print(text, file=sys.stderr)
    sys.exit(1)


def comments(comment_body: str) -> None:
    gh_repo: str = os.environ.get("GITHUB_REPOSITORY")
    gh_token: str = os.environ.get("GITHUB_TOKEN")
    pull: str = os.environ.get("GITHUB_REF_NAME")
    gh_pull: int = re.search(r"\d+", pull).group(0)
    if not gh_repo:
        abort("Env variable GITHUB_REPOSITORY is not set correctly")
    if not gh_pull:
        abort("Env variable GITHUB_REF_NAME is not being read correctly")
    print(f"Getting comments for {gh_repo}/pull/{gh_pull}")
    if not gh_token:
        abort("Env variable GH_TOKEN is not set correctly")

    auth = Auth.Token(gh_token)
    gh = Github(auth=auth)
    repo = gh.get_repo(gh_repo)
    pr = repo.get_pull(int(gh_pull))
    scanner_comment = None
    comments = pr.get_issue_comments()
    for comment in comments:
        if "<Scan Results>" in comment.body:
            scanner_comment = comment

    if scanner_comment is None:
        pr.create_issue_comment(comment_body)
    else:
        scanner_comment.edit(comment_body)


def parse_results(data: ReportDict) -> Iterator[Report]:
    try:
        results = data["Results"]
    except KeyError:
        comment = zero_findings()
        comments(comment)
        sys.exit(0)
    if not isinstance(results, list):
        raise KeyError(
            f"The JSON entry Results section is not a list, got: {type(results).__name__}"
        )

    reports: OrderedDict[str, Issue] = collections.OrderedDict()

    for idx, result in enumerate(results):
        if not isinstance(result, dict):
            raise TypeError(
                f"The JSON entry .Results[{idx}] is not a dictionary, got: {type(result).__name__}"
            )
        target: str = result["Target"]
        if "Misconfigurations" in result:
            misconfigs = result["Misconfigurations"]
            for misconfig in misconfigs:
                id = misconfig["ID"]
                avdid = misconfig["AVDID"]
                report_id: str = f"{id}:{avdid}"
                report: Report = Report(
                    kind="Misconfig",
                    id=report_id,
                    target=result["Target"],
                    misconfigs=[misconfig],
                )
                reports[report_id] = report

    return reports.values()


def parse_misconfigs(reports: Iterator[Report], severity: str) -> list:
    misconfigs: list = []
    for report in reports:
        target: str = report.target
        for misconfig_idx, misconfig in enumerate(report.misconfigs, start=1):
            if severity in misconfig["Severity"]:
                misconfig["Target"] = target
                misconfigs.append(misconfig)

    return misconfigs


def zero_findings() -> str:
    repo: str = os.environ.get("GITHUB_REPOSITORY")
    comment_body: str = f"""
<Scan Results>

#### For full details connect to staging VPN and see [Defectdojo](https://defectdojo.reclients.com/product/7/finding/open?verified=true)

#### Scan Summary:

:godmode: You've done well! No Findings! :godmode:
"""
    return comment_body


def generate_comment(criticals: list, highs: list, mediums: list, lows: list) -> str:
    repo: str = os.environ.get("GITHUB_REPOSITORY")
    startline: int = None
    endline: int = None
    filename: str = None
    filelink: str = None
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    row: str = ""

    for misconfig in criticals:
        misconfig["Severity"] = "${\color{red}{\\textsf{Critical}}}$"
        if misconfig["CauseMetadata"]:
            causedata: dict = misconfig["CauseMetadata"]
            occurrences: list = causedata.get("Occurrences", [])
            if occurrences:
                for occurrence in occurrences:
                    startline = occurrence["Location"]["StartLine"]
                    endline = occurrence["Location"]["EndLine"]
                    filename = occurrence["Filename"]
                    filelink = f"https://github.com/{repo}/blob/main/{filename}?plain=1#L{str(startline)}-L{str(endline)}"
            else:
                startline: int = causedata.get("StartLine", int)
                endline: int = causedata.get("EndLine", int)
                filename = misconfig["Target"]
                if startline and endline is None:
                    filelink = f"https://gibhub.com/{repo}/blob/main/{filename}"
                else:
                    filelink = f"https://github.com/{repo}/blob/main/{filename}?plain=1#L{str(startline)}-L{str(endline)}"
                continue

        row += f"| {misconfig['Severity']} | [{filename}]({filelink}) | [{misconfig['ID']}]({misconfig['PrimaryURL']}) | {misconfig['Message']} |\n"
        critical_count += 1

    for misconfig in highs:
        misconfig["Severity"] = "${\color{Orange}{\\textsf{High}}}$"
        if misconfig["CauseMetadata"]:
            causedata: dict = misconfig["CauseMetadata"]
            occurrences: list = causedata.get("Occurrences", [])
            if occurrences:
                for occurrence in occurrences:
                    startline = occurrence["Location"]["StartLine"]
                    endline = occurrence["Location"]["EndLine"]
                    filename = occurrence["Filename"]
                    filelink = f"https://github.com/{repo}/blob/main/{filename}?plain=1#L{str(startline)}-L{str(endline)}"
            else:
                startline = causedata.get("StartLine", int)
                endline = causedata.get("EndLine", int)
                filename = misconfig["Target"]
                if startline and endline is None:
                    filelink = f"https://gibhub.com/{repo}/blob/main/{filename}"
                else:
                    filelink = f"https://github.com/{repo}/blob/main/{filename}?plain=1#L{str(startline)}-L{str(endline)}"
                continue

        row += f"| {misconfig['Severity']} | [{filename}]({filelink}) | [{misconfig['ID']}]({misconfig['PrimaryURL']}) | {misconfig['Message']} |\n"
        high_count += 1

    for misconfig in mediums:
        misconfig["Severity"] = "${\color{yellow}{\\textsf{Medium}}}$"
        if misconfig["CauseMetadata"]:
            causedata: dict = misconfig["CauseMetadata"]
            occurrences: list = causedata.get("Occurrences", [])
            if occurrences:
                for occurrence in occurrences:
                    startline = occurrence["Location"]["StartLine"]
                    endline = occurrence["Location"]["EndLine"]
                    filename = occurrence["Filename"]
                    filelink = f"https://github.com/{repo}/blob/main/{filename}?plain=1#L{str(startline)}-L{str(endline)}"
            else:
                startline = causedata.get("StartLine", int)
                endline = causedata.get("EndLine", int)
                filename = misconfig["Target"]
                if startline and endline is None:
                    filelink = f"https://gibhub.com/{repo}/blob/main/{filename}"
                else:
                    filelink = f"https://github.com/{repo}/blob/main/{filename}?plain=1#L{str(startline)}-L{str(endline)}"
                continue

        row += f"| {misconfig['Severity']} | [{filename}]({filelink}) | [{misconfig['ID']}]({misconfig['PrimaryURL']}) | {misconfig['Message']} |\n"
        medium_count += 1

    for misconfig in lows:
        misconfig["Severity"] = "${\color{green}{\\textsf{Low}}}$"
        if misconfig["CauseMetadata"]:
            causedata: dict = misconfig["CauseMetadata"]
            occurrences: list = causedata.get("Occurrences", [])
            if occurrences:
                for occurrence in occurrences:
                    startline = occurrence["Location"]["StartLine"]
                    endline = occurrence["Location"]["EndLine"]
                    filename = occurrence["Filename"]
                    filelink = f"https://github.com/{repo}/blob/main/{filename}?plain=1#L{str(startline)}-L{str(endline)}"
            else:
                startline = causedata.get("StartLine", int)
                endline = causedata.get("EndLine", int)
                filename = misconfig["Target"]
                if startline and endline is None:
                    filelink = f"https://gibhub.com/{repo}/blob/main/{filename}"
                else:
                    filelink = f"https://github.com/{repo}/blob/main/{filename}?plain=1#L{str(startline)}-L{str(endline)}"
                continue

        row += f"| {misconfig['Severity']} | [{filename}]({filelink}) | [{misconfig['ID']}]({misconfig['PrimaryURL']}) | {misconfig['Message']} |\n"
        low_count += 1

    critical_findings: str = (
        "${\color{red}{\\textsf{Critical:" + str(critical_count) + "}}}$"
    )
    high_findings: str = "${\color{Orange}{\\textsf{High: " + str(high_count) + "}}}$"
    medium_findings: str = (
        "${\color{yellow}{\\textsf{Medium: " + str(medium_count) + "}}}$"
    )
    low_findings: str = "${\color{green}{\\textsf{Low: " + str(low_count) + "}}}$"
    comment_body: str = f"""
<Scan Results>

#### For full details connect to staging VPN and see [Defectdojo](https://defectdojo.reclients.com/product/7/finding/open?verified=true)

#### Scan Summary:

| | | | |
| - | - | - | - |
| {critical_findings} | {high_findings} | {medium_findings} | {low_findings} |

#### Security Scan Report:
| Severity | File | ID | Description |
| - | - | - | - |
"""
    comment_body += row
    return comment_body


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Parses Trivy JSON report files and reports minsconfigurations as a PR comment."
            "Existing comments are read from the PR and used to exclude reported and update if changes are made."
        )
    )
    parser.add_argument("file")
    args = parser.parse_args()

    filename = args.file

    data: ReportDict = json.load(open(filename, "rb"))
    if not isinstance(data, dict):
        abort(f"Data in json file {filename} does not contain a dictionary")

    try:
        reports = parse_results(data)
    except TypeError as e:
        abort(f"Failed to parse JSON report. Error: {e}")
    except KeyError as e:
        abort(f"No results from scan. Error: {e}")

    try:
        criticals: list = parse_misconfigs(reports, "CRITICAL")
        highs: list = parse_misconfigs(reports, "HIGH")
        mediums: list = parse_misconfigs(reports, "MEDIUM")
        lows: list = parse_misconfigs(reports, "LOW")
    except TypeError as e:
        abort(f"Type Error: Failed to generate comment data. Error: {e}")
    except KeyError as e:
        abort(f"Unable to read report data. Error: {e}")

    try:
        comment = generate_comment(criticals, highs, mediums, lows)
        print("Reported Findings")
    except TypeError as e:
        abort(f"Type Error: Failed to generate comment data. Error: {e}")
    except KeyError as e:
        abort(f"Unable to read report data. Error: {e}")

    try:
        comments(comment)
    except ValueError as e:
        print(f"{e}. Exiting...")
        sys.exit(0)
    except TypeError as e:
        abort(f"Failed to post comment. Type Error: {e}")
    except KeyError as e:
        abort(f"Failed to post comment. Key Error: {e}")


if __name__ == "__main__":
    main()
