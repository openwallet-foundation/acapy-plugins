#!/usr/bin/env python3
"""List open Dependabot PRs and the libraries they update."""

import json
import re
import subprocess
import sys


def get_open_dependabot_prs():
    result = subprocess.run(
        [
            "gh", "pr", "list",
            "--author", "app/dependabot",
            "--state", "open",
            "--limit", "200",
            "--json", "number,title,body",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)


def extract_libraries(title: str, body: str) -> list[str]:
    # Titles like: "bump ruff from X to Y ..."
    # or: "bump cryptography from X to Y in /dir ..."
    match = re.search(r"bump (\S+) from ", title)
    if match:
        return [match.group(1)]

    # Fallback: body always has "Updates `library`" lines, one per library
    return re.findall(r"Updates `([^`]+)`", body)


def main():
    debug = "--debug" in sys.argv

    prs = get_open_dependabot_prs()
    if not prs:
        print("No open Dependabot PRs found.")
        return

    all_libraries = set()
    pr_libs = []
    for pr in prs:
        libraries = extract_libraries(pr["title"], pr["body"])
        unique_libs = sorted(set(libraries))
        all_libraries.update(unique_libs)
        pr_libs.append((pr, unique_libs))

    if debug:
        print(f"{'PR':>6}  {'Library/Libraries':<35}  Title")
        print("-" * 110)
        for pr, unique_libs in pr_libs:
            lib_str = ", ".join(unique_libs) if unique_libs else "(unknown)"
            print(f"#{pr['number']:>5}  {lib_str:<35}  {pr['title']}")
    else:
        for lib in sorted(all_libraries):
            print(lib)


if __name__ == "__main__":
    main()
