#!/usr/bin/env python3
"""Install the canonical src/code-security tree into another project."""

import argparse
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "code-security"


def install(target_project, force=False):
    target_project = Path(target_project).resolve()
    destination = target_project / ".claude" / "skills" / "code-security"

    if target_project == ROOT:
        raise ValueError(
            "Refusing to create a duplicate inside this source repository. "
            "Choose the project where the skill should be installed."
        )
    if destination.exists():
        if not force:
            raise FileExistsError(
                f"{destination} already exists; rerun with --force to replace it"
            )
        shutil.rmtree(destination)

    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(
        SOURCE,
        destination,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache"),
    )
    return destination


def main():
    parser = argparse.ArgumentParser(
        description="Install Code Security Skill into a target project"
    )
    parser.add_argument("target_project", help="Project directory that will receive .claude/skills")
    parser.add_argument(
        "--force", action="store_true", help="Replace an existing installed skill"
    )
    args = parser.parse_args()

    destination = install(args.target_project, force=args.force)
    print(f"Installed Code Security Skill to {destination}")


if __name__ == "__main__":
    main()
