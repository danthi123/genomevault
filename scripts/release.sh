#!/usr/bin/env bash
#
# release.sh — version-bump, build, publish, tag, push
#
# Usage:
#   scripts/release.sh <new-version>
#
# Example:
#   scripts/release.sh 0.2.0
#
# What this does (in order, aborting on any failure):
#   1. Sanity — clean working tree on main branch, no untracked critical files
#   2. Update src/genomevault/version.py
#   3. Seed a new [<version>] stanza in CHANGELOG.md (you edit the details)
#   4. Run the full test suite + lint + mypy
#   5. Build sdist + wheel into dist/
#   6. Run twine check on the artifacts
#   7. Upload to PyPI (via twine; credentials from ~/.pypirc or TWINE_* env)
#   8. Commit the version bump + CHANGELOG entry
#   9. Tag v<version> and push both main and the tag to origin + gitea
#
# Requirements:
#   - Python 3.10+ with build, twine, ruff, mypy, pytest installed
#     (pip install -e '.[dev]' && pip install build twine)
#   - ~/.pypirc configured with a project-scoped token, OR
#     TWINE_USERNAME=__token__ TWINE_PASSWORD=pypi-... in the environment
#   - git remotes `origin` (GitHub) and `gitea` (self-hosted Gitea)
#   - A clean git tree on the main branch
#
# Flags:
#   --skip-tests    Skip pytest + ruff + mypy (for hotfixes you've verified manually)
#   --skip-upload   Build and tag, but do not run twine upload (for dry runs)
#   --skip-push     Do not push main/tag to either remote

set -euo pipefail

# ----- arg parsing ---------------------------------------------------------

NEW_VERSION=""
SKIP_TESTS=0
SKIP_UPLOAD=0
SKIP_PUSH=0

for arg in "$@"; do
    case "$arg" in
        --skip-tests)   SKIP_TESTS=1 ;;
        --skip-upload)  SKIP_UPLOAD=1 ;;
        --skip-push)    SKIP_PUSH=1 ;;
        -h|--help)
            sed -n '2,40p' "$0"
            exit 0
            ;;
        -*)
            echo "error: unknown flag $arg" >&2
            exit 2
            ;;
        *)
            if [[ -n "$NEW_VERSION" ]]; then
                echo "error: extra positional argument $arg" >&2
                exit 2
            fi
            NEW_VERSION="$arg"
            ;;
    esac
done

if [[ -z "$NEW_VERSION" ]]; then
    echo "usage: $0 <new-version> [--skip-tests] [--skip-upload] [--skip-push]" >&2
    exit 2
fi

# Basic semver shape check.  We allow pre-release suffixes like 0.2.0-rc1.
if ! [[ "$NEW_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9]+)*$ ]]; then
    echo "error: '$NEW_VERSION' does not look like a version" >&2
    exit 2
fi

# ----- move to repo root --------------------------------------------------

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
echo "release.sh: repo root = $REPO_ROOT"
echo "release.sh: target version = $NEW_VERSION"

# ----- pre-flight ---------------------------------------------------------

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$BRANCH" != "main" ]]; then
    echo "error: must release from 'main' branch, currently on '$BRANCH'" >&2
    exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
    echo "error: working tree is not clean; commit or stash first" >&2
    git status --short
    exit 1
fi

# Refuse to re-release an existing version.
if git tag -l | grep -qx "v$NEW_VERSION"; then
    echo "error: tag v$NEW_VERSION already exists" >&2
    exit 1
fi

# ----- bump the version file ---------------------------------------------

VERSION_FILE="src/genomevault/version.py"
CURRENT_VERSION="$(grep -oE '"[^"]+"' "$VERSION_FILE" | tr -d '"')"
echo "release.sh: bumping $VERSION_FILE: $CURRENT_VERSION -> $NEW_VERSION"

# Cross-platform sed: write to a temp file, then move.  Works on BSD + GNU sed.
python - "$VERSION_FILE" "$NEW_VERSION" <<'PYEOF'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
new_version = sys.argv[2]
text = path.read_text()
import re
path.write_text(
    re.sub(r'^__version__ = "[^"]+"$', f'__version__ = "{new_version}"', text, flags=re.M)
)
PYEOF

# ----- seed a CHANGELOG stanza -------------------------------------------

CHANGELOG="CHANGELOG.md"
DATE="$(date +%Y-%m-%d)"
TMP_CHANGELOG="$(mktemp)"

# If there is already a stanza for this version, do not duplicate it.
if grep -q "^## \[$NEW_VERSION\]" "$CHANGELOG"; then
    echo "release.sh: CHANGELOG already has an entry for $NEW_VERSION, leaving alone"
else
    echo "release.sh: seeding CHANGELOG.md with a new [$NEW_VERSION] stanza"
    awk -v new="$NEW_VERSION" -v date="$DATE" '
        BEGIN { inserted = 0 }
        /^## \[/ && !inserted {
            print "## [" new "] — " date
            print ""
            print "### Added"
            print ""
            print "- TODO: describe the additions"
            print ""
            print "### Changed"
            print ""
            print "- TODO: describe the changes"
            print ""
            print "### Fixed"
            print ""
            print "- TODO: describe the fixes (remove this section if none)"
            print ""
            inserted = 1
        }
        { print }
    ' "$CHANGELOG" > "$TMP_CHANGELOG"
    mv "$TMP_CHANGELOG" "$CHANGELOG"
fi

# ----- quality gates -----------------------------------------------------

if [[ "$SKIP_TESTS" -eq 0 ]]; then
    echo "release.sh: running ruff"
    python -m ruff check .
    echo "release.sh: running mypy"
    python -m mypy src || { echo "mypy failed; aborting" >&2; exit 1; }
    echo "release.sh: running pytest"
    python -m pytest -q
else
    echo "release.sh: SKIPPING tests / lint / type check (--skip-tests)"
fi

# ----- build -------------------------------------------------------------

echo "release.sh: cleaning dist/ and building"
rm -rf dist/ build/ src/*.egg-info
python -m build

echo "release.sh: twine check"
python -m twine check dist/*

# ----- upload ------------------------------------------------------------

if [[ "$SKIP_UPLOAD" -eq 0 ]]; then
    echo "release.sh: uploading to PyPI"
    python -m twine upload dist/*
else
    echo "release.sh: SKIPPING upload (--skip-upload); artifacts in dist/"
fi

# ----- commit + tag + push ----------------------------------------------

git add "$VERSION_FILE" "$CHANGELOG"
git commit -m "release: v$NEW_VERSION"
git tag -a "v$NEW_VERSION" -m "Release v$NEW_VERSION"

if [[ "$SKIP_PUSH" -eq 0 ]]; then
    echo "release.sh: pushing main + v$NEW_VERSION tag to origin (GitHub)"
    git push origin main
    git push origin "v$NEW_VERSION"

    # The gitea remote may not be set on every clone; skip cleanly if absent.
    if git remote | grep -qx "gitea"; then
        echo "release.sh: pushing to gitea"
        git push gitea main
        git push gitea "v$NEW_VERSION"
    else
        echo "release.sh: no 'gitea' remote configured, skipping Gitea push"
    fi
else
    echo "release.sh: SKIPPING git push (--skip-push); remember to push main + v$NEW_VERSION tag manually"
fi

echo ""
echo "release.sh: done — v$NEW_VERSION published"
echo "  PyPI:   https://pypi.org/project/genomevault/$NEW_VERSION/"
echo "  GitHub: https://github.com/danthi123/genomevault/releases/tag/v$NEW_VERSION"
echo ""
echo "next steps:"
echo "  * review CHANGELOG.md — replace the TODO placeholders with real entries"
echo "  * if you edit the changelog now, amend the release commit and force-push"
echo "  * or let the next release absorb the edits"
