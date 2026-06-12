#!/usr/bin/env bash

if [[ "$1" == "--help" ]]; then
    echo "Usage: bump-patch-version.sh [--help]"
    echo "Fetches git tags, finds the latest semantic version, and prints the next patch version."
    exit 0
fi


git fetch --tags

latest_tag=$(git tag --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -n 1)

IFS='.' read -r major minor patch <<< "${latest_tag#v}"

echo "v${major}.${minor}.$((patch + 1))"
