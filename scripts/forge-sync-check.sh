#!/usr/bin/env bash
# Detects drift between this repo's copies of forge's shared files and the
# canonical versions in rsvalerio/forge.
#
# The forge ref is not configured here: it is read out of `.github/workflows/`,
# so the files are always compared against the same tag the reusable workflows
# are pinned to. Bumping the pin therefore re-points the check automatically.
#
# Deliberate divergence is allowed but must be *recorded*: the exact expected
# diff lives in `.forge-sync/waivers/<file>.patch` under a `# reason:` header
# explaining it. Because the waiver is the diff and not a blanket exemption, a
# later change on the forge side still fails the check — a whole-file skip
# would hide it, which matters most for deny.toml, where a missed advisory
# policy update is a security gap rather than a style one.
#
#   ./scripts/forge-sync-check.sh            # check; exit 1 on unrecorded drift
#   ./scripts/forge-sync-check.sh --update   # record the current diff as a waiver
#                                            # (FORGE_SYNC_REASON=... for new ones)
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

manifest=.forge-sync/manifest
waiver_dir=.forge-sync/waivers
update=0
[ "${1:-}" = "--update" ] && update=1

die() {
    echo "forge-sync: $*" >&2
    exit 1
}

[ -f "$manifest" ] || die "missing $manifest"

# The pin the workflows use. Every forge reference must agree, or "the tag the
# workflows are pinned to" has no single answer and this check would be lying
# about what it compared against.
mapfile -t refs < <(
    grep -ho 'rsvalerio/forge/[^@[:space:]]*@[[:alnum:]._/-]*' .github/workflows/*.yml |
        sed 's/.*@//' | sort -u
)
case ${#refs[@]} in
0) die "no rsvalerio/forge reference in .github/workflows/ — nothing says which tag to compare against" ;;
1) ref=${refs[0]} ;;
*) die "workflows pin forge at more than one ref (${refs[*]}); align them before checking drift" ;;
esac

# `ops verify` strips trailing whitespace repo-wide, which would eat the blank
# context lines inside a recorded patch. Normalize both sides so a waiver
# survives that, dropping the `#` header and any trailing blank lines with it.
normalize() {
    sed -e 's/[[:space:]]*$//' -e '/^#/d' "$1" |
        awk '{ line[NR] = $0 } END { last = NR; while (last > 0 && line[last] == "") last--; for (i = 1; i <= last; i++) print line[i] }'
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

drifted=()
while read -r local_path forge_path; do
    case "$local_path" in '' | '#'*) continue ;; esac
    [ -n "$forge_path" ] || die "$manifest: '$local_path' has no forge path"
    [ -f "$local_path" ] || die "$local_path is listed in $manifest but does not exist"

    url="https://raw.githubusercontent.com/rsvalerio/forge/$ref/$forge_path"
    canonical="$tmp/canonical"
    curl -fsSL --retry 3 --retry-delay 2 --max-time 30 -o "$canonical" "$url" ||
        die "could not fetch $url (network failure, or forge no longer has $forge_path at $ref)"

    # The labels deliberately omit the ref so a waiver stays valid across a pin
    # bump for as long as the divergence itself is unchanged.
    actual="$tmp/actual.patch"
    diff -u --label "forge/$forge_path" --label "$local_path" "$canonical" "$local_path" \
        >"$actual" || true

    waiver="$waiver_dir/$(echo "$local_path" | tr '/' '_').patch"

    if [ "$update" = 1 ]; then
        if [ ! -s "$actual" ]; then
            if [ -f "$waiver" ]; then
                rm "$waiver"
                echo "forge-sync: $local_path is back in sync, waiver removed"
            fi
            continue
        fi
        reason=$(sed -n 's/^# reason: //p' "$waiver" 2>/dev/null || true)
        [ -n "$reason" ] || reason=${FORGE_SYNC_REASON:-}
        [ -n "$reason" ] ||
            die "recording a divergence for $local_path needs a reason: set FORGE_SYNC_REASON"
        mkdir -p "$waiver_dir"
        {
            echo "# reason: $reason"
            cat "$actual"
        } >"$waiver"
        echo "forge-sync: recorded the divergence for $local_path"
        continue
    fi

    expected="$tmp/expected.patch"
    if [ -f "$waiver" ]; then
        sed -n 's/^# reason: //p' "$waiver" | grep -q . ||
            die "$waiver has no '# reason:' header — a waived divergence must say why"
        normalize "$waiver" >"$expected"
    else
        : >"$expected"
    fi

    normalize "$actual" >"$tmp/actual.norm"
    if ! diff -q "$tmp/actual.norm" "$expected" >/dev/null; then
        drifted+=("$local_path")
        echo
        echo "=== $local_path has drifted from forge/$forge_path@$ref ==="
        if [ -s "$actual" ]; then
            cat "$actual"
        else
            echo "(the local copy matches forge again, but $waiver still records a divergence)"
        fi
        if [ -f "$waiver" ]; then
            echo "--- recorded divergence ($waiver) ---"
            cat "$waiver"
        fi
    fi
done <"$manifest"

if [ ${#drifted[@]} -gt 0 ]; then
    echo
    echo "forge-sync: ${#drifted[@]} file(s) differ from rsvalerio/forge@$ref: ${drifted[*]}"
    echo "Copy the canonical file back, or — when the divergence is deliberate — record it:"
    echo "  FORGE_SYNC_REASON='why this repo differs' ./scripts/forge-sync-check.sh --update"
    exit 1
fi

echo "forge-sync: every file matches rsvalerio/forge@$ref (recorded divergences applied)"
