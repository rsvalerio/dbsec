#!/usr/bin/env bash
# Detects drift between this repo's copies of forge's shared files and the
# canonical versions in rsvalerio/forge.
#
# The forge ref is not configured here: it is read out of `.github/workflows/`,
# so the files are always compared against the same tag the reusable workflows
# are pinned to. Bumping the pin therefore re-points the check automatically.
#
# Deliberate divergence is allowed but must be *recorded*: the expected diff
# lives in `.forge-sync/waivers/<file>.patch` under a `# reason:` header
# explaining it. Because the waiver is the diff and not a blanket exemption, a
# later change on the forge side still fails the check — a whole-file skip
# would hide it, which matters most for deny.toml, where a missed advisory
# policy update is a security gap rather than a style one.
#
# The waiver is checked by *applying* it to the canonical file and requiring the
# result to be this repo's copy, byte for byte — not by comparing its text to a
# freshly generated diff. Two `diff` implementations describe the same change
# with different hunk boundaries (BSD groups the header and the comment block
# differently from GNU), so a text comparison passes on the machine that
# recorded the waiver and fails everywhere else. It did: this check was red for
# `CONTRIBUTING.md` while the recorded divergence was correct and the forge side
# had not moved at all. Applying the patch answers the question the check is
# actually asking — "is the difference still exactly the one we signed off?" —
# and gives the same answer on every platform.
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

    # What this repo's copy is expected to be: the canonical file with the
    # recorded divergence applied, or the canonical file itself when nothing is
    # waived.
    expected="$tmp/expected"
    cp "$canonical" "$expected"
    if [ -f "$waiver" ]; then
        sed -n 's/^# reason: //p' "$waiver" | grep -q . ||
            die "$waiver has no '# reason:' header — a waived divergence must say why"
        # `--fuzz=0` because a waiver that only applies with fuzz is no longer a
        # statement about *this* divergence. `ops verify` strips trailing
        # whitespace repo-wide, so the blank context lines inside a stored patch
        # arrive empty rather than as a single space; patch reads them the same
        # way, which is why the recorded diff survives that rewriting.
        # `-f` as well as `-s`: `-s` silences output, not questions, and stdin
        # here is the waiver itself — a reversed or stale patch would prompt
        # ("Assume -R?") and read the answer out of its own body.
        if ! patch -s -f --fuzz=0 -r "$tmp/reject" "$expected" <"$waiver" >"$tmp/patch.err" 2>&1; then
            drifted+=("$local_path")
            echo
            echo "=== the recorded divergence for $local_path no longer applies to forge/$forge_path@$ref ==="
            echo "forge changed a part of the file the waiver describes. Take the change,"
            echo "then re-record: ./scripts/forge-sync-check.sh --update"
            sed 's/^/  /' "$tmp/patch.err"
            continue
        fi
    fi

    if ! diff -q "$expected" "$local_path" >/dev/null; then
        drifted+=("$local_path")
        echo
        echo "=== $local_path has drifted from forge/$forge_path@$ref ==="
        if [ ! -s "$actual" ] && [ -f "$waiver" ]; then
            echo "(the local copy matches forge again, but $waiver still records a divergence)"
        else
            echo "Beyond the recorded divergence, this repo's copy differs by:"
            diff -u --label "expected ($forge_path + waiver)" --label "$local_path" \
                "$expected" "$local_path" || true
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
