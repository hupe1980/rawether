# rawether — development task runner (https://just.systems). `just ci` mirrors CI.

msrv := "1.88"

default:
    @just --list --unsorted

# Every local quality gate, in order; stops at the first failure.
ci: fmt-check lint test doc deny msrv package planning-paths workflows

# `ci` plus the kernel suite on a veth pair in a Linux container.
ci-all: ci veth-docker

fmt:
    cargo fmt --all

fmt-check:
    @echo "==> gate: fmt-check"
    cargo fmt --all --check

# Clippy on the host and on the other backends (cross-checked).
lint:
    @echo "==> gate: lint"
    cargo clippy --all-targets -- -D warnings
    cargo clippy --all-targets --target aarch64-unknown-linux-gnu -- -D warnings
    cargo clippy --all-targets --target aarch64-apple-darwin -- -D warnings
    cargo clippy --target x86_64-pc-windows-gnu -- -D warnings

test:
    @echo "==> gate: test"
    cargo test

doc:
    @echo "==> gate: doc"
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --target aarch64-unknown-linux-gnu
    test -f target/aarch64-unknown-linux-gnu/doc/rawether/threat_model/index.html

deny:
    @echo "==> gate: deny"
    cargo deny check

msrv:
    @echo "==> gate: msrv"
    cargo +{{msrv}} check --all-targets

# The published package builds from what it ships, and ships the threat model.
package:
    @echo "==> gate: package"
    cargo package --allow-dirty --list | grep -qx THREAT_MODEL.md || { echo "THREAT_MODEL.md is not in the package" >&2; exit 1; }
    ! cargo package --allow-dirty --list | grep -E '^(specs|\.specify|\.claude|concepts)/'
    cargo publish --dry-run --allow-dirty

# The website: internal links resolve, external ones are reported, and it builds.
site:
    @echo "==> gate: site"
    cd site && zola check && zola build

# The kernel suite on a veth pair, natively (Linux, sudo) or in Docker.
veth:
    scripts/veth-test.sh

veth-docker:
    scripts/veth-test.sh --docker

# The crate never cites the planning directories, and the design records name no private note,
# local path or e-mail address.
planning-paths:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "==> gate: planning-paths"
    status=0
    if grep -rnE '(concepts|specs|\.specify)/' src examples tests Cargo.toml deny.toml; then
        echo "planning paths in the crate" >&2; status=1
    fi
    if grep -rnE 'concepts[/]' README.md SECURITY.md THREAT_MODEL.md CHANGELOG.md site justfile .github; then
        echo "private notes cited in the published tree" >&2; status=1
    fi
    if [[ -d specs ]] && grep -rnE --exclude='incoming-*' 'concept[s]/|/Users/|/home/[a-z]|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]{2,}' specs .specify/memory; then
        echo "private references in the design records" >&2; status=1
    fi
    exit $status

# Every action pinned to a full commit SHA with its version as a comment; read-only tokens.
workflows:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "==> gate: workflows"
    status=0
    wf=(.github/workflows/*.yml)
    if grep -nE '^\s*(- )?uses:' "${wf[@]}" | grep -vE 'uses: [^@ ]+@[0-9a-f]{40} # v[0-9]'; then
        echo "actions not pinned to a full SHA with a version comment" >&2; status=1
    fi
    for f in "${wf[@]}"; do
        grep -A1 -xE 'permissions:' "$f" | grep -qxE '  contents: read' || { echo "$f: no top-level read-only token" >&2; status=1; }
    done
    if grep -nE 'pull_request_target|workflow_run' "${wf[@]}"; then echo "privileged trigger" >&2; status=1; fi
    if grep -nE '\$\{\{ *github\.(event\.|head_ref)' "${wf[@]}"; then echo "untrusted context in an expression" >&2; status=1; fi
    exit $status
