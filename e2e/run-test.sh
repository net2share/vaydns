#!/usr/bin/env bash
# Runs all e2e tests sequentially. Each test can also be run individually.
set -euo pipefail
cd "$(dirname "$0")"

failed=0
total=0

for rt in txt cname a aaaa mx ns srv; do
    total=$((total + 1))
    echo ""
    echo "========================================"
    echo "  e2e/tunnel (record-type: $rt)"
    echo "========================================"
    if bash tunnel/run.sh "$rt"; then
        echo ""
    else
        echo ""
        failed=$((failed + 1))
    fi
done

for test_dir in socks-download recovery transport-recovery; do
    total=$((total + 1))
    echo ""
    echo "========================================"
    echo "  e2e/$test_dir"
    echo "========================================"
    if bash "$test_dir/run.sh"; then
        echo ""
    else
        echo ""
        failed=$((failed + 1))
    fi
done

echo "========================================"
echo "  $((total - failed))/$total tests passed"
echo "========================================"

if [ "$failed" -gt 0 ]; then
    exit 1
fi
