#!/usr/bin/env bash
# Test: Transport recovery — kill DNS resolver, restart, verify client recovers
# This tests that the client rebuilds the full transport stack (resolver +
# DNSPacketConn) on reconnect, not just the session layers.
set -euo pipefail
cd "$(dirname "$0")"

cleanup() { docker compose down -v 2>/dev/null; }
trap cleanup EXIT

echo "--- Building and starting services ---"
docker compose up -d --build

# Wait for tunnel to come up
echo "--- Waiting for SOCKS tunnel (up to 30s) ---"
for i in $(seq 1 30); do
    if docker compose exec -T client curl -s \
        --socks5-hostname localhost:7000 --proxy-user user:pass \
        --connect-timeout 5 http://heavy/ 2>/dev/null | grep -q "Welcome to nginx"; then
        echo ""
        echo "--- Tunnel is up ---"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo ""
        docker compose logs client server
        echo "=== FAIL (tunnel not ready) ==="
        exit 1
    fi
    printf "."
    sleep 1
done

# Kill the DNS resolver to poison the transport layer.
# The server is still running — only the DNS path is broken.
echo "--- Killing DNS resolver (poisoning transport) ---"
docker compose kill dns
sleep 5

# Restart the DNS resolver.
echo "--- Restarting DNS resolver ---"
docker start "$(docker compose ps -a -q dns)"

# Verify recovery within 30s.
# The client must rebuild its transport stack to recover.
echo "--- Waiting for tunnel recovery (up to 30s) ---"
recovery_start=$SECONDS
for i in $(seq 1 30); do
    if docker compose exec -T client curl -s \
        --socks5-hostname localhost:7000 --proxy-user user:pass \
        --connect-timeout 3 http://heavy/ 2>/dev/null | grep -q "Welcome to nginx"; then
        recovery_elapsed=$((SECONDS - recovery_start))
        echo ""
        echo "  Recovered after ~${recovery_elapsed}s"

        # Verify a full download works after recovery
        echo "--- Verifying full download after recovery ---"
        post_output=$(docker compose exec -T client \
            curl -s --socks5-hostname localhost:7000 --proxy-user user:pass \
            --max-time 300 \
            -w '\nsize_download=%{size_download}\n' \
            -o /dev/null \
            http://heavy/bigfile 2>&1) || true
        post_size=$(echo "$post_output" | grep '^size_download=' | cut -d= -f2)
        expected_size=10485760
        if [ "${post_size:-0}" = "$expected_size" ]; then
            echo "  Post-recovery download: ${post_size} bytes — OK"
            echo "=== PASS ==="
            exit 0
        else
            echo "  Post-recovery download: expected $expected_size, got ${post_size:-0}"
            docker compose logs client server
            echo "=== FAIL ==="
            exit 1
        fi
    fi
    printf "."
    sleep 1
done

echo ""
echo "--- Client did not recover after DNS resolver restart ---"
docker compose logs client server
echo "=== FAIL ==="
exit 1
