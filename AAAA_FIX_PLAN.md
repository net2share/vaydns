# AAAA Query Bug Fix and Test Plan

## Problem Statement
The project was modified to use AAAA queries instead of TXT queries. However, responses come back but don't register—data is getting lost.

## Root Cause
**Bug in `EncodeRDataAAAA()` function** ([dns/dns.go](dns/dns.go#L580-L600))

The function loses the last DNS record chunk when the payload size is not a multiple of 15 bytes.

### Why It Fails
The last AAAA record was appended AFTER checking if remaining data was less than 15 bytes, causing it to be skipped:

```go
// BEFORE (buggy)
for len(p) > 0 {
    // ... create record ...
    if len(p) < 15 {
        break  // ← Breaks BEFORE appending last record!
    }
    records = append(records, record)  // ← Only reached if len(p) >= 15
}

// AFTER (fixed)
for len(p) > 0 {
    // ... create record ...
    records = append(records, record)  // ← Now always appended
    if len(p) < 15 {
        break
    }
}
```

### Example Failure
- **Input:** 16 bytes of data
- **Expected:** 2 AAAA records (0-14 bytes, then 15)
- **Bug behavior:** 1 AAAA record (0-14 bytes), byte 15 is lost ❌
- **Fixed behavior:** 2 AAAA records, all data preserved ✓

## Fixes Applied

### 1. Code Fix ✓
**File:** [dns/dns.go](dns/dns.go#L596)  
**Change:** Moved `records.append(records, record)` to line 596 (before the break check)

### 2. Unit Tests Added ✓
**File:** [dns/dns_test.go](dns/dns_test.go#L664-L693)  
**Function:** `TestRDataAAAAEdgeCases()`

Tests comprehensive edge cases that previously failed:
- **1, 8, 14 bytes** - less than 15 (not enough for 1 full record)
- **16, 23, 31 bytes** - not multiples of 15
- **45, 100, 256, 1000 bytes** - larger payloads with remainder

Each test performs a round-trip encode/decode and verifies data integrity.

## Test Strategy

### Unit Tests (DNS Package)
Run DNS unit tests to verify the fix doesn't break existing functionality:

```bash
cd /workspaces/vaydns
go test -v ./dns
```

**Expected output:** 
- ✓ `TestEncodeRDataAAAA` - original tests still pass
- ✓ `TestDecodeRDataAAAA` - decoding works correctly  
- ✓ `TestRDataAAAARoundTrip` - round-trip tests pass
- ✓ `TestRDataAAAAEdgeCases` - NEW edge case tests pass

### Integration Tests (E2E)
The E2E tests verify full tunnel functionality with AAAA DNS records:

#### Quick Test (Tunnel Only)
```bash
cd /workspaces/vaydns/e2e/tunnel
bash run.sh
```
Tests: Client fetches a page through the DNS tunnel

#### All E2E Tests
```bash
cd /workspaces/vaydns/e2e
bash run-test.sh
```
Tests:
1. **tunnel/** - Basic tunnel functionality
2. **socks-download/** - SOCKS5 through tunnel with file download
3. **recovery/** - Connection recovery handling

### How E2E Tests Work
Each E2E test:
1. Starts Docker containers (server, client, upstream services)
2. Client sends data encoded in AAAA records through DNS tunnel
3. Server decodes AAAA records and proxies the connection
4. Tests verify end-to-end data integrity

The decode step uses `DecodeRDataAAAA()` and the encode step uses `EncodeRDataAAAA()`. If the encoding bug loses data, the tests will fail because data won't round-trip correctly.

## Verification Checklist

- [ ] Unit tests pass: `go test -v ./dns`
- [ ] Quick E2E test passes: `bash e2e/tunnel/run.sh`
- [ ] All E2E tests pass: `bash e2e/run-test.sh`
- [ ] Tunnel can handle various payload sizes (verified by connection logs)

## Data Flow with AAAA Records

```
Client Request:
  1. Create DNS Question with Type=AAAA
  2. Encode tunnel data in AAAA records using EncodeRDataAAAA()
  3. Send DNS query

Server Processing:
  4. Receive AAAA records
  5. Decode tunnel data using DecodeRDataAAAA()
  6. Establish proxy connection, forward traffic
  7. Encode response data using EncodeRDataAAAA()
  8. Send back in AAAA records

Client Response:
  9. Receive AAAA records
  10. Decode using DecodeRDataAAAA()
  11. Deliver to local socket
```

The bug was in step 7 and step 2 - if the encoded data lost the last chunk, the response wouldn't round-trip correctly.

## Files Changed
- [dns/dns.go](dns/dns.go#L596) - Fixed EncodeRDataAAAA()
- [dns/dns_test.go](dns/dns_test.go#L664-L693) - Added TestRDataAAAAEdgeCases()
