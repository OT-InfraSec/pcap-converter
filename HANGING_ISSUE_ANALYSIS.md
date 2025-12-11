# PCAP Importer - Hanging Application Analysis

## Executive Summary

The pcap-importer application hangs indefinitely when processing PCAP files due to a **SQLite database locking deadlock** between the main packet processing thread and a background batch processing goroutine.

## Issue Reproduction

- **Command**: `./external-tests.sh` (run multiple times with 2-second timeout)
- **Symptoms**: Program times out consistently, with log indicating it stops after database initialization:
  ```
  2025/12/11 14:38:02 main.go:54: Clearing database at database.sqlite before import
  2025/12/11 14:38:03 main.go:71: Using database at database.sqlite
  [then hangs indefinitely...]
  ```

## Root Cause Analysis

### Problem Location
File: [internal/parser/gopacket_parser.go](internal/parser/gopacket_parser.go#L856-L1910)

### The Deadlock Scenario

The `ParseFile()` method creates a concurrent processing pattern with **database write contention**:

#### Main Thread (`ParseFile` loop) - Line 1759+:
```go
// Main loop processes packets from PCAP file
for packet := range packetSource.Packets() {
    // ... extensive packet analysis and layer parsing ...
    
    modelPacket := &model2.Packet{ /* ... */ }
    
    // SENDS TO CHANNEL (non-blocking, channel has 1000 buffer)
    packetChan <- modelPacket  // Line 1759
    
    // THEN IMMEDIATELY PERFORMS DATABASE WRITES (blocking operations)
    p.upsertDevice(srcIP, "IP", ...)          // Lines 1765-1770 - DB WRITE
    p.upsertDevice(dstIP, "IP", ...)          
    
    // Even more DB operations for industrial protocols:
    industrialProtocols, err := p.industrialParser.ParseIndustrialProtocols(...)
    // ... followed by:
    p.repo.SaveProtocolUsageStats(stats)      // Lines 1796, 1808 - DB WRITE
    
    p.updateFlow(...)                         // Line 1835 - DB WRITE
}
```

#### Worker Goroutine (Line 894-917):
```go
go func() {
    defer close(doneChan)
    batch := make([]*model2.Packet, 0, batchSize)
    
    for packet := range packetChan {
        batch = append(batch, packet)
        
        if len(batch) >= batchSize {
            // ATTEMPTS DATABASE WRITE
            if err := p.repo.UpsertPackets(batch); err != nil {  // DB WRITE
                errChan <- fmt.Errorf("failed to upsert packet batch: %w", err)
                return
            }
            batch = batch[:0]
        }
    }
    
    // Process remaining packets
    if len(batch) > 0 {
        if err := p.repo.UpsertPackets(batch); err != nil {    // DB WRITE
            errChan <- fmt.Errorf("failed to upsert final packet batch: %w", err)
        }
    }
}()
```

### Why the Deadlock Occurs

1. **Main thread acquires write lock**: While processing an industrialprotocol analysis, the main thread calls `p.repo.SaveProtocolUsageStats()` and `p.upsertDevice()`, acquiring SQLite's exclusive write lock.

2. **Worker goroutine blocks**: Meanwhile, the worker goroutine is trying to call `p.repo.UpsertPackets()`, which tries to acquire a write lock. SQLite serializes these, so the goroutine blocks waiting for the main thread to release its lock.

3. **Channel buffer fills**: The `packetChan` buffer is 1000 packets. Once filled, the main thread tries to send another packet (`packetChan <- modelPacket`), which **blocks** waiting for the goroutine to read from the channel.

4. **Deadlock**: 
   - Main thread: Holding write lock → Blocked on channel send (waiting for goroutine to read)
   - Goroutine: Blocked on database write (waiting for main thread to release lock)
   - Result: Both threads permanently blocked, application hangs

### Secondary Issue: Error Channel Not Being Read

Even if the goroutine encounters an error and sends to `errChan`, the error isn't immediately acted upon. The main thread waits with a `select` statement:
```go
select {
case err := <-errChan:
    return err
case <-doneChan:
    // Processing completed successfully
}
```

But if the goroutine is **blocked** during database operations and can never send to `errChan`, the main thread waits forever on `doneChan`.

## Affected Code Components

| Component | Issue |
|-----------|-------|
| [gopacket_parser.go Line 894-917](internal/parser/gopacket_parser.go#L894) | Worker goroutine with database operations |
| [gopacket_parser.go Line 1759-1835](internal/parser/gopacket_parser.go#L1759) | Main loop with interleaved database writes |
| [gopacket_parser.go Line 1845-1851](internal/parser/gopacket_parser.go#L1845) | Channel closure and blocking select statement |
| [internal/repository/sqlite_repository.go](internal/repository/sqlite_repository.go) | SQLite write operations (UpsertPackets, UpsertDevices, SaveProtocolUsageStats) |

## Why This is Hard to Debug

1. **Intermittent**: Depends on packet timing and database lock contention
2. **Race condition characteristics**: The hang happens when:
   - PCAP file has enough packets to fill the channel buffer (1000 packets)
   - Industrial protocol analysis takes enough time for channel to fill
   - Worker goroutine is performing database operations
3. **No error messages**: The application simply hangs silently; no error is printed

## Impact

- **Severity**: Critical - makes the application unusable with large PCAP files
- **Frequency**: Consistent (appears in 100% of test runs)
- **User Impact**: Application appears frozen, must be manually killed

## Recommended Remediation Strategy

The solution is to **decouple database operations** from the packet processing loop to eliminate concurrent database access:

### Option A: Deferred Database Operations (RECOMMENDED)
**Approach**: Collect device info and industrial protocol data in memory during packet processing, then perform all database writes **after** the main loop completes.

**Advantages**:
- Eliminates concurrent database access
- Cleaner separation of concerns
- Easier to understand and maintain
- Better performance (batch operations)

**Changes required**:
1. Move `p.upsertDevice()` calls out of main loop
2. Move `p.repo.SaveProtocolUsageStats()` calls out of main loop
3. Move `p.updateFlow()` calls out of main loop OR defer them
4. Remove the worker goroutine (unnecessary with this approach)
5. Collect device and flow data in maps/lists, then batch insert at the end

### Option B: Serialize All Database Operations
**Approach**: Keep the worker goroutine but ensure **no other thread** does database operations until the worker finishes.

**Disadvantages**:
- More complex locking
- Still potential for race conditions

### Option C: Use Connection Pool with Write Serialization
**Approach**: Implement connection pooling and explicit write serialization.

**Disadvantages**:
- Requires significant refactoring
- More infrastructure

## Next Steps (Pending Your Approval)

1. ✓ Document findings (this document)
2. Implement Option A (deferred database operations)
3. Test the fix with `./external-tests.sh` in a loop
4. Verify no data loss or corruption
5. Monitor performance implications

## Questions for Clarification

Before implementing the fix, I'd like to confirm:

1. **Performance priority**: Is it acceptable to batch all database operations at the end, or is incremental processing important?
2. **Memory constraints**: Are there memory constraints for large PCAP files (storing all devices/flows in memory)?
3. **Testing environment**: Can I run the test multiple times in sequence without issues after the fix?

---

**Analysis Date**: December 11, 2025
**Analyzed By**: GitHub Copilot
**Status**: Ready for remediation planning
