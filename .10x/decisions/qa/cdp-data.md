# QA: cdp-data
Report: reviews/2026-10-21-cdp-qa-report.md. Result: pass. Gates: `go test ./...` (only the 5 known iec62443 failures), `go vet`, `-race`, 20 s fuzz.
Bugs found and fixed: tagged CDP not decoded; untagged hostile CDP aborted the import.
Gap: no real-world CDP capture tested yet (frames are synthesized).
