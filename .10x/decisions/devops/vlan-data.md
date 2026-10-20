# DevOps: vlan-data
Library/CLI change, no deployment pipeline touched. Rollout: consumers must delete and re-import databases (user_version gate). Rollback: revert commit; old importer cannot read v1 DBs' extra columns but ignores them. CI note: `go test ./...` is red on HEAD (pre-existing failures listed in qa).
