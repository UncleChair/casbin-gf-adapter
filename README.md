Gdb Adapter
====

Gdb Adapter is the goframe orm adapter for Casbin.

## Installation
    go get github.com/UncleChair/casbin-gf-adapter

## Quick Start

This project provides a Casbin adapter based on GoFrame's `gdb`. It stores Casbin policy rules into a single table and loads them back into Casbin's in-memory model.

### Prerequisites

1. Go modules enabled.
2. A working GoFrame `gdb` configuration with a database group (for example, `gdb.DefaultGroupName`).
3. The Casbin policy table already exists in the target database.

### Configure GoFrame `gdb`

Update `config/config.yaml` (or your own GoFrame config) to set:

- `database.<group>.link`: your DB connection string
- `database.<group>.prefix`: table name prefix (prefer `""` for this group so the physical table is `casbin_rule`, same as docs and `NewAdapter` defaults)
- `database.<group>.debug`: optional

The adapter uses the **base table name** `casbin_rule` (overridable via `NewAdapter`'s optional `tableName` argument). If your gdb group uses a non-empty prefix, migrate the physical table gdb expects (`<prefix>casbin_rule`); the adapter API still takes the base name only.

Columns: `id`, `p_type`, `v0`..`v7`

### Create the policy table (strict mode)

The adapter is in **strict mode**: it will **not** auto-create the table during `NewAdapter`.
If the table does not exist, `NewAdapter` returns an error.

Example (MySQL/MariaDB-style DDL; base table name `casbin_rule` when `prefix` is empty):

```sql
CREATE TABLE IF NOT EXISTS casbin_rule (
  id bigint unsigned AUTO_INCREMENT,
  p_type VARCHAR(100),
  v0 VARCHAR(100),
  v1 VARCHAR(100),
  v2 VARCHAR(100),
  v3 VARCHAR(100),
  v4 VARCHAR(100),
  v5 VARCHAR(100),
  v6 VARCHAR(25),
  v7 VARCHAR(25),
  PRIMARY KEY (id),
  UNIQUE KEY idx_casbin_rule (p_type, v0, v1, v2, v3, v4, v5, v6, v7)
);
```

## Simple Example

```go
package main

import (
	"context"
	"github.com/casbin/casbin/v2"
	_ "github.com/gogf/gf/contrib/drivers/mysql/v2"
	"github.com/gogf/gf/v2/database/gdb"
	gdbadapter "github.com/UncleChair/casbin-gf-adapter"
)

func main() {
	// Initialize a gdb adapter and use it in a Casbin enforcer:
	// The adapter will use the database source configured for the given gdb group.
	// (Use base table name casbin_rule; set gdb prefix to "" for that group unless you migrate <prefix>casbin_rule.)
	ctx := context.Background()
	a, err := gdbadapter.NewAdapter(ctx, gdb.DefaultGroupName)
	if err != nil {
		panic(err)
	}
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", a)
	if err != nil {
		panic(err)
	}

	// Load the policy from DB.
	if err := e.LoadPolicy(); err != nil {
		panic(err)
	}

	// Check the permission.
	// Pick a subject/object/action that exists in your policies.
	// See examples/rbac_policy.csv for the sample values.
	ok, err := e.Enforce("chair", "dataA", "read")
	if err != nil {
		panic(err)
	}
	_ = ok

	// Modify the policy.
	// e.AddPolicy(...)
	// e.RemovePolicy(...)

	// Save the policy back to DB.
	if err := e.SavePolicy(); err != nil {
		panic(err)
	}
}
```

### Notes

- `LoadPolicy()` loads all policy rules from the DB into the Casbin model.
- `SavePolicy()` persists the current in-memory model back to the DB.
- Auto-save depends on Casbin's `EnableAutoSave()` setting (enabled by default in Casbin).

## Getting Help

- [Casbin](https://github.com/casbin/casbin)
