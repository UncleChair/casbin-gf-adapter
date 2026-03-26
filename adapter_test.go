package adapter

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/util"
	_ "github.com/gogf/gf/contrib/drivers/sqlite/v2"
	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/stretchr/testify/assert"
)

func setupSQLiteGroup(t *testing.T) string {
	t.Helper()

	groupName := fmt.Sprintf("sqlite_test_%d", time.Now().UnixNano())
	dbPath := filepath.Join(t.TempDir(), "casbin.sqlite3")
	link := fmt.Sprintf("sqlite::@file(%s)", filepath.ToSlash(dbPath))

	err := gdb.SetConfigGroup(groupName, gdb.ConfigGroup{
		{
			Type:   "sqlite",
			Link:   link,
			Prefix: "sys_",
			Debug:  false,
		},
	})
	assert.NoError(t, err)
	return groupName
}

// createPolicyTableForGroup is a helper for tests/migrations only.
// It creates the Casbin policy table if it doesn't exist.
func createPolicyTableForGroup(ctx context.Context, groupName string) error {
	db := g.DB(groupName)
	tableName := fmt.Sprintf("%s%s", db.GetPrefix(), defaultTableName)
	dbType := db.GetConfig().Type

	switch dbType {
	case "sqlite":
		// SQLite-friendly DDL:
		// - `id` uses AUTOINCREMENT to mimic MySQL's auto increment primary key.
		// - All policy tokens are stored as TEXT.
		_, err := db.Exec(ctx, fmt.Sprintf(
			"CREATE TABLE IF NOT EXISTS `%s` (`id` INTEGER PRIMARY KEY AUTOINCREMENT,`p_type` TEXT,`v0` TEXT,`v1` TEXT,`v2` TEXT,`v3` TEXT,`v4` TEXT,`v5` TEXT,`v6` TEXT,`v7` TEXT,UNIQUE (`p_type`,`v0`,`v1`,`v2`,`v3`,`v4`,`v5`,`v6`,`v7`))",
			tableName,
		))
		return err
	default:
		// Default to MySQL/MariaDB-like DDL.
		_, err := db.Exec(ctx, fmt.Sprintf(
			"CREATE TABLE IF NOT EXISTS %s (`id` bigint unsigned AUTO_INCREMENT,`p_type` VARCHAR(100),`v0` VARCHAR(100),`v1` VARCHAR(100),`v2` VARCHAR(100),`v3` VARCHAR(100),`v4` VARCHAR(100),`v5` VARCHAR(100), `v6` VARCHAR(25), `v7` VARCHAR(25),PRIMARY KEY (`id`),UNIQUE KEY `idx_%s` (`p_type`,`v0`,`v1`,`v2`,`v3`,`v4`,`v5`,`v6`,`v7`))",
			tableName, tableName,
		))
		return err
	}
}

func assertPolicy(t *testing.T, enforcer *casbin.Enforcer, want [][]string) {
	t.Helper()

	// Policy is a set semantically; DB engines may return rows in different orders.
	got, err := enforcer.GetPolicy()
	assert.NoError(t, err)
	assert.True(t, policiesEqualAsSet(got, want), "policy mismatch: got=%v want=%v", got, want)
}

func policiesEqualAsSet(got [][]string, want [][]string) bool {
	if len(got) != len(want) {
		return false
	}

	counts := make(map[string]int, len(got))
	for _, rule := range got {
		counts[util.ArrayToString(rule)]++
	}
	for _, rule := range want {
		key := util.ArrayToString(rule)
		if counts[key] == 0 {
			return false
		}
		counts[key]--
	}
	return true
}

func initPolicy(t *testing.T, adapter *Adapter) {
	t.Helper()

	// Because the DB is empty at first,
	// so we need to load the policy from the file adapter (.CSV) first.
	enforcer, err := casbin.NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	assert.NoError(t, err)

	// This is a trick to save the current policy to the DB.
	// We can't call e.SavePolicy() because the adapter in the enforcer is still the file adapter.
	// The current policy means the policy in the Casbin enforcer (aka in memory).
	err = adapter.SavePolicy(enforcer.GetModel())
	assert.NoError(t, err)

	// Clear the current policy.
	enforcer.ClearPolicy()
	assertPolicy(t, enforcer, [][]string{})

	// Load the policy from DB.
	err = adapter.LoadPolicy(enforcer.GetModel())
	assert.NoError(t, err)
	assertPolicy(t, enforcer, [][]string{{"chair", "dataA", "read"}, {"uncle", "dataB", "write"}, {"dataB_admin", "dataB", "read"}, {"dataB_admin", "dataB", "write"}})
}

func cleanPolicy(ctx context.Context, adapter *Adapter) {
	// Clear the current policy.
	if adapter.tableName != "" {
		_, _ = adapter.db.Model(adapter.tableName).Safe().Where("1=1").Ctx(ctx).Delete()
	}
}

func testSaveLoad(t *testing.T, adapter *Adapter) {
	// Initialize some policy in DB.
	initPolicy(t, adapter)
	// Note: you don't need to look at the above code
	// if you already have a working DB with policy inside.

	// Now the DB has policy, so we can provide a normal use case.
	// Create an adapter and an enforcer.
	// NewEnforcer() will load the policy automatically.
	enforcer, err := casbin.NewEnforcer("examples/rbac_model.conf", adapter)
	assert.NoError(t, err)
	assertPolicy(t, enforcer, [][]string{{"chair", "dataA", "read"}, {"uncle", "dataB", "write"}, {"dataB_admin", "dataB", "read"}, {"dataB_admin", "dataB", "write"}})
}

func initAdapter(t *testing.T, ctx context.Context, groupName string) *Adapter {
	t.Helper()

	// NewAdapter in strict mode requires the policy table to exist.
	err := createPolicyTableForGroup(ctx, groupName)
	assert.NoError(t, err)

	a, err := NewAdapter(ctx, groupName)
	assert.NoError(t, err)
	t.Cleanup(func() {
		_ = a.db.Close(ctx)
	})
	// Initialize some policy in DB.
	initPolicy(t, a)
	// Now the DB has policy, so we can provide a normal use case.
	// Note: you don't need to look at the above code
	// if you already have a working DB with policy inside.

	return a
}

func TestNilField(t *testing.T) {
	ctx := context.Background()
	groupName := setupSQLiteGroup(t)
	err := createPolicyTableForGroup(ctx, groupName)
	assert.NoError(t, err)

	a, err := NewAdapter(ctx, groupName)
	assert.NoError(t, err)
	t.Cleanup(func() {
		_ = a.db.Close(ctx)
	})

	e, err := casbin.NewEnforcer("examples/rbac_model.conf", a)
	assert.NoError(t, err)
	e.EnableAutoSave(false)

	ok, err := e.AddPolicy("", "dataA", "write")
	assert.NoError(t, err)
	assert.True(t, ok)
	_ = e.SavePolicy()
	assert.NoError(t, e.LoadPolicy())

	ok, err = e.Enforce("", "dataA", "write")
	assert.NoError(t, err)
	assert.True(t, ok)
}

func testAutoSave(t *testing.T, adapter *Adapter) {

	// NewEnforcer() will load the policy automatically.
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", adapter)
	assert.NoError(t, err)
	// AutoSave is enabled by default.
	// Now we disable it.
	e.EnableAutoSave(false)

	// Because AutoSave is disabled, the policy change only affects the policy in Casbin enforcer,
	// it doesn't affect the policy in the storage.
	e.AddPolicy("chair", "dataA", "write")
	// Reload the policy from the storage to see the effect.
	e.LoadPolicy()
	// This is still the original policy.
	assertPolicy(t, e, [][]string{{"chair", "dataA", "read"}, {"uncle", "dataB", "write"}, {"dataB_admin", "dataB", "read"}, {"dataB_admin", "dataB", "write"}})

	// Now we enable the AutoSave.
	e.EnableAutoSave(true)

	// Because AutoSave is enabled, the policy change not only affects the policy in Casbin enforcer,
	// but also affects the policy in the storage.
	e.AddPolicy("chair", "dataA", "write")
	// Reload the policy from the storage to see the effect.
	e.LoadPolicy()
	// The policy has a new rule: {"chair", "dataA", "write"}.
	assertPolicy(t, e, [][]string{{"chair", "dataA", "read"}, {"uncle", "dataB", "write"}, {"dataB_admin", "dataB", "read"}, {"dataB_admin", "dataB", "write"}, {"chair", "dataA", "write"}})

	// Remove the added rule.
	e.RemovePolicy("chair", "dataA", "write")
	e.LoadPolicy()
	assertPolicy(t, e, [][]string{{"chair", "dataA", "read"}, {"uncle", "dataB", "write"}, {"dataB_admin", "dataB", "read"}, {"dataB_admin", "dataB", "write"}})

	// Remove "dataB_admin" related policy rules via a filter.
	// Two rules: {"dataB_admin", "dataB", "read"}, {"dataB_admin", "dataB", "write"} are deleted.
	e.RemoveFilteredPolicy(0, "dataB_admin")
	e.LoadPolicy()
	assertPolicy(t, e, [][]string{{"chair", "dataA", "read"}, {"uncle", "dataB", "write"}})
}

func testFilteredPolicy(t *testing.T, adapter *Adapter) {
	// NewEnforcer() without an adapter will not auto load the policy
	e, err := casbin.NewEnforcer("examples/rbac_model.conf")
	assert.NoError(t, err)
	// Now set the adapter
	e.SetAdapter(adapter)

	// Load only chair's policies
	assert.NoError(t, e.LoadFilteredPolicy(Filter{V0: []string{"chair"}}))
	assertPolicy(t, e, [][]string{{"chair", "dataA", "read"}})

	// Load only uncle's policies
	assert.NoError(t, e.LoadFilteredPolicy(Filter{V0: []string{"uncle"}}))
	assertPolicy(t, e, [][]string{{"uncle", "dataB", "write"}})

	// Load policies for dataB_admin
	assert.NoError(t, e.LoadFilteredPolicy(Filter{V0: []string{"dataB_admin"}}))
	assertPolicy(t, e, [][]string{{"dataB_admin", "dataB", "read"}, {"dataB_admin", "dataB", "write"}})

	// Load policies for chair and uncle
	assert.NoError(t, e.LoadFilteredPolicy(Filter{V0: []string{"chair", "uncle"}}))
	assertPolicy(t, e, [][]string{{"chair", "dataA", "read"}, {"uncle", "dataB", "write"}})
}

func testUpdatePolicy(t *testing.T, adapter *Adapter) {
	// NewEnforcer() will load the policy automatically.
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", adapter)
	assert.NoError(t, err)

	e.EnableAutoSave(true)
	e.UpdatePolicy([]string{"chair", "dataA", "read"}, []string{"chair", "dataA", "write"})
	e.LoadPolicy()
	assertPolicy(t, e, [][]string{{"chair", "dataA", "write"}, {"uncle", "dataB", "write"}, {"dataB_admin", "dataB", "read"}, {"dataB_admin", "dataB", "write"}})
}

func testUpdatePolicies(t *testing.T, adapter *Adapter) {
	// NewEnforcer() will load the policy automatically.
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", adapter)
	assert.NoError(t, err)

	e.EnableAutoSave(true)
	e.UpdatePolicies([][]string{
		{"chair", "dataA", "write"},
		{"uncle", "dataB", "write"},
	}, [][]string{
		{"chair", "dataA", "read"},
		{"uncle", "dataB", "read"},
	})
	e.LoadPolicy()
	assertPolicy(t, e, [][]string{
		{"chair", "dataA", "read"},
		{"uncle", "dataB", "read"},
		{"dataB_admin", "dataB", "read"},
		{"dataB_admin", "dataB", "write"},
	})
}

func testUpdateFilteredPolicies(t *testing.T, adapter *Adapter) {
	// NewEnforcer() will load the policy automatically.
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", adapter)
	assert.NoError(t, err)

	e.EnableAutoSave(true)
	e.UpdateFilteredPolicies([][]string{{"chair", "dataA", "write"}}, 0, "chair", "dataA", "read")
	e.UpdateFilteredPolicies([][]string{{"uncle", "dataB", "read"}}, 0, "uncle", "dataB", "write")
	e.LoadPolicy()
	assertPolicy(t, e, [][]string{{"chair", "dataA", "write"}, {"dataB_admin", "dataB", "read"}, {"dataB_admin", "dataB", "write"}, {"uncle", "dataB", "read"}})
}

func TestAdapters(t *testing.T) {
	ctx := context.Background()
	groupName := setupSQLiteGroup(t)
	adapter := initAdapter(t, ctx, groupName)
	testAutoSave(t, adapter)
	testSaveLoad(t, adapter)
	testFilteredPolicy(t, adapter)
	testUpdatePolicy(t, adapter)
	testUpdatePolicies(t, adapter)
	testUpdateFilteredPolicies(t, adapter)
	cleanPolicy(ctx, adapter)
}

func TestAddPolicies(t *testing.T) {
	ctx := context.Background()
	groupName := setupSQLiteGroup(t)
	adapter := initAdapter(t, ctx, groupName)
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", adapter)
	assert.NoError(t, err)
	_, err = e.AddPolicies([][]string{
		{"hacker", "dataA", "read"},
		{"jack2", "dataA", "read"},
	})
	assert.NoError(t, err)
	err = e.LoadPolicy()
	assert.NoError(t, err)

	assertPolicy(t, e, [][]string{
		{"chair", "dataA", "read"},
		{"uncle", "dataB", "write"},
		{"dataB_admin", "dataB", "read"},
		{"dataB_admin", "dataB", "write"},
		{"hacker", "dataA", "read"},
		{"jack2", "dataA", "read"},
	})
	cleanPolicy(ctx, adapter)
}

func TestAddPoliciesFullColumn(t *testing.T) {
	ctx := context.Background()
	groupName := setupSQLiteGroup(t)
	adapter := initAdapter(t, ctx, groupName)
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", adapter)
	assert.NoError(t, err)
	_, err = e.AddPolicies([][]string{
		{"hacker", "dataA", "read", "col3", "col4", "col5", "col6", "col7"},
		{"jack2", "dataA", "read", "col3", "col4", "col5", "col6", "col7"},
	})
	assert.NoError(t, err)
	err = adapter.LoadPolicy(e.GetModel())
	assert.NoError(t, err)
	assertPolicy(t, e, [][]string{
		{"chair", "dataA", "read"},
		{"uncle", "dataB", "write"},
		{"dataB_admin", "dataB", "read"},
		{"dataB_admin", "dataB", "write"},
		{"hacker", "dataA", "read", "col3", "col4", "col5", "col6", "col7"},
		{"jack2", "dataA", "read", "col3", "col4", "col5", "col6", "col7"},
	})
	cleanPolicy(ctx, adapter)
}

func TestCasbinRuleTableName(t *testing.T) {
	var r CasbinRule
	assert.Equal(t, defaultTableName, r.TableName())
}

func TestNewAdapterTableNotFound(t *testing.T) {
	ctx := context.Background()
	groupName := setupSQLiteGroup(t)
	// NewAdapter() is expected to fail (policy table not found), but it may still open a DB connection.
	// Ensure the connection is closed to avoid sqlite file lock issues during TempDir cleanup.
	defer func() {
		_ = g.DB(groupName).Close(ctx)
	}()

	var panicVal any
	func() {
		defer func() {
			panicVal = recover()
		}()
		_, _ = NewAdapter(ctx, groupName)
	}()
	assert.NotNil(t, panicVal)
	assert.True(t, strings.Contains(fmt.Sprint(panicVal), "casbin policy table not found"))
}

func TestLoadFilteredPolicyInvalidFilter(t *testing.T) {
	ctx := context.Background()
	groupName := setupSQLiteGroup(t)
	adapter := initAdapter(t, ctx, groupName)

	e, err := casbin.NewEnforcer("examples/rbac_model.conf")
	assert.NoError(t, err)

	// This should fail early due to invalid filter type.
	err = adapter.LoadFilteredPolicy(e.GetModel(), "not-a-Filter")
	assert.Error(t, err)
}

func TestLoadFilteredPolicyByOtherFields(t *testing.T) {
	ctx := context.Background()
	groupName := setupSQLiteGroup(t)
	adapter := initAdapter(t, ctx, groupName)

	// NewEnforcer() without an adapter will not auto load the policy.
	e, err := casbin.NewEnforcer("examples/rbac_model.conf")
	assert.NoError(t, err)
	e.SetAdapter(adapter)

	// Filter by act (V2).
	assert.NoError(t, e.LoadFilteredPolicy(Filter{V2: []string{"read"}}))
	assertPolicy(t, e, [][]string{{"chair", "dataA", "read"}, {"dataB_admin", "dataB", "read"}})

	// Filter by obj (V1).
	assert.NoError(t, e.LoadFilteredPolicy(Filter{V1: []string{"dataB"}}))
	assertPolicy(t, e, [][]string{{"uncle", "dataB", "write"}, {"dataB_admin", "dataB", "read"}, {"dataB_admin", "dataB", "write"}})

	// Filter by multiple fields.
	assert.NoError(t, e.LoadFilteredPolicy(Filter{V0: []string{"dataB_admin"}, V2: []string{"write"}}))
	assertPolicy(t, e, [][]string{{"dataB_admin", "dataB", "write"}})
}

func TestLoadPolicyLineEmptyTokens(t *testing.T) {
	// When ptype + tokens are all empty, toStringPolicy() should return []string{},
	// and loadPolicyLine() must do nothing.
	e, err := casbin.NewEnforcer("examples/rbac_model.conf")
	assert.NoError(t, err)

	policy, err := e.GetPolicy()
	assert.NoError(t, err)
	assert.Len(t, policy, 0)
	loadPolicyLine(CasbinRule{}, e.GetModel())
	policy, err = e.GetPolicy()
	assert.NoError(t, err)
	assert.Len(t, policy, 0)
}

func TestInsertPolicyLinesEmpty(t *testing.T) {
	ctx := context.Background()
	groupName := setupSQLiteGroup(t)
	adapter := initAdapter(t, ctx, groupName)

	err := adapter.db.Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		// insertPolicyLines() should return nil without touching tx when lines is empty.
		return insertPolicyLines(ctx, tx, adapter.tableName, nil)
	})
	assert.NoError(t, err)
}

func TestTruncateTable(t *testing.T) {
	ctx := context.Background()
	groupName := setupSQLiteGroup(t)
	adapter := initAdapter(t, ctx, groupName)

	e, err := casbin.NewEnforcer("examples/rbac_model.conf", adapter)
	assert.NoError(t, err)

	// Sanity check initial policy.
	assertPolicy(t, e, [][]string{{"chair", "dataA", "read"}, {"uncle", "dataB", "write"}, {"dataB_admin", "dataB", "read"}, {"dataB_admin", "dataB", "write"}})

	// SQLite typically doesn't support TRUNCATE TABLE; depending on the driver it may fail.
	truncErr := adapter.truncateTable()
	err = e.LoadPolicy()
	assert.NoError(t, err)

	policy, err := e.GetPolicy()
	assert.NoError(t, err)
	if truncErr == nil {
		// If TRUNCATE succeeded, policy should be empty.
		assert.Len(t, policy, 0)
	} else {
		// If TRUNCATE failed, policy should remain unchanged.
		assertPolicy(t, e, [][]string{{"chair", "dataA", "read"}, {"uncle", "dataB", "write"}, {"dataB_admin", "dataB", "read"}, {"dataB_admin", "dataB", "write"}})
	}
}

func TestRemovePolicies(t *testing.T) {
	ctx := context.Background()
	groupName := setupSQLiteGroup(t)
	adapter := initAdapter(t, ctx, groupName)

	e, err := casbin.NewEnforcer("examples/rbac_model.conf", adapter)
	assert.NoError(t, err)

	// Remove two rules at once (Casbin should route to Adapter.RemovePolicies()).
	err = adapter.RemovePolicies("", "p", [][]string{
		{"chair", "dataA", "read"},
		{"dataB_admin", "dataB", "read"},
	})
	assert.NoError(t, err)

	assert.NoError(t, e.LoadPolicy())
	assertPolicy(t, e, [][]string{
		{"uncle", "dataB", "write"},
		{"dataB_admin", "dataB", "write"},
	})
	cleanPolicy(ctx, adapter)
}

func TestAddPoliciesEmpty(t *testing.T) {
	ctx := context.Background()
	groupName := setupSQLiteGroup(t)
	adapter := initAdapter(t, ctx, groupName)

	err := adapter.AddPolicies("", "p", [][]string{})
	assert.NoError(t, err)
	cleanPolicy(ctx, adapter)
}

func TestUpdatePoliciesLengthMismatch(t *testing.T) {
	ctx := context.Background()
	groupName := setupSQLiteGroup(t)
	adapter := initAdapter(t, ctx, groupName)

	err := adapter.UpdatePolicies("", "p",
		[][]string{{"chair", "dataA", "read"}},
		[][]string{{"chair", "dataA", "write"}, {"uncle", "dataB", "write"}},
	)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "oldRules and newRules length mismatch"))
	cleanPolicy(ctx, adapter)
}

func TestFilteredQueryStringOutOfRange(t *testing.T) {
	var a *Adapter

	whereSQL, whereArgs := a.filteredQueryString("p", 8, []string{"x"})
	assert.Equal(t, "p_type = ?", whereSQL)
	assert.Len(t, whereArgs, 1)
	assert.Equal(t, "p", whereArgs[0])
}

func TestUpdateFilteredPoliciesEmptyNewPolicies(t *testing.T) {
	ctx := context.Background()
	groupName := setupSQLiteGroup(t)
	adapter := initAdapter(t, ctx, groupName)

	e, err := casbin.NewEnforcer("examples/rbac_model.conf", adapter)
	assert.NoError(t, err)

	deleted, err := adapter.UpdateFilteredPolicies("", "p", nil /* newPolicies */, 0 /* fieldIndex */, "chair")
	assert.NoError(t, err)
	assert.Len(t, deleted, 1)

	assert.NoError(t, e.LoadPolicy())
	assertPolicy(t, e, [][]string{
		{"uncle", "dataB", "write"},
		{"dataB_admin", "dataB", "read"},
		{"dataB_admin", "dataB", "write"},
	})
	cleanPolicy(ctx, adapter)
}
