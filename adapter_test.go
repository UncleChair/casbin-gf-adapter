package adapter

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/util"
	_ "github.com/gogf/gf/contrib/drivers/sqlite/v2"
	"github.com/gogf/gf/v2/database/gdb"
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
