package adapter

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/frame/g"
)

const (
	defaultTableName = "casbin_rule"
	flushEvery       = 1000
)

type CasbinRule struct {
	// ID should be omitted (NULL) on insert so that the DB can auto-generate it.
	// Using a pointer allows the default value to be nil.
	ID    *uint  `orm:"id" json:"id"`
	PType string `orm:"p_type" json:"p_type"`
	V0    string `orm:"v0" json:"v0"`
	V1    string `orm:"v1" json:"v1"`
	V2    string `orm:"v2" json:"v2"`
	V3    string `orm:"v3" json:"v3"`
	V4    string `orm:"v4" json:"v4"`
	V5    string `orm:"v5" json:"v5"`
	V6    string `orm:"v6" json:"v6"`
	V7    string `orm:"v7" json:"v7"`
}

func (CasbinRule) TableName() string {
	return defaultTableName
}

func (c *CasbinRule) toStringPolicy() []string {
	// Trim only trailing empty tokens, but preserve empty tokens in the middle.
	// This is important for Casbin rules where some fields can be empty strings.
	tokens := []string{c.PType, c.V0, c.V1, c.V2, c.V3, c.V4, c.V5, c.V6, c.V7}
	last := len(tokens) - 1
	for last >= 0 && tokens[last] == "" {
		last--
	}
	if last < 0 {
		return []string{}
	}
	return tokens[:last+1]
}

type Filter struct {
	PType []string
	V0    []string
	V1    []string
	V2    []string
	V3    []string
	V4    []string
	V5    []string
	V6    []string
	V7    []string
}

// Adapter represents the Gorm adapter for policy store.
type Adapter struct {
	dbGroupName string
	tableName   string
	db          gdb.DB
	ctx         context.Context
	isFiltered  bool
}

// NewAdapter is the constructor for Adapter.
func NewAdapter(ctx context.Context, groupName string) (*Adapter, error) {
	a := &Adapter{
		dbGroupName: groupName,
		tableName:   defaultTableName,
		ctx:         ctx,
	}
	// Open the DB and ensure the policy table exists.
	if err := a.open(); err != nil {
		return nil, err
	}

	return a, nil
}

func (a *Adapter) open() error {
	a.db = g.DB(a.dbGroupName)
	a.tableName = fmt.Sprintf("%s%s", a.db.GetPrefix(), a.tableName)
	return a.createTable()
}

// HasTable determine whether the table name exists in the database.
func (a *Adapter) HasTable(name string) (bool, error) {
	tableList, err := a.db.Tables(a.ctx)
	if err != nil {
		return false, err
	}
	for _, table := range tableList {
		if table == name {
			return true, nil
		}
	}
	return false, nil
}

func (a *Adapter) createTable() error {
	// Strict mode:
	// - Do not auto-create the policy table.
	// - If the table does not exist, return an error so that misconfiguration is detected early.
	exists, err := a.HasTable(a.tableName)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("casbin policy table not found: %s", a.tableName)
	}
	return nil
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

func (a *Adapter) truncateTable() error {
	_, err := a.db.Exec(a.ctx, fmt.Sprintf("TRUNCATE TABLE %s", a.tableName))
	return err
}

func loadPolicyLine(line CasbinRule, model model.Model) {
	tokens := (&line).toStringPolicy()
	if len(tokens) == 0 {
		return
	}
	persist.LoadPolicyArray(tokens, model)
}

// LoadPolicy loads policy from database.
func (a *Adapter) LoadPolicy(model model.Model) error {
	// Reset filtered state when doing a full load.
	a.isFiltered = false
	var lines []CasbinRule
	// Policy does not need ordering; DB may return rows in different orders.
	if err := a.db.Model(a.tableName).Ctx(a.ctx).Scan(&lines); err != nil {
		return err
	}
	for _, line := range lines {
		loadPolicyLine(line, model)
	}

	return nil
}

// LoadFilteredPolicy loads only policy rules that match the filter.
func (a *Adapter) LoadFilteredPolicy(model model.Model, filter any) error {
	var lines []CasbinRule

	filterValue, ok := filter.(Filter)
	if !ok {
		return errors.New("invalid filter type")
	}
	db := a.db.Model(a.tableName).Safe().Ctx(a.ctx)
	if len(filterValue.PType) > 0 {
		db = db.WhereIn("p_type", filterValue.PType)
	}
	if len(filterValue.V0) > 0 {
		db = db.WhereIn("v0", filterValue.V0)
	}
	if len(filterValue.V1) > 0 {
		db = db.WhereIn("v1", filterValue.V1)
	}
	if len(filterValue.V2) > 0 {
		db = db.WhereIn("v2", filterValue.V2)
	}
	if len(filterValue.V3) > 0 {
		db = db.WhereIn("v3", filterValue.V3)
	}
	if len(filterValue.V4) > 0 {
		db = db.WhereIn("v4", filterValue.V4)
	}
	if len(filterValue.V5) > 0 {
		db = db.WhereIn("v5", filterValue.V5)
	}
	if len(filterValue.V6) > 0 {
		db = db.WhereIn("v6", filterValue.V6)
	}
	if len(filterValue.V7) > 0 {
		db = db.WhereIn("v7", filterValue.V7)
	}
	// Policy does not need ordering; DB may return rows in different orders.
	if err := db.Scan(&lines); err != nil {
		return err
	}

	for _, line := range lines {
		loadPolicyLine(line, model)
	}
	a.isFiltered = true

	return nil
}

// IsFiltered returns true if the loaded policy has been filtered.
func (a *Adapter) IsFiltered() bool {
	return a.isFiltered
}

func (a *Adapter) savePolicyLine(ptype string, rule []string) CasbinRule {
	line := CasbinRule{PType: ptype}
	if len(rule) > 0 {
		line.V0 = rule[0]
	}
	if len(rule) > 1 {
		line.V1 = rule[1]
	}
	if len(rule) > 2 {
		line.V2 = rule[2]
	}
	if len(rule) > 3 {
		line.V3 = rule[3]
	}
	if len(rule) > 4 {
		line.V4 = rule[4]
	}
	if len(rule) > 5 {
		line.V5 = rule[5]
	}
	if len(rule) > 6 {
		line.V6 = rule[6]
	}
	if len(rule) > 7 {
		line.V7 = rule[7]
	}

	return line
}

func insertPolicyLines(ctx context.Context, tx gdb.TX, tableName string, lines []CasbinRule) error {
	if len(lines) == 0 {
		return nil
	}
	_, err := tx.Model(tableName).Data(&lines).Ctx(ctx).Insert()
	return err
}

// SavePolicy saves policy to database.
func (a *Adapter) SavePolicy(model model.Model) error {
	// SavePolicy should be atomic and compatible with multiple DB dialects.
	// Using `TRUNCATE TABLE` breaks on some databases (e.g. sqlite), so we use:
	// - Transaction
	// - DELETE WHERE 1=1
	// - Batch INSERT
	return a.db.Transaction(a.ctx, func(ctx context.Context, tx gdb.TX) error {
		// Delete all existing policy records.
		if _, err := tx.Model(a.tableName).Safe().Where("1=1").Delete(); err != nil {
			return err
		}

		pending := make([]CasbinRule, 0, flushEvery)
		flush := func() error {
			if err := insertPolicyLines(ctx, tx, a.tableName, pending); err != nil {
				return err
			}
			pending = pending[:0]
			return nil
		}

		for ptype, assertion := range model["p"] {
			for _, rule := range assertion.Policy {
				pending = append(pending, a.savePolicyLine(ptype, rule))
				if len(pending) >= flushEvery {
					if err := flush(); err != nil {
						return err
					}
				}
			}
		}

		for ptype, assertion := range model["g"] {
			for _, rule := range assertion.Policy {
				pending = append(pending, a.savePolicyLine(ptype, rule))
				if len(pending) >= flushEvery {
					if err := flush(); err != nil {
						return err
					}
				}
			}
		}

		return flush()
	})
}

// AddPolicy adds a policy rule to the store.
func (a *Adapter) AddPolicy(_ string, ptype string, rule []string) error {
	line := a.savePolicyLine(ptype, rule)
	_, err := a.db.Model(a.tableName).Data(&line).Ctx(a.ctx).Insert()
	return err
}

// RemovePolicy removes a policy rule from the store.
func (a *Adapter) RemovePolicy(_ string, ptype string, rule []string) error {
	return a.db.Transaction(a.ctx, func(ctx context.Context, tx gdb.TX) error {
		return a.deleteByRule(tx, ptype, rule)
	})
}

// AddPolicies adds multiple policy rules to the store.
func (a *Adapter) AddPolicies(_ string, ptype string, rules [][]string) error {
	lines := make([]CasbinRule, 0, len(rules))
	for _, rule := range rules {
		lines = append(lines, a.savePolicyLine(ptype, rule))
	}
	if len(lines) == 0 {
		return nil
	}
	_, err := a.db.Model(a.tableName).Data(&lines).Ctx(a.ctx).Insert()
	return err
}

// RemovePolicies removes multiple policy rules from the store.
func (a *Adapter) RemovePolicies(_ string, ptype string, rules [][]string) error {
	return a.db.Transaction(a.ctx, func(ctx context.Context, tx gdb.TX) error {
		for _, rule := range rules {
			if err := a.deleteByRule(tx, ptype, rule); err != nil {
				return err
			}
		}
		return nil
	})
}

// RemoveFilteredPolicy removes policy rules that match the filter from the store.
func (a *Adapter) RemoveFilteredPolicy(_ string, ptype string, fieldIndex int, fieldValues ...string) error {
	whereSQL, whereArgs := a.filteredQueryString(ptype, fieldIndex, fieldValues)
	return a.db.Transaction(a.ctx, func(ctx context.Context, tx gdb.TX) error {
		_, err := tx.Model(a.tableName).Safe().Where(whereSQL, whereArgs...).Delete([]CasbinRule{})
		return err
	})
}

func (a *Adapter) ruleCondition(ptype string, rule []string) gdb.Map {
	where := gdb.Map{"p_type": ptype}
	for i := 0; i < len(rule) && i < 8; i++ {
		// Include empty strings too: empty can be a valid token in Casbin.
		where[fmt.Sprintf("v%d", i)] = rule[i]
	}
	return where
}

func (a *Adapter) deleteByRule(tx gdb.TX, ptype string, rule []string) error {
	_, err := tx.Model(a.tableName).Safe().Delete(a.ruleCondition(ptype, rule))
	return err
}

func (a *Adapter) filteredQueryString(ptype string, fieldIndex int, fieldValues []string) (string, []any) {
	var b strings.Builder
	b.WriteString("p_type = ?")
	args := []any{ptype}
	for i, val := range fieldValues {
		colIndex := fieldIndex + i
		if colIndex < 0 || colIndex > 7 {
			continue
		}
		fmt.Fprintf(&b, " AND v%d = ?", colIndex)
		args = append(args, val)
	}
	return b.String(), args
}

// UpdatePolicy updates a new policy rule to DB.
func (a *Adapter) UpdatePolicy(_ string, ptype string, oldRule, newPolicy []string) error {
	return a.db.Transaction(a.ctx, func(ctx context.Context, tx gdb.TX) error {
		if err := a.deleteByRule(tx, ptype, oldRule); err != nil {
			return err
		}
		newLine := a.savePolicyLine(ptype, newPolicy)
		_, err := tx.Model(a.tableName).Data(&newLine).Ctx(ctx).Insert()
		return err
	})
}

func (a *Adapter) UpdatePolicies(_ string, ptype string, oldRules, newRules [][]string) error {
	if len(oldRules) != len(newRules) {
		return fmt.Errorf("UpdatePolicies: oldRules and newRules length mismatch: %d != %d", len(oldRules), len(newRules))
	}

	newPolicyLines := make([]CasbinRule, 0, len(newRules))
	for _, newRule := range newRules {
		newPolicyLines = append(newPolicyLines, a.savePolicyLine(ptype, newRule))
	}

	return a.db.Transaction(a.ctx, func(ctx context.Context, tx gdb.TX) error {
		for i := range oldRules {
			// Use delete+insert to guarantee empty-string token correctness.
			if err := a.deleteByRule(tx, ptype, oldRules[i]); err != nil {
				return err
			}
			if _, err := tx.Model(a.tableName).Data(&newPolicyLines[i]).Ctx(ctx).Insert(); err != nil {
				return err
			}
		}
		return nil
	})
}

func (a *Adapter) UpdateFilteredPolicies(_ string, ptype string, newPolicies [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	// UpdateFilteredPolicies deletes old rules and adds new rules.
	whereSQL, whereArgs := a.filteredQueryString(ptype, fieldIndex, fieldValues)

	var deleted []CasbinRule
	err := a.db.Transaction(a.ctx, func(ctx context.Context, tx gdb.TX) error {
		// 1) Load old policies once.
		if err := tx.Model(a.tableName).Where(whereSQL, whereArgs...).Scan(&deleted); err != nil {
			return err
		}

		// 2) Delete once.
		if _, err := tx.Model(a.tableName).Where(whereSQL, whereArgs...).Delete([]CasbinRule{}); err != nil {
			return err
		}

		// 3) Insert all new policies (if any).
		if len(newPolicies) == 0 {
			return nil
		}

		newRows := make([]CasbinRule, 0, len(newPolicies))
		for _, rule := range newPolicies {
			newRows = append(newRows, a.savePolicyLine(ptype, rule))
		}
		return insertPolicyLines(ctx, tx, a.tableName, newRows)
	})
	if err != nil {
		return nil, err
	}

	// Return deleted policies (for Casbin to update its in-memory model).
	deletedPolicies := make([][]string, 0, len(deleted))
	for i := range deleted {
		deletedPolicies = append(deletedPolicies, deleted[i].toStringPolicy())
	}
	return deletedPolicies, nil
}
