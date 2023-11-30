package iam

import (
	"time"

	"github.com/heypkg/store/tsdb"
	"github.com/pkg/errors"
	"gorm.io/gorm"
)

func Setup(db *gorm.DB, dataRetentionPeriod time.Duration,
	enforcerDriverName string, enforcerDataSourceName string) {

	setupEnforcer(enforcerDriverName, enforcerDataSourceName)

	db.AutoMigrate(&Role{}, &User{})
	db.AutoMigrate(&AuditLog{})
	tsdb.CreateHyperTable(db, "audit_logs", dataRetentionPeriod)
	tsdb.CreateHyperTableCountView(db, "audit_logs", "audit_logs_hourly_view", "1h", AuditLogIndexNames)
	tsdb.CreateHyperTableCountView(db, "audit_logs", "audit_logs_daily_view", "1d", AuditLogIndexNames)
	tsdb.CreateHyperTableCountView(db, "audit_logs", "audit_logs_device_hourly_view", "1h", AuditLogUserIndexNames)
	tsdb.CreateHyperTableCountView(db, "audit_logs", "audit_logs_device_daily_view", "1d", AuditLogUserIndexNames)
}

func SetupAdmin(db *gorm.DB, schema string, password string) error {
	role, err := CreateDefaultRole(db, schema, "admin", "admin", []string{})
	if err != nil {
		return err
	}
	if _, err := AddApiRuleForRole(role.Schema, role.Name, ApiRule{Path: "*", Method: ".*"}); err != nil {
		return err
	}

	user, err := CreateDefaultUser(db, schema, "admin", "admin", password)
	if err != nil {
		return err
	}
	if _, err := AddRoleForUser(user.Schema, user.Name, role.Name); err != nil {
		return err
	}
	return nil
}

func createUser(db *gorm.DB, schema, name string, alias string, password string, isDefault bool) (*User, error) {
	user := new(User)
	user.Schema = schema
	user.Name = name
	user.Alias = alias
	user.Enable = true
	user.Default = isDefault

	user.SetPassword(password)
	if err := db.Where("schema = ? AND name = ?", schema, name).FirstOrCreate(user).Error; err != nil {
		return nil, errors.Wrap(err, "create user")
	}
	return user, nil
}
func CreateUser(db *gorm.DB, schema, name string, alias string, password string) (*User, error) {
	return createUser(db, schema, name, alias, password, false)
}

func CreateDefaultUser(db *gorm.DB, schema, name string, alias string, password string) (*User, error) {
	return createUser(db, schema, name, alias, password, true)
}

func createRole(db *gorm.DB, schema string, name string, alias string, isDefault bool, patterns []string) (*Role, error) {
	role := new(Role)
	role.Schema = schema
	role.Name = name
	role.Alias = alias
	role.Enable = true
	role.Default = isDefault
	if err := db.Where("schema = ? AND name = ?", schema, name).FirstOrCreate(role).Error; err != nil {
		return nil, errors.Wrap(err, "create role")
	}
	rules := GetApiRules(patterns...)
	if _, err := SetApiRulesForRole(role.Schema, role.Name, rules); err != nil {
		return nil, errors.Wrap(err, "set api rules for role")
	}
	return role, nil
}

func CreateRole(db *gorm.DB, schema string, name string, alias string, patterns []string) (*Role, error) {
	return createRole(db, schema, name, alias, false, patterns)
}

func CreateDefaultRole(db *gorm.DB, schema string, name string, alias string, patterns []string) (*Role, error) {
	return createRole(db, schema, name, alias, true, patterns)
}
