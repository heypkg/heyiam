package iam

import (
	"sync"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/heypkg/store/echohandler"
	"github.com/heypkg/store/tsdb"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type IAMServer struct {
	logger      *zap.Logger
	secret      string
	db          *gorm.DB
	apiRulesMap map[string]ApiRule

	enforcerDriverName     string
	enforcerDataSourceName string
	e                      *casbin.Enforcer

	ignoreApiRuleIdsLock sync.RWMutex
	ignoreApiRuleIds     []string
}

func NewIAMServer(db *gorm.DB, dataRetentionPeriod time.Duration,
	enforcerDriverName string, enforcerDataSourceName string,
	secret string, rules map[string]ApiRule) *IAMServer {

	s := IAMServer{
		secret:      secret,
		logger:      zap.L().Named("iam"),
		db:          db,
		apiRulesMap: defaultApiRulesMap,
	}
	s.enforcerDriverName = enforcerDriverName
	s.enforcerDataSourceName = enforcerDataSourceName

	s.setup(dataRetentionPeriod)
	s.setupEnforcer()
	s.logger.Info("setup enforcer")

	s.setupApiRules(rules)
	s.logger.Info("setup rules")
	return &s
}

func (s *IAMServer) setup(dataRetentionPeriod time.Duration) {
	s.db.AutoMigrate(&Role{}, &User{})
	s.db.AutoMigrate(&AuditLog{})
	tsdb.CreateHyperTable(s.db, "audit_logs", dataRetentionPeriod)
	tsdb.CreateHyperTableCountView(s.db, "audit_logs", "audit_logs_hourly_view", "1h", AuditLogIndexNames)
	tsdb.CreateHyperTableCountView(s.db, "audit_logs", "audit_logs_daily_view", "1d", AuditLogIndexNames)
	tsdb.CreateHyperTableCountView(s.db, "audit_logs", "audit_logs_device_hourly_view", "1h", AuditLogUserIndexNames)
	tsdb.CreateHyperTableCountView(s.db, "audit_logs", "audit_logs_device_daily_view", "1d", AuditLogUserIndexNames)
}

func (s *IAMServer) GetDB() *gorm.DB {
	return s.db
}

func (s *IAMServer) SetupEchoGroup(group *echo.Group) *echo.Group {
	db := s.GetDB()
	meGroup := group.Group("/current")
	meGroup.GET("", s.HandleWhoAmI)
	meGroup.PUT("/change-password", s.HandleChangePassword)

	group.GET("/rules", s.HandleListApiRules)

	group.GET("/users", s.HandleListUsers)
	group.POST("/users", s.HandleCreateUser)
	group.DELETE("/users/:id", s.HandleDeleteUser, echohandler.ObjectHandler[User](db))
	group.GET("/users/:id", s.HandleGetUser, echohandler.ObjectHandler[User](db))
	group.PUT("/users/:id", s.HandleUpdateUser, echohandler.ObjectHandler[User](db))
	group.PUT("/users/:id/enable", s.HandleSetUserEnable, echohandler.ObjectHandler[User](db))
	group.PUT("/users/:id/disable", s.HandleSetUserDisable, echohandler.ObjectHandler[User](db))
	group.PUT("/users/:id/reset-password", s.HandleResetUserPassword, echohandler.ObjectHandler[User](db))
	group.PUT("/users/:id/change-password", s.HandleChangeUserPassword, echohandler.ObjectHandler[User](db))
	group.GET("/users/:id/roles", s.HandleGetUserRoles, echohandler.ObjectHandler[User](db))
	group.POST("/users/:id/roles", s.HandleAddUserRoles, echohandler.ObjectHandler[User](db))
	group.PUT("/users/:id/roles", s.HandleSetUserRoles, echohandler.ObjectHandler[User](db))

	group.GET("/roles", s.HandleListRoles)
	group.POST("/roles", s.HandleCreateRole)
	group.DELETE("/roles/:id", s.HandleDeleteRole, echohandler.ObjectHandler[Role](db))
	group.GET("/roles/:id", s.HandleGetRole, echohandler.ObjectHandler[Role](db))
	group.PUT("/roles/:id", s.HandleUpdateRole, echohandler.ObjectHandler[Role](db))
	group.PUT("/roles/:id/enable", s.HandleSetRoleEnable, echohandler.ObjectHandler[Role](db))
	group.PUT("/roles/:id/disable", s.HandleSetRoleDisable, echohandler.ObjectHandler[Role](db))
	group.PUT("/roles/:id/rules", s.HandleSetRoleApiRules, echohandler.ObjectHandler[Role](db))

	group.GET("/audit-logs", s.HandleListAuditLogs)
	group.GET("/audit-logs/:ts", s.HandleGetAuditLog, echohandler.TSObjectHandler[AuditLog](db))
	return group
}

func (s *IAMServer) SetupAdmin(schema string, password string) error {
	role, err := s.CreateDefaultRole(schema, "admin", "admin", []string{})
	if err != nil {
		return err
	}
	if _, err := s.AddApiRuleForRole(role.Schema, role.Name, ApiRule{Path: "*", Method: ".*"}); err != nil {
		return err
	}
	user, err := s.CreateDefaultUser(schema, "admin", "admin", password)
	if err != nil {
		return err
	}
	if _, err := s.AddRoleForUser(user.Schema, user.Name, role.Name); err != nil {
		return err
	}
	return nil
}
func (s *IAMServer) CreateUser(schema, name string, alias string, password string) (*User, error) {
	return s.createUser(schema, name, alias, password, false)
}

func (s *IAMServer) CreateDefaultUser(schema, name string, alias string, password string) (*User, error) {
	return s.createUser(schema, name, alias, password, true)
}

func (s *IAMServer) CreateRole(schema string, name string, alias string, patterns []string) (*Role, error) {
	return s.createRole(schema, name, alias, false, patterns)
}

func (s *IAMServer) CreateDefaultRole(schema string, name string, alias string, patterns []string) (*Role, error) {
	return s.createRole(schema, name, alias, true, patterns)
}

func (s *IAMServer) createUser(schema, name string, alias string, password string, isDefault bool) (*User, error) {
	user := new(User)
	user.Schema = schema
	user.Name = name
	user.Alias = alias
	user.Enable = true
	user.Default = isDefault
	user.SetPassword(password)
	if err := s.db.Where("schema = ? AND name = ?", schema, name).FirstOrCreate(user).Error; err != nil {
		return nil, errors.Wrap(err, "create user")
	}
	return user, nil
}

func (s *IAMServer) createRole(schema string, name string, alias string, isDefault bool, patterns []string) (*Role, error) {
	role := new(Role)
	role.Schema = schema
	role.Name = name
	role.Alias = alias
	role.Enable = true
	role.Default = isDefault
	if err := s.db.Where("schema = ? AND name = ?", schema, name).FirstOrCreate(role).Error; err != nil {
		return nil, errors.Wrap(err, "create role")
	}
	rules := s.GetApiRules(patterns...)
	if _, err := s.SetApiRulesForRole(role.Schema, role.Name, rules); err != nil {
		return nil, errors.Wrap(err, "set api rules for role")
	}
	return role, nil
}
