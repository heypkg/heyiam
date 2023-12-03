package iam

import (
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

var defaultServer *IAMServer
var defaultServerMutex sync.Mutex

func Setup(db *gorm.DB, dataRetentionPeriod time.Duration,
	enforcerDriverName string, enforcerDataSourceName string, rules map[string]ApiRule) {
	defaultServerMutex.Lock()
	defer defaultServerMutex.Unlock()
	defaultServer = NewIAMServer(db, dataRetentionPeriod, enforcerDriverName, enforcerDataSourceName, rules)
}

// @title IAM API
// @version 1.0
// @host dev.netdoop.com
// @BasePath /api/v1
// @schemes http
// @securityDefinitions.apikey Bearer
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.
func SetupEchoGroup(group *echo.Group) *echo.Group {
	return getDefaultServer().SetupEchoGroup(group)
}

func getDefaultServer() *IAMServer {
	return defaultServer
}

func SetupAdmin(schema string, password string) error {
	return getDefaultServer().SetupAdmin(schema, password)
}

func CreateUser(schema, name string, alias string, password string) (*User, error) {
	return getDefaultServer().CreateUser(schema, name, alias, password)
}

func CreateDefaultUser(db *gorm.DB, schema, name string, alias string, password string) (*User, error) {
	return getDefaultServer().CreateDefaultUser(schema, name, alias, password)
}

func CreateRole(db *gorm.DB, schema string, name string, alias string, patterns []string) (*Role, error) {
	return getDefaultServer().CreateRole(schema, name, alias, patterns)
}

func CreateDefaultRole(db *gorm.DB, schema string, name string, alias string, patterns []string) (*Role, error) {
	return getDefaultServer().CreateDefaultRole(schema, name, alias, patterns)
}
