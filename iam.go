package iam

import (
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

var defaultServer *IAMServer
var defaultServerMutex sync.Mutex
var defaultSecret string = "heypkg2023!!"

func Setup(db *gorm.DB, dataRetentionPeriod time.Duration,
	enforcerDriverName string, enforcerDataSourceName string, secret string, rules map[string]ApiRule) {
	defaultServerMutex.Lock()
	defer defaultServerMutex.Unlock()
	defaultSecret = secret
	defaultServer = NewIAMServer(db, dataRetentionPeriod, enforcerDriverName, enforcerDataSourceName, rules)
}

func SetupEchoGroup(group *echo.Group) *echo.Group {
	return getDefaultServer().SetupEchoGroup(group)
}

func MakeJwtHandler() echo.MiddlewareFunc {
	return getDefaultServer().MakeJwtHandler()
}

func MakeLoginHandler() echo.MiddlewareFunc {
	return getDefaultServer().MakeAuditLogHandler()
}

func MakeAuditLogHandler() echo.MiddlewareFunc {
	return getDefaultServer().MakeAuditLogHandler()
}

func HandleAuthenticate(c echo.Context) error {
	return getDefaultServer().HandleAuthenticate(c)
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

func CreateDefaultUser(schema, name string, alias string, password string) (*User, error) {
	return getDefaultServer().CreateDefaultUser(schema, name, alias, password)
}

func CreateRole(schema string, name string, alias string, patterns []string) (*Role, error) {
	return getDefaultServer().CreateRole(schema, name, alias, patterns)
}

func CreateDefaultRole(schema string, name string, alias string, patterns []string) (*Role, error) {
	return getDefaultServer().CreateDefaultRole(schema, name, alias, patterns)
}

func AddRoleForUser(domain string, user string, role string) (bool, error) {
	return getDefaultServer().AddRoleForUser(domain, user, role)
}

func AddRolesForUser(domain string, user string, roles []string) (bool, error) {
	return getDefaultServer().AddRolesForUser(domain, user, roles)
}
