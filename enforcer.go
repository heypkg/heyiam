package iam

import (
	"fmt"
	"strings"
	"sync"

	sqlxadapter "github.com/Blank-Xu/sqlx-adapter"
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const modelString string = `
[request_definition]
r = sub, obj, act, dom

[policy_definition]
p = sub, obj, act, dom

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)
`

var defaultDriverName string
var defaultDataSourceName string
var defaultEnforcer *casbin.Enforcer
var defaultEnforcerOnce sync.Once

func setupEnforcer(driverName string, dataSourceName string) {
	defaultDriverName = driverName
	defaultDataSourceName = dataSourceName
}

func GetEnforcer() *casbin.Enforcer {
	defaultEnforcerOnce.Do(func() {
		var err error
		defaultEnforcer, err = NewEnforcer()
		if err != nil {
			zap.L().Fatal("create enforcer failed", zap.Error(err))
		}
	})
	return defaultEnforcer
}

func NewEnforcer() (*casbin.Enforcer, error) {
	db, err := sqlx.Open(defaultDriverName, defaultDataSourceName)
	if err != nil {
		return nil, errors.Wrap(err, "open database")
	}
	a, err := sqlxadapter.NewAdapter(db, "casbin_rule")
	if err != nil {
		return nil, errors.Wrap(err, "create adapter")
	}

	m, err := model.NewModelFromString(modelString)
	if err != nil {
		return nil, errors.Wrap(err, "import model")
	}

	e, err := casbin.NewEnforcer(m, a)
	if err != nil {
		return nil, errors.Wrap(err, "create enforcer")
	}

	e.LoadPolicy()
	e.EnableAutoSave(true)
	return e, nil
}

func Enforce(e *casbin.Enforcer, dom string, sub string, obj string, act string) bool {
	ok, err := e.Enforce(sub, obj, act, dom)
	if err != nil {
		return false
	}
	return ok
}

func EnforceApi(e *casbin.Enforcer, domain string, user string, path string, method string) bool {
	return Enforce(e,
		fmt.Sprintf("d:%v", domain),
		fmt.Sprintf("u:%v", user),
		fmt.Sprintf("p:%v", path),
		strings.ToUpper(method),
	)
}

func GetRolesForUser(e *casbin.Enforcer, domain string, user string) ([]string, error) {
	roles := []string{}
	_roles, err := e.GetRolesForUser(fmt.Sprintf("u:%v", user), fmt.Sprintf("d:%v", domain))
	if err != nil {
		return roles, err
	}
	for _, v := range _roles {
		if strings.HasPrefix(v, "r:") {
			roles = append(roles, v[2:])
		}
	}
	return roles, nil
}

func DeleteAllRolesForUser(e *casbin.Enforcer, domain string, user string) (bool, error) {
	return e.DeleteRolesForUser(
		fmt.Sprintf("u:%v", user),
		fmt.Sprintf("d:%v", domain),
	)
}

func AddRoleForUser(e *casbin.Enforcer, domain string, user string, role string) (bool, error) {
	return e.AddRoleForUser(
		fmt.Sprintf("u:%v", user),
		fmt.Sprintf("r:%v", role),
		fmt.Sprintf("d:%v", domain),
	)
}

func AddRolesForUser(e *casbin.Enforcer, domain string, user string, roles []string) (bool, error) {
	_roles := []string{}
	for _, role := range roles {
		_roles = append(_roles, fmt.Sprintf("r:%v", role))
	}
	return e.AddRolesForUser(
		fmt.Sprintf("u:%v", user),
		_roles,
		fmt.Sprintf("d:%v", domain),
	)
}

func SetRolesForUser(e *casbin.Enforcer, domain string, user string, roles []string) (bool, error) {
	DeleteAllRolesForUser(e, domain, user)
	return AddRolesForUser(e, domain, user, roles)
}
