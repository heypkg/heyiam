package iam

import (
	"fmt"
	"strings"

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

func NewEnforcer(driverName string, dataSourceName string) (*casbin.Enforcer, error) {
	db, err := sqlx.Open(driverName, dataSourceName)
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

func (s *IAMServer) setupEnforcer() {
	e, err := NewEnforcer(s.enforcerDriverName, s.enforcerDataSourceName)
	if err != nil {
		s.logger.Fatal("create enforcer failed", zap.Error(err))
	}
	s.e = e
}

func (s *IAMServer) Enforce(dom string, sub string, obj string, act string) bool {
	ok, err := s.e.Enforce(sub, obj, act, dom)
	if err != nil {
		return false
	}
	return ok
}

func (s *IAMServer) EnforceApi(domain string, user string, path string, method string) bool {
	return s.Enforce(
		fmt.Sprintf("d:%v", domain),
		fmt.Sprintf("u:%v", user),
		fmt.Sprintf("p:%v", path),
		strings.ToUpper(method),
	)
}

func (s *IAMServer) GetRolesForUser(domain string, user string) ([]string, error) {
	roles := []string{}
	_roles, err := s.e.GetRolesForUser(fmt.Sprintf("u:%v", user), fmt.Sprintf("d:%v", domain))
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

func (s *IAMServer) DeleteAllRolesForUser(domain string, user string) (bool, error) {
	return s.e.DeleteRolesForUser(
		fmt.Sprintf("u:%v", user),
		fmt.Sprintf("d:%v", domain),
	)
}

func (s *IAMServer) AddRoleForUser(domain string, user string, role string) (bool, error) {
	return s.e.AddRoleForUser(
		fmt.Sprintf("u:%v", user),
		fmt.Sprintf("r:%v", role),
		fmt.Sprintf("d:%v", domain),
	)
}

func (s *IAMServer) AddRolesForUser(domain string, user string, roles []string) (bool, error) {
	_roles := []string{}
	for _, role := range roles {
		_roles = append(_roles, fmt.Sprintf("r:%v", role))
	}
	return s.e.AddRolesForUser(
		fmt.Sprintf("u:%v", user),
		_roles,
		fmt.Sprintf("d:%v", domain),
	)
}

func (s *IAMServer) SetRolesForUser(domain string, user string, roles []string) (bool, error) {
	s.DeleteAllRolesForUser(domain, user)
	return s.AddRolesForUser(domain, user, roles)
}
