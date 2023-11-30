package iam

import (
	"fmt"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/spf13/cast"
)

type ApiRule struct {
	Path   string `json:"Path"`
	Method string `json:"Method"`
}
type GroupRule struct {
	GroupId uint   `json:"GroupId"`
	Method  string `json:"Method"`
}

func GetApiRulesForRole(e *casbin.Enforcer, domain string, role string) []ApiRule {
	if role == "admin" {
		return getApiRules("*")
	}
	rules := []ApiRule{}
	polices := e.GetFilteredPolicy(0, fmt.Sprintf("r:%v", role), "", "", fmt.Sprintf("d:%v", domain))
	for _, v := range polices {
		if strings.HasPrefix(v[1], "p:") {
			rules = append(rules, ApiRule{Path: v[1][2:], Method: v[2]})
		}
	}
	return rules
}

func GetApiRulesForUser(e *casbin.Enforcer, domain string, user string) []ApiRule {
	rules := []ApiRule{}
	roles, _ := GetRolesForUser(e, domain, user)
	for _, role := range roles {
		_rules := GetApiRulesForRole(e, domain, role)
		rules = append(rules, _rules...)
	}
	return rules
}

func GetGroupRulesForRole(e *casbin.Enforcer, domain string, role string) []GroupRule {
	rules := []GroupRule{}
	polices := e.GetFilteredPolicy(0, fmt.Sprintf("r:%v", role), "", "", fmt.Sprintf("d:%v", domain))
	for _, v := range polices {
		if strings.HasPrefix(v[1], "g:") {
			rules = append(rules, GroupRule{GroupId: cast.ToUint(v[1][2:]), Method: v[2]})
		}
	}
	return rules
}

func DeleteAllApiRulesForRole(e *casbin.Enforcer, domain string, role string) (bool, error) {
	polices := [][]string{}
	_polices := e.GetFilteredPolicy(0, fmt.Sprintf("r:%v", role), "", "", fmt.Sprintf("d:%v", domain))
	for _, v := range _polices {
		if strings.HasPrefix(v[1], "p:") {
			polices = append(polices, v)
		}
	}
	return e.RemovePolicies(polices)
}

func DeleteAllGroupRulesForRole(e *casbin.Enforcer, domain string, role string) (bool, error) {
	polices := [][]string{}
	_polices := e.GetFilteredPolicy(0, fmt.Sprintf("r:%v", role), "", "", fmt.Sprintf("d:%v", domain))
	for _, v := range _polices {
		if strings.HasPrefix(v[1], "g:") {
			polices = append(polices, v)
		}
	}
	return e.RemovePolicies(polices)
}

func SetApiRulesForRole(e *casbin.Enforcer, domain string, role string, rules []ApiRule) (bool, error) {
	DeleteAllApiRulesForRole(e, domain, role)
	policies := [][]string{}
	for _, rule := range rules {
		policies = append(policies, []string{
			fmt.Sprintf("r:%v", role),
			fmt.Sprintf("p:%v", rule.Path),
			strings.ToUpper(rule.Method),
			fmt.Sprintf("d:%v", domain),
		})
	}
	return e.AddPolicies(policies)
}

func SetGroupPoliciesForRole(e *casbin.Enforcer, domain string, role string, rules []GroupRule) (bool, error) {
	DeleteAllGroupRulesForRole(e, domain, role)
	policies := [][]string{}
	for _, rule := range rules {
		policies = append(policies, []string{
			fmt.Sprintf("r:%v", role),
			fmt.Sprintf("g:%v", rule.GroupId),
			strings.ToUpper(rule.Method),
			fmt.Sprintf("d:%v", domain),
		})
	}
	return e.AddPolicies(policies)
}

func AddApiRuleForRole(e *casbin.Enforcer, domain string, role string, rule ApiRule) (bool, error) {
	return e.AddPolicy(
		fmt.Sprintf("r:%v", role),
		fmt.Sprintf("p:%v", rule.Path),
		strings.ToUpper(rule.Method),
		fmt.Sprintf("d:%v", domain),
	)
}

func AddGroupPolicyForRole(e *casbin.Enforcer, domain string, role string, rule GroupRule) (bool, error) {
	return e.AddPolicy(
		fmt.Sprintf("r:%v", role),
		fmt.Sprintf("g:%v", rule.GroupId),
		strings.ToUpper(rule.Method),
		fmt.Sprintf("d:%v", domain),
	)
}
