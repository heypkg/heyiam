package iam

import (
	"fmt"
	"strings"

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

func GetApiRulesForRole(domain string, role string) []ApiRule {
	e := GetEnforcer()
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

func GetApiRulesForUser(domain string, user string) []ApiRule {
	rules := []ApiRule{}
	roles, _ := GetRolesForUser(domain, user)
	for _, role := range roles {
		_rules := GetApiRulesForRole(domain, role)
		rules = append(rules, _rules...)
	}
	return rules
}

func GetGroupRulesForRole(domain string, role string) []GroupRule {
	e := GetEnforcer()
	rules := []GroupRule{}
	polices := e.GetFilteredPolicy(0, fmt.Sprintf("r:%v", role), "", "", fmt.Sprintf("d:%v", domain))
	for _, v := range polices {
		if strings.HasPrefix(v[1], "g:") {
			rules = append(rules, GroupRule{GroupId: cast.ToUint(v[1][2:]), Method: v[2]})
		}
	}
	return rules
}

func DeleteAllApiRulesForRole(domain string, role string) (bool, error) {
	e := GetEnforcer()
	polices := [][]string{}
	_polices := e.GetFilteredPolicy(0, fmt.Sprintf("r:%v", role), "", "", fmt.Sprintf("d:%v", domain))
	for _, v := range _polices {
		if strings.HasPrefix(v[1], "p:") {
			polices = append(polices, v)
		}
	}
	return e.RemovePolicies(polices)
}

func DeleteAllGroupRulesForRole(domain string, role string) (bool, error) {
	e := GetEnforcer()
	polices := [][]string{}
	_polices := e.GetFilteredPolicy(0, fmt.Sprintf("r:%v", role), "", "", fmt.Sprintf("d:%v", domain))
	for _, v := range _polices {
		if strings.HasPrefix(v[1], "g:") {
			polices = append(polices, v)
		}
	}
	return e.RemovePolicies(polices)
}

func SetApiRulesForRole(domain string, role string, rules []ApiRule) (bool, error) {
	e := GetEnforcer()
	DeleteAllApiRulesForRole(domain, role)
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

func SetGroupPoliciesForRole(domain string, role string, rules []GroupRule) (bool, error) {
	e := GetEnforcer()
	DeleteAllGroupRulesForRole(domain, role)
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

func AddApiRuleForRole(domain string, role string, rule ApiRule) (bool, error) {
	e := GetEnforcer()
	return e.AddPolicy(
		fmt.Sprintf("r:%v", role),
		fmt.Sprintf("p:%v", rule.Path),
		strings.ToUpper(rule.Method),
		fmt.Sprintf("d:%v", domain),
	)
}

func AddGroupPolicyForRole(domain string, role string, rule GroupRule) (bool, error) {
	e := GetEnforcer()
	return e.AddPolicy(
		fmt.Sprintf("r:%v", role),
		fmt.Sprintf("g:%v", rule.GroupId),
		strings.ToUpper(rule.Method),
		fmt.Sprintf("d:%v", domain),
	)
}
