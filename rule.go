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

func (s *IAMServer) GetApiRulesForRole(domain string, role string) []ApiRule {
	if role == "admin" {
		return s.GetApiRules("*")
	}
	rules := []ApiRule{}
	polices := s.e.GetFilteredPolicy(0, fmt.Sprintf("r:%v", role), "", "", fmt.Sprintf("d:%v", domain))
	for _, v := range polices {
		if strings.HasPrefix(v[1], "p:") {
			rules = append(rules, ApiRule{Path: v[1][2:], Method: v[2]})
		}
	}
	return rules
}

func (s *IAMServer) GetApiRulesForUser(domain string, user string) []ApiRule {
	rules := []ApiRule{}
	roles, _ := s.GetRolesForUser(domain, user)
	for _, role := range roles {
		_rules := s.GetApiRulesForRole(domain, role)
		rules = append(rules, _rules...)
	}
	return rules
}

func (s *IAMServer) GetGroupRulesForRole(domain string, role string) []GroupRule {
	rules := []GroupRule{}
	polices := s.e.GetFilteredPolicy(0, fmt.Sprintf("r:%v", role), "", "", fmt.Sprintf("d:%v", domain))
	for _, v := range polices {
		if strings.HasPrefix(v[1], "g:") {
			rules = append(rules, GroupRule{GroupId: cast.ToUint(v[1][2:]), Method: v[2]})
		}
	}
	return rules
}

func (s *IAMServer) DeleteAllApiRulesForRole(domain string, role string) (bool, error) {
	polices := [][]string{}
	_polices := s.e.GetFilteredPolicy(0, fmt.Sprintf("r:%v", role), "", "", fmt.Sprintf("d:%v", domain))
	for _, v := range _polices {
		if strings.HasPrefix(v[1], "p:") {
			polices = append(polices, v)
		}
	}
	return s.e.RemovePolicies(polices)
}

func (s *IAMServer) DeleteAllGroupRulesForRole(domain string, role string) (bool, error) {
	polices := [][]string{}
	_polices := s.e.GetFilteredPolicy(0, fmt.Sprintf("r:%v", role), "", "", fmt.Sprintf("d:%v", domain))
	for _, v := range _polices {
		if strings.HasPrefix(v[1], "g:") {
			polices = append(polices, v)
		}
	}
	return s.e.RemovePolicies(polices)
}

func (s *IAMServer) SetApiRulesForRole(domain string, role string, rules []ApiRule) (bool, error) {
	s.DeleteAllApiRulesForRole(domain, role)
	policies := [][]string{}
	for _, rule := range rules {
		policies = append(policies, []string{
			fmt.Sprintf("r:%v", role),
			fmt.Sprintf("p:%v", rule.Path),
			strings.ToUpper(rule.Method),
			fmt.Sprintf("d:%v", domain),
		})
	}
	return s.e.AddPolicies(policies)
}

func (s *IAMServer) SetGroupPoliciesForRole(domain string, role string, rules []GroupRule) (bool, error) {
	s.DeleteAllGroupRulesForRole(domain, role)
	policies := [][]string{}
	for _, rule := range rules {
		policies = append(policies, []string{
			fmt.Sprintf("r:%v", role),
			fmt.Sprintf("g:%v", rule.GroupId),
			strings.ToUpper(rule.Method),
			fmt.Sprintf("d:%v", domain),
		})
	}
	return s.e.AddPolicies(policies)
}

func (s *IAMServer) AddApiRuleForRole(domain string, role string, rule ApiRule) (bool, error) {
	return s.e.AddPolicy(
		fmt.Sprintf("r:%v", role),
		fmt.Sprintf("p:%v", rule.Path),
		strings.ToUpper(rule.Method),
		fmt.Sprintf("d:%v", domain),
	)
}

func (s *IAMServer) AddGroupPolicyForRole(domain string, role string, rule GroupRule) (bool, error) {
	return s.e.AddPolicy(
		fmt.Sprintf("r:%v", role),
		fmt.Sprintf("g:%v", rule.GroupId),
		strings.ToUpper(rule.Method),
		fmt.Sprintf("d:%v", domain),
	)
}
