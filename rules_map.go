package iam

import (
	"regexp"
	"strings"
)

var defaultApiRulesMap = map[string]ApiRule{
	// "api.system.time.get": {Method: "GET", Path: "/api/v1/system/time"},

	"api.auth": {Method: "POST", Path: "/api/v1/auth"},

	// "api.current.get":             {Method: "GET", Path: "/api/v1/current"},
	// "api.current.change-password": {Method: "PUT", Path: "/api/v1/current/change-password"},

	"api.iam.roles.list":      {Method: "GET", Path: "/api/v1/iam/roles"},
	"api.iam.roles.get":       {Method: "GET", Path: "/api/v1/iam/roles/:id"},
	"api.iam.roles.create":    {Method: "POST", Path: "/api/v1/iam/roles"},
	"api.iam.roles.delete":    {Method: "DELETE", Path: "/api/v1/iam/roles/:id"},
	"api.iam.roles.update":    {Method: "PUT", Path: "/api/v1/iam/roles/:id"},
	"api.iam.roles.enable":    {Method: "PUT", Path: "/api/v1/iam/roles/:id/enable"},
	"api.iam.roles.disable":   {Method: "PUT", Path: "/api/v1/iam/roles/:id/disable"},
	"api.iam.roles.set-rules": {Method: "PUT", Path: "/api/v1/iam/roles/:id/rules"},

	"api.iam.users.list":            {Method: "GET", Path: "/api/v1/iam/users"},
	"api.iam.users.create":          {Method: "POST", Path: "/api/v1/iam/users"},
	"api.iam.users.update":          {Method: "PUT", Path: "/api/v1/iam/users/:id"},
	"api.iam.users.delete":          {Method: "DELETE", Path: "/api/v1/iam/users/:id"},
	"api.iam.users.get":             {Method: "GET", Path: "/api/v1/iam/users/:id"},
	"api.iam.users.change-password": {Method: "PUT", Path: "/api/v1/iam/users/:id/change-password"},
	"api.iam.users.enable":          {Method: "PUT", Path: "/api/v1/iam/users/:id/enable"},
	"api.iam.users.disable":         {Method: "PUT", Path: "/api/v1/iam/users/:id/disable"},
	"api.iam.users.reset-password":  {Method: "PUT", Path: "/api/v1/iam/users/:id/reset-password"},
	"api.iam.users.roles.list":      {Method: "GET", Path: "/api/v1/iam/users/:id/roles"},
	"api.iam.users.roles.create":    {Method: "POST", Path: "/api/v1/iam/users/:id/roles"},
	"api.iam.users.roles.update":    {Method: "PUT", Path: "/api/v1/iam/users/:id/roles"},

	"api.iam.audit-logs.list": {Method: "GET", Path: "/api/v1/iam/audit-logs"},
	"api.iam.audit-logs.get":  {Method: "GET", Path: "/api/v1/iam/audit-logs/:ts"},
}

func (s *IAMServer) setupApiRules(rules map[string]ApiRule) {
	for key, rule := range rules {
		s.apiRulesMap[key] = rule
	}
}

func (s *IAMServer) GetApiRuleIds(patterns ...string) []string {
	ids := []string{}
	ruleMap := make(map[string]bool)
	for _, pattern := range patterns {
		pattern = strings.ReplaceAll(pattern, ".", "\\.")
		pattern = strings.ReplaceAll(pattern, "*", ".*")
		re := regexp.MustCompile(pattern)
		for id, _ := range s.apiRulesMap {
			if re.Match([]byte(id)) {
				if _, ok := ruleMap[id]; !ok {
					ruleMap[id] = true
					ids = append(ids, id)
				}
			}
		}
	}
	return ids
}

func (s *IAMServer) GetApiRules(patterns ...string) []ApiRule {
	rules := []ApiRule{}
	ruleMap := make(map[string]bool)
	for _, pattern := range patterns {
		pattern = strings.ReplaceAll(pattern, ".", "\\.")
		pattern = strings.ReplaceAll(pattern, "*", ".*")
		re := regexp.MustCompile(pattern)
		for id, rule := range s.apiRulesMap {
			if re.Match([]byte(id)) {
				if _, ok := ruleMap[id]; !ok {
					ruleMap[id] = true
					rules = append(rules, rule)
				}
			}
		}
	}
	return rules
}

func (s *IAMServer) GetApiRuleIdsByRule(rules []ApiRule) []string {
	ids := []string{}
	ruleMap := make(map[string]bool)
	for _, rule := range rules {
		for id, rule2 := range s.apiRulesMap {
			if rule.Method == rule2.Method && rule.Path == rule2.Path {
				if _, ok := ruleMap[id]; !ok {
					ruleMap[id] = true
					ids = append(ids, id)
				}
			}
		}
	}
	return ids
}

func (s *IAMServer) GetApiRuleIdByRule(rule ApiRule) string {
	for id, rule2 := range s.apiRulesMap {
		if rule.Method == rule2.Method && rule.Path == rule2.Path {
			return id
		}
	}
	return ""
}
