package iam

import (
	"net/http"
	"sort"

	"github.com/labstack/echo/v4"
)

type listRulesBody struct {
	Data  []string `json:"Data"`
	Total int      `json:"Total"`
}

// HandleListApiRules godoc
// @Summary List rules
// @ID list-rules
// @Tags Rules
// @Security Bearer
// @Success 200 {object} listRulesBody
// @Failure 500 {object} echo.HTTPError "Internal server error"
// @Router /iam/rules [get]
func HandleListApiRules(c echo.Context) error {
	rules := GetApiRuleIds("*")
	sort.Slice(rules, func(i, j int) bool {
		return rules[i] < rules[j]
	})
	return c.JSON(http.StatusOK, listRulesBody{Data: rules, Total: len(rules)})
}
