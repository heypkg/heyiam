package iam

import (
	"fmt"
	"net/http"

	"github.com/heypkg/store/echohandler"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type listRolesData struct {
	Data  []Role `json:"Data"`
	Total int64  `json:"Total"`
}

// HandleListRoles godoc
// @Summary List roles
// @ID list-roles
// @Tags IAM Roles
// @Security Bearer
// @Param page query int false "Page" default(1)
// @Param page_size query int false "Page size" default(20)
// @Param order_by query string false "Sort order" default()
// @Param q query string false "Query" default()
// @Success 200 {object} listRolesData
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 500 {object} echo.HTTPError "Internal server error"
// @Router /iam/roles [get]
func HandleListRoles(c echo.Context) error {
	data, total, err := echohandler.ListObjects[Role](GetDB(), c, nil, nil)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	c.Response().Header().Set("X-Total", fmt.Sprintf("%v", total))
	return c.JSON(http.StatusOK, listRolesData{Data: data, Total: total})
}

type createRoleBody struct {
	Name  string
	Alias string
}

// HandleCreateRole godoc
// @Summary Create a role
// @Tags IAM Roles
// @ID create-role
// @Security Bearer
// @Param body body createRoleBody true "Create Role Body"
// @Success 200 {object} Role
// @Failure 400 {object} echo.HTTPError "Bad Request"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 500 {object} echo.HTTPError "Internal server error"
// @Router /iam/roles [post]
func HandleCreateRole(c echo.Context) error {
	var data createRoleBody
	if err := c.Bind(&data); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, errors.Wrap(err, "invalid input parameter").Error())
	}

	role := &Role{
		Name:  data.Name,
		Alias: data.Alias,
	}
	db := GetDB()
	if err := db.Create(role).Error; err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	return c.JSON(http.StatusOK, role)
}

// HandleGetRole godoc
// @Summary Get role
// @Tags IAM Roles
// @ID get-role
// @Security Bearer
// @Param id path int true "Role ID"
// @Success 200 {object} Role
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 500 {object} echo.HTTPError "Internal server error"
// @Router /iam/roles/{id} [get]
func HandleGetRole(c echo.Context) error {
	role := echohandler.GetObjectFromEchoContext[Role](c)
	return c.JSON(http.StatusOK, role)
}

type updateRoleBody struct {
	Alias string
}

// HandleUpdateRole godoc
// @Summary Update role
// @Tags IAM Roles
// @ID update-role
// @Security Bearer
// @Param id path int true "Role ID"
// @Param body body updateRoleBody true "Update Role Body"
// @Success 200 {object} Role
// @Failure 400 {object} echo.HTTPError "Bad Request"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 500 {object} echo.HTTPError "Internal server error"
// @Router /iam/roles/{id} [put]
func HandleUpdateRole(c echo.Context) error {
	var data updateRoleBody
	if err := c.Bind(&data); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, errors.Wrap(err, "invalid input parameter").Error())
	}

	role := echohandler.GetObjectFromEchoContext[Role](c)
	if role.Default {
		return echo.NewHTTPError(http.StatusForbidden, "default role")
	}
	updateColumns := []string{"alias"}
	updateData := &Role{
		Alias: data.Alias,
	}
	db := GetDB()
	if err := db.Model(role).Select(updateColumns).Updates(updateData).Error; err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	return c.JSON(http.StatusOK, role)
}

// HandleSetRoleEnable godoc
// @Summary Set role enable
// @Tags IAM Roles
// @ID set-role-enable
// @Security Bearer
// @Param id path int true "Role ID"
// @Success 200 {object} Role
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 403 {object} echo.HTTPError "Forbidden"
// @Failure 500 {object} echo.HTTPError "Internal server error"
// @Router /iam/roles/{id}/enable [put]
func HandleSetRoleEnable(c echo.Context) error {
	role := echohandler.GetObjectFromEchoContext[Role](c)
	if role.Default {
		return echo.NewHTTPError(http.StatusForbidden, "default role")
	}
	if !role.Enable {
		db := GetDB()
		if result := db.Model(role).Update("enable", true); result.Error != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, result.Error)
		}
	}
	return c.JSON(http.StatusOK, role)
}

// HandleSetRoleDisable godoc
// @Summary Set role disable
// @Tags IAM Roles
// @ID set-role-disable
// @Security Bearer
// @Param id path int true "Role ID"
// @Success 200 {object} Role
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 403 {object} echo.HTTPError "Forbidden"
// @Failure 500 {object} echo.HTTPError "Internal server error"
// @Router /iam/roles/{id}/disable [put]
func HandleSetRoleDisable(c echo.Context) error {
	role := echohandler.GetObjectFromEchoContext[Role](c)
	if role.Default {
		return echo.NewHTTPError(http.StatusForbidden, "default role")
	}
	if role.Enable {
		db := GetDB()
		if result := db.Model(role).Update("enable", false); result.Error != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, result.Error)
		}
	}
	return c.JSON(http.StatusOK, role)
}

// HandleDeleteRole godoc
// @Summary Delete role
// @Tags IAM Roles
// @ID delete-role
// @Security Bearer
// @Param id path int true "Role ID"
// @Success 204 "No Content"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 500 {object} echo.HTTPError "Internal server error"
// @Router /iam/roles/{id} [delete]
func HandleDeleteRole(c echo.Context) error {
	role := echohandler.GetObjectFromEchoContext[Role](c)
	if role.Default {
		return echo.NewHTTPError(http.StatusForbidden, "default role")
	}
	db := GetDB().Unscoped()
	if err := db.Delete(role).Error; err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}
	if _, err := DeleteAllApiRulesForRole(role.Schema, role.Name); err != nil {
		GetLogger().Error("delete all api polices for role", zap.Error(err))
	}
	if _, err := DeleteAllGroupRulesForRole(role.Schema, role.Name); err != nil {
		GetLogger().Error("delete all group polices for role", zap.Error(err))
	}
	return c.NoContent(http.StatusNoContent)
}

type setRoleApiRulesBody struct {
	RuleIds []string `json:"RoleIds"`
}

// HandleSetRoleApiRules godoc
// @Summary Set rules for role
// @Tags IAM Roles
// @ID set-role-rules
// @Security Bearer
// @Param id path int true "Role ID"
// @Param body body setRoleApiRulesBody true "rules to set"
// @Success 200 {object} User
// @Failure 400 {object} echo.HTTPError "Bad Request"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 500 {object} echo.HTTPError "Internal Server Error"
// @Router /iam/roles/{id}/rules [put]
func HandleSetRoleApiRules(c echo.Context) error {
	var data setRoleApiRulesBody
	if err := c.Bind(&data); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, errors.Wrap(err, "invalid input parameter").Error())
	}
	role := echohandler.GetObjectFromEchoContext[Role](c)
	if role.Default {
		return echo.NewHTTPError(http.StatusForbidden, "default role")
	}

	rules := GetApiRules(data.RuleIds...)
	if ok, err := SetApiRulesForRole(role.Schema, role.Name, rules); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	} else if !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "already has the role")
	}
	return c.JSON(http.StatusOK, role)
}
