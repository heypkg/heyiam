package iam

import (
	"fmt"
	"net/http"

	"github.com/heypkg/store/echohandler"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"github.com/spf13/cast"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type listUsersData struct {
	Data  []User `json:"Data"`
	Total int64  `json:"Total"`
}

// HandleListUsers lists users based on specified filters.
// @Summary List users
// @ID list-users
// @Tags Users
// @Produce json
// @Param page query int false "Page" default(1)
// @Param page_size query int false "Page size" default(20)
// @Param order_by query string false "Sort order" default()
// @Param q query string false "Query" default()
// @Security Bearer
// @Success 200 {object} listUsersData
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 500 {object} echo.HTTPError "Internal server error"
// @Router /iam/users [get]
func HandleListUsers(c echo.Context) error {
	data, total, err := echohandler.ListObjects[User](GetDB(), c, nil, nil)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	users2 := []User{}
	for _, user := range data {
		tmp := user
		users2 = append(users2, tmp)
	}
	c.Response().Header().Set("X-Total", fmt.Sprintf("%v", total))
	return c.JSON(http.StatusOK, listUsersData{Data: users2, Total: total})
}

type createUserBody struct {
	Name     string
	Alias    string
	Password string
}

// HandleCreateUser creates a new user.
// @Summary Create user
// @ID create-user
// @Tags Users
// @Produce json
// @Security Bearer
// @Param body body createUserBody true "User"
// @Success 200 {object} User
// @Failure 400 {object} echo.HTTPError "Bad Request: invalid input parameter"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 500 {object} echo.HTTPError "Internal server error"
// @Router /iam/users [post]
func HandleCreateUser(c echo.Context) error {
	var data createUserBody
	if err := c.Bind(&data); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, errors.Wrap(err, "invalid input parameter").Error())
	}

	db := GetDB()
	user := User{
		Schema: cast.ToString(c.Get("schema")),
		Name:   data.Name,
		Alias:  data.Alias,
	}
	user.SetPassword(data.Password)

	result := db.Create(&user)
	if result.Error != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, result.Error)
	}
	return c.JSON(http.StatusOK, user)
}

// HandleGetUser retrieves a single user from the database.
// @Summary Get user
// @ID get-user
// @Tags Users
// @Produce json
// @Security Bearer
// @Param id path int true "User ID"
// @Success 200 {object} User
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 404 {object} echo.HTTPError "User not found"
// @Failure 500 {object} echo.HTTPError "Internal server error"
// @Router /iam/users/{id} [get]
func HandleGetUser(c echo.Context) error {
	user := echohandler.GetObjectFromEchoContext[User](c)
	return c.JSON(http.StatusOK, user)
}

type updateUserBody struct {
	Alias string
}

// HandleUpdateUser updates a user
// @Summary Update user
// @ID update-user
// @Tags Users
// @Produce json
// @Security Bearer
// @Param id path int true "User ID"
// @Param body body updateUserBody true "User"
// @Success 200 {object} User
// @Failure 400 {object} echo.HTTPError "Bad Request: invalid input parameter"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 404 {object} echo.HTTPError "User not found"
// @Failure 500 {object} echo.HTTPError "Internal server error"
// @Router /iam/users/{id} [put]
func HandleUpdateUser(c echo.Context) error {
	var data updateUserBody
	if err := c.Bind(&data); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, errors.Wrap(err, "invalid input parameter").Error())
	}
	updateColumns := []string{"alias"}
	updateData := &User{
		Alias: data.Alias,
	}
	user := echohandler.GetObjectFromEchoContext[User](c)
	if user.Default {
		return echo.NewHTTPError(http.StatusForbidden, "default user")
	}

	db := GetDB()
	if result := db.Model(user).Select(updateColumns).Updates(updateData); result.Error != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, result.Error)
	}
	return c.JSON(http.StatusOK, user)
}

// HandleGetUserRoles godoc
// @Summary Get roles for user
// @Tags Users
// @ID get-user-roles
// @Security Bearer
// @Param id path int true "User ID"
// @Success 200 {array} string
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 500 {object} echo.HTTPError "Internal Server Error"
// @Router /iam/users/{id}/roles [get]
func HandleGetUserRoles(c echo.Context) error {
	user := echohandler.GetObjectFromEchoContext[User](c)
	return c.JSON(http.StatusOK, user.Roles)
}

type addUserRolesBody struct {
	RoleNames []string
}

// HandleAddUserRoles godoc
// @Summary Add roles for user
// @Tags Users
// @ID add-user-roles
// @Security Bearer
// @Param id path int true "User ID"
// @Param body body addUserRolesBody true "Roles to add"
// @Success 200 {object} User
// @Failure 400 {object} echo.HTTPError "Bad Request"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 500 {object} echo.HTTPError "Internal Server Error"
// @Router /iam/users/{id}/roles [post]
func HandleAddUserRoles(c echo.Context) error {
	var data addUserRolesBody
	if err := c.Bind(&data); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, errors.Wrap(err, "invalid input parameter").Error())
	}
	user := echohandler.GetObjectFromEchoContext[User](c)
	if user.Default {
		return echo.NewHTTPError(http.StatusForbidden, "default user")
	}

	db := GetDB()
	for _, roleName := range data.RoleNames {
		role := new(Role)
		if err := db.Where("schema = ? AND name = ?", user.Schema, roleName).First(role).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return echo.NewHTTPError(http.StatusBadRequest, "invalid role")
			} else {
				return echo.NewHTTPError(http.StatusInternalServerError, err)
			}
		}
	}
	if ok, err := AddRolesForUser(user.Schema, user.Name, data.RoleNames); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	} else if !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "already has the role")
	}
	return c.JSON(http.StatusOK, user)
}

type setUserRoles struct {
	RoleNames []string
}

// HandleSetUserRoles godoc
// @Summary Set roles for user
// @Tags Users
// @ID set-user-roles
// @Security Bearer
// @Param id path int true "User ID"
// @Param body body setUserRoles true "Roles to set"
// @Success 200 {object} User
// @Failure 400 {object} echo.HTTPError "Bad Request"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 500 {object} echo.HTTPError "Internal Server Error"
// @Router /iam/users/{id}/roles [put]
func HandleSetUserRoles(c echo.Context) error {
	var data setUserRoles
	if err := c.Bind(&data); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, errors.Wrap(err, "invalid input parameter").Error())
	}
	user := echohandler.GetObjectFromEchoContext[User](c)
	if user.Default {
		return echo.NewHTTPError(http.StatusForbidden, "default user")
	}

	db := GetDB()
	for _, roleName := range data.RoleNames {
		role := new(Role)
		if err := db.Where("schema = ? AND name = ?", user.Schema, roleName).First(role).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return echo.NewHTTPError(http.StatusBadRequest, "invalid role")
			} else {
				return echo.NewHTTPError(http.StatusInternalServerError, err)
			}
		}
	}
	if ok, err := SetRolesForUser(user.Schema, user.Name, data.RoleNames); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	} else if !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "already has the role")
	}
	return c.JSON(http.StatusOK, user)
}

// HandleSetUserEnable godoc
// @Summary Set user enable
// @Tags Users
// @ID set-user-enable
// @Security Bearer
// @Param id path int true "User ID"
// @Success 200 {object} User
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 403 {object} echo.HTTPError "Forbidden"
// @Failure 500 {object} echo.HTTPError "Internal server error"
// @Router /iam/users/{id}/enable [put]
func HandleSetUserEnable(c echo.Context) error {
	user := echohandler.GetObjectFromEchoContext[User](c)
	if user.Default {
		return echo.NewHTTPError(http.StatusForbidden, "default user")
	}
	if !user.Enable {
		db := GetDB()
		if result := db.Model(user).Update("enable", true); result.Error != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, result.Error)
		}
	}
	return c.JSON(http.StatusOK, user)
}

// HandleSetUserDisable godoc
// @Summary Set user disable
// @Tags Users
// @ID set-user-disable
// @Security Bearer
// @Param id path int true "User ID"
// @Success 200 {object} User
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 403 {object} echo.HTTPError "Forbidden"
// @Failure 500 {object} echo.HTTPError "Internal server error"
// @Router /iam/users/{id}/disable [put]
func HandleSetUserDisable(c echo.Context) error {
	user := echohandler.GetObjectFromEchoContext[User](c)
	if user.Default {
		return echo.NewHTTPError(http.StatusForbidden, "default user")
	}
	if user.Enable {
		db := GetDB()
		if result := db.Model(user).Update("enable", false); result.Error != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, result.Error)
		}
	}
	return c.JSON(http.StatusOK, user)
}

// HandleResetUserPassword resets a user's password
// @Summary Reset user password
// @ID reset-user-password
// @Tags Users
// @Produce json
// @Security Bearer
// @Param id path int true "User ID"
// @Success 200 {object} echo.Map
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 404 {object} echo.HTTPError "User not found"
// @Failure 500 {object} echo.HTTPError "Internal server error"
// @Router /iam/users/{id}/reset-password [put]
func HandleResetUserPassword(c echo.Context) error {
	password := GeneratePassword()
	updateColumns := []string{"passwod"}
	updateData := &User{}
	updateData.SetPassword(password)
	user := echohandler.GetObjectFromEchoContext[User](c)
	db := GetDB()
	if result := db.Model(user).Select(updateColumns).Updates(updateData); result.Error != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, result.Error)
	}
	return c.JSON(http.StatusOK, echo.Map{
		"password": password,
	})
}

// HandleChangeUserPassword changes a user's password.
// @Summary Change user password
// @ID change-user-password
// @Tags Users
// @Produce json
// @Security Bearer
// @Param id path int true "User ID"
// @Param body body changePasswordBody true "Change password request"
// @Success 200 {object} User
// @Failure 400 {object} echo.HTTPError "Invalid input parameter"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 404 {object} echo.HTTPError "User not found"
// @Failure 500 {object} echo.HTTPError "Internal server error"
// @Router /iam/users/{id}/change-password [put]
func HandleChangeUserPassword(c echo.Context) error {
	var data changePasswordBody
	if err := c.Bind(&data); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, errors.Wrap(err, "invalid input parameter").Error())
	}
	user := echohandler.GetObjectFromEchoContext[User](c)
	if !user.ChangePassword(data.Password, data.NewPassword) {
		return echo.NewHTTPError(http.StatusUnauthorized, "unauthorized")
	}
	updateColumns := []string{"password"}
	updateData := &User{}
	updateData.SetPassword(data.NewPassword)
	db := GetDB()
	if result := db.Model(user).Select(updateColumns).Updates(updateData); result.Error != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, result.Error)
	}
	return c.JSON(http.StatusOK, user)
}

// HandleDeleteUser deletes a user.
// @Summary Delete user
// @ID delete-user
// @Tags Users
// @Produce json
// @Security Bearer
// @Param id path int true "User ID"
// @Success 204
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 403 {object} echo.HTTPError "Forbidden"
// @Failure 404 {object} echo.HTTPError "User not found"
// @Failure 500 {object} echo.HTTPError "Internal server error"
// @Router /iam/users/{id} [delete]
func HandleDeleteUser(c echo.Context) error {
	user := echohandler.GetObjectFromEchoContext[User](c)
	if user.Default {
		return echo.NewHTTPError(http.StatusForbidden, "default user")
	}
	db := GetDB().Unscoped()
	if result := db.Delete(user); result.Error != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, result.Error)
	}
	if _, err := DeleteAllRolesForUser(user.Schema, user.Name); err != nil {
		GetLogger().Error("delete all roles for user", zap.Error(err))
	}
	return c.NoContent(http.StatusNoContent)
}
