package iam

import (
	"github.com/heypkg/store/echohandler"
	"github.com/labstack/echo/v4"
)

func SetupEchoGroup(group *echo.Group) *echo.Group {
	db := GetDB()

	meGroup := group.Group("/current")
	meGroup.GET("", HandleWhoAmI)
	meGroup.PUT("/change-password", HandleChangePassword)

	group.GET("/rules", HandleListApiRules)

	group.GET("/users", HandleListUsers)
	group.POST("/users", HandleCreateUser)
	group.DELETE("/users/:id", HandleDeleteUser, echohandler.ObjectHandler[User](db))
	group.GET("/users/:id", HandleGetUser, echohandler.ObjectHandler[User](db))
	group.PUT("/users/:id", HandleUpdateUser, echohandler.ObjectHandler[User](db))
	group.PUT("/users/:id/enable", HandleSetUserEnable, echohandler.ObjectHandler[User](db))
	group.PUT("/users/:id/disable", HandleSetUserDisable, echohandler.ObjectHandler[User](db))
	group.PUT("/users/:id/reset-password", HandleResetUserPassword, echohandler.ObjectHandler[User](db))
	group.PUT("/users/:id/change-password", HandleChangeUserPassword, echohandler.ObjectHandler[User](db))
	group.GET("/users/:id/roles", HandleGetUserRoles, echohandler.ObjectHandler[User](db))
	group.POST("/users/:id/roles", HandleAddUserRoles, echohandler.ObjectHandler[User](db))
	group.PUT("/users/:id/roles", HandleSetUserRoles, echohandler.ObjectHandler[User](db))

	group.GET("/roles", HandleListRoles)
	group.POST("/roles", HandleCreateRole)
	group.DELETE("/roles/:id", HandleDeleteRole, echohandler.ObjectHandler[Role](db))
	group.GET("/roles/:id", HandleGetRole, echohandler.ObjectHandler[Role](db))
	group.PUT("/roles/:id", HandleUpdateRole, echohandler.ObjectHandler[Role](db))
	group.PUT("/roles/:id/enable", HandleSetRoleEnable, echohandler.ObjectHandler[Role](db))
	group.PUT("/roles/:id/disable", HandleSetRoleDisable, echohandler.ObjectHandler[Role](db))
	group.PUT("/roles/:id/rules", HandleSetRoleApiRules, echohandler.ObjectHandler[Role](db))

	group.GET("/audit-logs", HandleListAuditLogs)
	group.GET("/audit-logs/:ts", HandleGetAuditLog, echohandler.TSObjectHandler[AuditLog](db))
	return group
}
