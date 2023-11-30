package iam

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/heypkg/store/echohandler"
	"github.com/heypkg/store/jsontype"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.uber.org/zap"
)

func MakeAuditLogHandler() echo.MiddlewareFunc {
	return middleware.BodyDump(func(c echo.Context, reqBody, resBody []byte) {
		logger := GetLogger()
		db := GetDB()
		req := c.Request()
		resp := c.Response()
		if req == nil || resp == nil {
			return
		}
		method := strings.ToUpper(req.Method)
		registerPath := c.Path()
		path := req.URL.Path
		status := resp.Status
		if method == "POST" || method == "PUT" || method == "DELETE" {
			if v := c.Get("loginUser"); v != nil {
				if user, ok := v.(User); ok {
					metadata := jsontype.Tags{}
					if !strings.HasSuffix(path, "/auth") {
						metadata["RequestContent"] = reqBody
						metadata["ResponseContent"] = resBody
					}
					if err := InsertAuditLog(db, &user, method, registerPath, path, status, &metadata); err != nil {
						logger.Error("insert audit log", zap.Error(err))
					}
				}
			}
		}
	})
}

type listAuditLogsData struct {
	Data  []AuditLog `json:"Data"`
	Total int64      `json:"Total"`
}

// HandleListAuditLogs lists all audit logs.
// @Summary List audit logs
// @ID list-audit-logs
// @Produce json
// @Security Bearer
// @Param page query int false "Page" default(1)
// @Param page_size query int false "Page size" default(20)
// @Param order_by query string false "Sort order" default()
// @Param q query string false "Query" default()
// @Success 200 {object} listAuditLogsData
// @Header 200 {int} X-Total "Total number"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 500 {object} echo.HTTPError "Internal Server error"
// @Router /iam/audit-logs [get]
// @Tags AuditLogs
func HandleListAuditLogs(c echo.Context) error {
	data, total, err := echohandler.ListObjects[AuditLog](GetDB(), c, nil, nil)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	c.Response().Header().Set("X-Total", fmt.Sprintf("%v", total))
	return c.JSON(http.StatusOK, listAuditLogsData{Data: data, Total: total})
}

// HandleGetAuditLog retrieves a single audit log.
// @Summary Get audit log
// @ID get-audit-log
// @Produce json
// @Security Bearer
// @Param ts path int true "Timestamp"
// @Success 200 {object} AuditLog
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 500 {object} echo.HTTPError "Internal Server error"
// @Router /iam/audit-logs/{ts} [get]
// @Tags AuditLogs
func HandleGetAuditLog(c echo.Context) error {
	obj := echohandler.GetObjectFromEchoContext[AuditLog](c)
	return c.JSON(http.StatusOK, obj)
}
