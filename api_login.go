package iam

import (
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"github.com/spf13/cast"
	"go.uber.org/zap"
)

func (s *IAMServer) MakeJwtHandler(secret string) echo.MiddlewareFunc {
	config := echojwt.Config{
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(AccessClaims)
		},
		SigningKey:  []byte(secret),
		TokenLookup: "header:Authorization:Bearer ,query:token",
		// BeforeFunc: func(c echo.Context) {
		// 	req := c.Request()
		// 	auth := fmt.Sprintf("%v", req.Header["Authorization"][0])
		// 	auth = strings.ReplaceAll(auth, "Bearer ", "")
		// 	claims := &AccessClaims{}
		// 	fmt.Printf("!!!!!     %v\n", auth)
		// 	token, err := jwt.ParseWithClaims(auth, claims, func(token *jwt.Token) (interface{}, error) {
		// 		return []byte(secret), nil
		// 	})
		// 	if err != nil {
		// 		fmt.Printf("!!!!!     %v\n", err.Error())
		// 	}
		// 	fmt.Printf("!!!!!     %v\n", claims)
		// 	fmt.Printf("!!!!!     %v\n", token)
		// },
	}
	return echojwt.WithConfig(config)
}

func (s *IAMServer) MakeLoginHandler() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		logger := s.logger
		db := s.db
		return func(c echo.Context) error {
			path := c.Path()
			token := GetTokenFromEchoContext(c)
			if token == nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "unauthorized")
			}
			claims := token.Claims.(*AccessClaims)
			accessKey := claims.AccessKey
			username := claims.Username
			if username != "" {
				schema, name := ParseSchemaAndName(username)
				var user = User{}
				if result := db.Where("schema = ? AND name = ?", schema, name).First(&user); result.Error != nil {
					logger.Error("do enforce", zap.Error(result.Error))
					return echo.NewHTTPError(http.StatusUnauthorized, "unauthorized")
				}
				c.Set("schema", schema)
				c.Set("loginId", user.ID)
				c.Set("loginName", user.Name)
				c.Set("loginUser", user)
				if path != "/api/v1/current" && !strings.HasPrefix(path, "/api/v1/current/") && !strings.HasPrefix(path, "/api/v1/system/") {
					if ok := s.EnforceApi(user.Schema, user.Name, path, c.Request().Method); !ok {
						return echo.NewHTTPError(http.StatusUnauthorized, "unauthorized")
					}
				}
			} else if accessKey != "" {
				schema, _ := ParseSchemaAndName(accessKey)
				c.Set("schema", schema)
				c.Set("accessKey", accessKey)
			} else {
				return echo.NewHTTPError(http.StatusUnauthorized, "unauthorized")
			}

			return next(c)
		}
	}
}

func getLoginIdFromEchoContext(c echo.Context) uint {
	if v := c.Get("loginId"); v != nil {
		return cast.ToUint(v)
	}
	return 0
}

type authBody struct {
	Username string `json:"username" form:"username" query:"username" example:""`
	Password string `json:"password" form:"password" query:"password" example:""`
}
type authResponseBody struct {
	Token string `json:"token"`
}

// @Summary Authenticate a user
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body authBody true "Authenticate request"
// @Success 200 {object} authResponseBody "Returns a login token"
// @Failure 400 {object} echo.HTTPError "Bad request"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 500 {object} echo.HTTPError "Internal server error"
// @Router /iam/auth [POST]
func (s *IAMServer) HandleAuthenticate(c echo.Context) error {
	var data authBody
	if err := c.Bind(&data); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, errors.Wrap(err, "invalid input parameter").Error())
	}

	schema, name := ParseSchemaAndName(data.Username)

	db := s.db
	var user = User{}
	if result := db.Where("schema = ? AND name = ?", schema, name).First(&user); result.Error != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, errors.Wrap(result.Error, "get user").Error())
	}

	if !user.CheckPassword(data.Password) {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid username or password")
	}

	token, err := CreateLoginToken("", data.Username, time.Hour*8)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, err.Error())
	}
	c.Set("schema", schema)
	c.Set("loginId", user.ID)
	c.Set("loginName", user.Name)
	c.Set("loginUser", user)
	return c.JSON(http.StatusOK, authResponseBody{token})
}

// @Summary Get current user information
// @Tags Current
// @ID get-current
// @Accept json
// @Produce json
// @Security Bearer
// @Success 200 {object} User "User information"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 500 {object} echo.HTTPError "Internal server error"
// @Router /iam/current [GET]
func (s *IAMServer) HandleWhoAmI(c echo.Context) error {
	id := getLoginIdFromEchoContext(c)
	if id == 0 {
		return echo.NewHTTPError(http.StatusUnauthorized, "unauthorized")
	}
	var user User
	db := s.db
	if result := db.Where("id = ?", id).First(&user); result.Error != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, result.Error.Error())
	}
	return c.JSON(http.StatusOK, user)
}

type changePasswordBody struct {
	Password    string `json:"Password"`
	NewPassword string `json:"NewPassword"`
}

// @Summary Change current user password
// @Tags Current
// @ID change-current-password
// @Accept json
// @Produce json
// @Param body body changePasswordBody true "Change password request"
// @Security Bearer
// @Success 200 "Password changed successfully"
// @Failure 400 {object} echo.HTTPError "Bad request"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 500 {object} echo.HTTPError "Internal server error"
// @Router /iam/current/change-password [PUT]
func (s *IAMServer) HandleChangePassword(c echo.Context) error {
	var data changePasswordBody
	if err := c.Bind(&data); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, errors.Wrap(err, "invalid input parameter").Error())
	}

	schema := cast.ToString(c.Get("schema"))
	id := getLoginIdFromEchoContext(c)
	if id == 0 {
		return echo.NewHTTPError(http.StatusUnauthorized, "unauthorized")
	}
	user := new(User)
	db := s.db
	if result := db.Where("schema = ? AND id = ?", schema, id).First(user); result.Error != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, result.Error.Error())
	}
	if !user.ChangePassword(data.Password, data.NewPassword) {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid password")
	}
	updateColumns := []string{"password"}
	updateData := &User{}
	updateData.SetPassword(data.NewPassword)
	if result := db.Model(user).Select(updateColumns).Updates(updateData); result.Error != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, result.Error)
	}
	return c.JSON(http.StatusOK, nil)
}
