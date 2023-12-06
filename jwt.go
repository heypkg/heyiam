package iam

import (
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
)

type AccessClaims struct {
	jwt.RegisteredClaims
	AccessKey string `json:"ak,omitempty"`
	Username  string `json:"un,omitempty"`
}

func CreateTokenWithClaims(secret string, claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	t, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", errors.Wrap(err, "signed token string")
	}
	return t, nil
}

func CreateAccessToken(secret string, key string, expires time.Duration) (string, error) {
	claims := &AccessClaims{
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expires)),
		},
		key,
		"",
	}
	return CreateTokenWithClaims(secret, claims)
}

func CreateAccessClaims(username string, expires time.Duration) *AccessClaims {
	claims := &AccessClaims{
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expires)),
		},
		"",
		username,
	}
	return claims
}

func CreateLoginToken(secret string, username string, expires time.Duration) (string, error) {
	claims := CreateAccessClaims(username, expires)
	return CreateTokenWithClaims(secret, claims)
}

func GetTokenFromEchoContext(c echo.Context) *jwt.Token {
	req := c.Request()
	auth := fmt.Sprintf("%v", req.Header["Authorization"][0])
	auth = strings.ReplaceAll(auth, "Bearer ", "")
	claims := &AccessClaims{}
	fmt.Printf("!!!!!     %v\n", auth)
	token, err := jwt.ParseWithClaims(auth, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(defaultSecret), nil
	})
	if err != nil {
		return nil
	}
	// if v := c.Get("user"); v != nil {
	// 	if token, ok := v.(*jwt.Token); ok {
	// 		return token
	// 	}
	// }
	return token
}
