package iam

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
)

func CreateTokenWithClaims(secret string, claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	t, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", errors.Wrap(err, "signed token string")
	}
	return t, nil
}

func CreateAccessToken(secret string, accessKey string, expires time.Duration) (string, error) {
	claims := jwt.MapClaims{
		"exp": jwt.NewNumericDate(time.Now().Add(expires)),
		"ak":  accessKey,
	}

	return CreateTokenWithClaims(secret, claims)
}

func CreateLoginToken(secret string, username string, expires time.Duration) (string, error) {
	claims := jwt.MapClaims{
		"exp": jwt.NewNumericDate(time.Now().Add(expires)),
		"un":  username,
	}
	return CreateTokenWithClaims(secret, claims)
}

func GetTokenFromEchoContext(c echo.Context) (*jwt.Token, error) {
	token, ok := c.Get("user").(*jwt.Token) // by default token is stored under `user` key
	if !ok {
		return nil, errors.New("JWT token missing or invalid")
	}
	return token, nil
}
