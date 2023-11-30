package iam

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"strings"
	"time"

	"github.com/heypkg/store/jsontype"
	"gorm.io/gorm"
)

type Tags map[string]any

type User struct {
	ID      uint           `json:"Id" gorm:"primarykey"`
	Updated int64          `json:"Updated" gorm:"autoUpdateTime"`
	Created int64          `json:"Created" gorm:"autoCreateTime"`
	Deleted gorm.DeletedAt `json:"Deleted" gorm:"index"`

	Schema           string                            `json:"Schema" gorm:"uniqueIndex:idx_iam_user_unique"`
	Name             string                            `json:"Name" gorm:"uniqueIndex:idx_iam_user_unique,<-:create"`
	Alias            string                            `json:"Alias"`
	Password         string                            `json:"-"`
	PasswordExpireAt int64                             `json:"PasswordExpireAt"`
	Default          bool                              `json:"Default" gorm:"<-:create,default:false"`
	Enable           bool                              `json:"Enable" gorm:"index"`
	MetaDataRaw      jsontype.JSONType[*jsontype.Tags] `json:"-" gorm:"column:meta_data"`
	MetaData         *jsontype.Tags                    `json:"MetaData" gorm:"-"`
	Roles            []string                          `json:"Roles" gorm:"-"`
	Rules            []string                          `json:"Rules" gorm:"-"`
}

func (m *User) BeforeSave(tx *gorm.DB) (err error) {
	if m.MetaData != nil {
		m.MetaDataRaw = jsontype.NewJSONType(m.MetaData)
	}
	return nil
}

func (m *User) AfterFind(tx *gorm.DB) (err error) {
	m.MetaData = m.MetaDataRaw.Data
	m.Roles, _ = GetRolesForUser(m.Schema, m.Name)
	rules := GetApiRulesForUser(m.Schema, m.Name)
	m.Rules = getApiRuleIdsByRule(rules)
	return nil
}

func (s *User) SetPassword(password string) {
	s.Password = EncryptPassword(password)
}

func (s User) CheckPassword(password string) bool {
	if password != "" && s.Password == EncryptPassword(password) {
		return true
	}
	return false
}

func (s *User) ChangePassword(old string, password string) bool {
	if !s.CheckPassword(old) {
		return false
	}
	s.SetPassword(password)
	return true
}

func EncryptPassword(password string) string {
	h := md5.New()
	io.WriteString(h, password)
	sum := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(sum)
}

func GeneratePassword() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	password := ""
	for i := 0; i < 8; i++ {
		x := r.Intn(9)
		password = password + fmt.Sprintf("%d", x)
	}
	return password
}

func ParseSchemaAndName(data string) (string, string) {
	parts := strings.Split(data, "@")
	n := len(parts)
	if n < 2 {
		return "", data
	}
	return parts[n-1], strings.Join(parts[0:n-1], "@")
}
