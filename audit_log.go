package iam

import (
	"sync"

	"github.com/heypkg/store/jsontype"
	"github.com/pkg/errors"
	"gorm.io/gorm"
)

var AuditLogIndexNames = []string{"schema", "api_name"}
var AuditLogUserIndexNames = []string{"schema", "user_id", "user_name", "api_name"}

type AuditLog struct {
	Time    jsontype.JSONTime `json:"Time" gorm:"autoCreateTime;uniqueIndex:idx_user_audit_log_unique;not null"`
	Schema  string            `json:"Schema" gorm:"uniqueIndex:idx_user_audit_log_unique;not null"`
	UserID  uint              `json:"UserId" gorm:"uniqueIndex:idx_user_audit_log_unique;not null"`
	User    *User             `json:"User" gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	Updated jsontype.JSONTime `json:"Updated" gorm:"autoUpdateTime"`

	UserName  string `json:"UserName"`
	UserAlias string `json:"UserAlias"`

	ApiName     string                            `json:"ApiName" gorm:"uniqueIndex:idx_user_audit_log_unique;not null"`
	Method      string                            `json:"Method"`
	Path        string                            `json:"Path"`
	Status      int                               `json:"Status"`
	MetaDataRaw jsontype.JSONType[*jsontype.Tags] `json:"-" gorm:"column:meta_data"`
	MetaData    *jsontype.Tags                    `json:"MetaData" gorm:"-"`
}

func (m *AuditLog) SaveData() {
	m.MetaDataRaw = jsontype.NewJSONType(m.MetaData)
}
func (m *AuditLog) LoadData() {
	m.MetaData = m.MetaDataRaw.Data
}

func (m *AuditLog) BeforeSave(tx *gorm.DB) (err error) {
	m.SaveData()
	return nil
}

func (m *AuditLog) AfterFind(tx *gorm.DB) (err error) {
	m.LoadData()
	return nil
}

var ignoreApiRuleIdsLock sync.RWMutex
var ignoreApiRuleIds = []string{}

func SetAuditLogIgnoreIds(ids []string) {
	ignoreApiRuleIdsLock.Lock()
	defer ignoreApiRuleIdsLock.Unlock()
	ignoreApiRuleIds = ids
}

func InsertAuditLog(db *gorm.DB, user *User, method string, registerPath string, path string, status int, metaData *jsontype.Tags) error {
	if method == "" || path == "" {
		return nil
	}
	name := getApiRuleIdByRule(ApiRule{Method: method, Path: registerPath})
	if name == "" {
		return errors.New("unknow api rule")
	}
	ignoreApiRuleIdsLock.RLock()
	defer ignoreApiRuleIdsLock.RUnlock()
	for _, v := range ignoreApiRuleIds {
		if v == name {
			return nil
		}
	}

	obj := &AuditLog{
		Schema:    user.Schema,
		UserID:    user.ID,
		UserName:  user.Name,
		UserAlias: user.Alias,
		ApiName:   name,
		Method:    method,
		Path:      path,
		MetaData:  metaData,
	}
	result := db.Create(obj)
	if result.Error != nil {
		return errors.Wrap(result.Error, "create new audit log")
	}
	return nil
}
