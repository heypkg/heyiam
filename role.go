package iam

import (
	"github.com/heypkg/store/jsontype"
	"gorm.io/gorm"
)

type Role struct {
	ID      uint           `json:"Id" gorm:"primarykey"`
	Updated int64          `json:"Updated" gorm:"autoUpdateTime"`
	Created int64          `json:"Created" gorm:"autoCreateTime"`
	Deleted gorm.DeletedAt `json:"Deleted" gorm:"index"`

	Schema      string                            `json:"Schema" gorm:"uniqueIndex:idx_iam_role_unique"`
	Name        string                            `json:"Name" gorm:"uniqueIndex:idx_iam_role_unique,<-:create"`
	Alias       string                            `json:"Alias"`
	Default     bool                              `json:"Default" gorm:"<-:create,default:false"`
	Enable      bool                              `json:"Enable" gorm:"index"`
	MetaDataRaw jsontype.JSONType[*jsontype.Tags] `json:"-" gorm:"column:meta_data"`
	MetaData    *jsontype.Tags                    `json:"MetaData" gorm:"-"`

	Rules []string `json:"Rules" gorm:"-"`
}

func (m *Role) BeforeSave(tx *gorm.DB) (err error) {
	if m.MetaData != nil {
		m.MetaDataRaw = jsontype.NewJSONType(m.MetaData)
	}
	return nil
}

func (m *Role) AfterFind(tx *gorm.DB) (err error) {
	m.MetaData = m.MetaDataRaw.Data
	rules := GetApiRulesForRole(m.Schema, m.Name)
	m.Rules = getApiRuleIdsByRule(rules)
	return nil
}
