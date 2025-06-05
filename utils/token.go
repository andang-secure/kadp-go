package utils

import (
	"encoding/json"
	"errors"
	"github.com/golang-jwt/jwt/v4"
)

type Userinfo struct {
	UserId                 int64   `json:"user_id"`                  //用户编号
	DomainId               int64   `json:"domain_id"`                //用户当前域编号
	DomainName             string  `json:"domain_name"`              //
	Groups                 []int64 `json:"groups"`                   //用户当前域的组列表
	PasswordChangeRequired bool    `json:"password_change_required"` //需要修改用户密码
	Exp                    int64   `json:"exp"`                      //过期时间
	Pri                    string  `json:"pri"`                      //过期时间
	Pub                    string  `json:"pub"`                      //过期时间
	KeyStorePwd            string  `json:"key_store_pwd"`            //keystore 密码
}

func ParseToken(tokenStr string) (*Userinfo, error) {
	claim, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return []byte("fO3Dg3AD9$dt0KSyi2ZdRN2(OEz8FQ+Zf"), nil
	})
	if err != nil {
		return nil, err
	}

	tokenMap := claim.Claims.(jwt.MapClaims)

	_, ok := tokenMap["userinfo"]
	if !ok {
		return nil, errors.New("token 格式错误")
	}

	u := &Userinfo{}

	err = json.Unmarshal([]byte(tokenMap["userinfo"].(string)), u)
	if err != nil {
		return nil, err
	}

	if u == nil {
		return nil, errors.New("用户信息为空")
	}

	return u, nil
}
