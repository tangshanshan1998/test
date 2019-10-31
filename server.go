package gosdk

import (
	"github.com/dgrijalva/jwt-go"
	"net/http"
)

type server struct {
	token      *jwt.Token
	tokenExist bool
}

var serverInstance = &server{tokenExist: false}

var tokenData map[string]interface{}

func GetServerInstance(header http.Header) *server {
	token1 := GetBearerToken(header)
	if token1 != "" {
		serverInstance.token, _ = jwt.Parse(token1, func(token *jwt.Token) (i interface{}, e error) {
			return token, nil
		})
		if _, ok := serverInstance.token.Claims.(jwt.MapClaims); ok {
			serverInstance.tokenExist = true
		}
	}
	return serverInstance
}

func (server *server) GetTokenData() map[string]interface{} {
	if server.token != nil {
		return nil
	}
	if tokenData == nil {
		tokenData = make(map[string]interface{})
		claims, err := server.token.Claims.(jwt.MapClaims)
		if err {
			for key, value := range claims {
				tokenData[key] = value
			}
		}
	}
	return tokenData
}

func (server *server) GetAppkey() string {
	if server.token != nil {
		return server.token.Claims.(jwt.MapClaims)[TO_APPKEY_KEY].(string)
	}
	return ""
}

func (server *server) GetChannel() string {
	if server.token != nil {
		return server.token.Claims.(jwt.MapClaims)[TO_CHANNEL].(string)
	}
	return ""
}

func (server *server) GetAccountId() string {
	if server.token != nil {
		return server.token.Claims.(jwt.MapClaims)[ACCOUNT_ID_KEY].(string)
	}
	return ""
}

func (server *server) GetSubOrgKey() string {
	if server.token != nil {
		return server.token.Claims.(jwt.MapClaims)[SUB_ORG_KEY_KEY].(string)
	}
	return ""
}

func (server *server) GetUserInfo() map[string]string {
	if server.token != nil {
		return server.token.Claims.(jwt.MapClaims)[USER_INFO_KEY].(map[string]string)
	}
	return nil
}

func (server *server) GetFromAppkey() string {
	if server.token != nil {
		return server.token.Claims.(jwt.MapClaims)[FROM_APPKEY_KEY].(string)
	}
	return ""
}
func (server *server) GetFromChannel() string {
	if server.token != nil {
		return server.token.Claims.(jwt.MapClaims)[FROM_CHANNEL_KEY].(string)
	}
	return ""
}
func (server *server) GetFromAppid() string {
	if server.token != nil {
		return server.token.Claims.(jwt.MapClaims)[FROM_APPID_KEY].(string)
	}
	return ""
}
func (server *server) GetCallStack() []map[string]string {
	if server.token != nil {
		return server.token.Claims.(jwt.MapClaims)[CALL_STACK_KEY].([]map[string]string)
	}
	return nil
}
