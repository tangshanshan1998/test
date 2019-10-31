package gosdk

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type client struct {
	header          http.Header
	services        map[string]string
	connectTimeout  float64
	timeout         float64
	concurrency     int
	token           string
	isTokenIssuer   bool
	accountId       string
	subOrgKey       string
	baseAccountInfo map[string]string
	appSecret       string
	callStacks      []map[string]string
	targetInfo      map[string]string
	currentInfo     map[string]string
	inited          bool
}

var clientInstance = &client{
	services:       make(map[string]string),
	connectTimeout: CONNECT_TIMEOUT,
	timeout:        TIMEOUT,
	concurrency:    DEFAULT_CONCURRENCY,
	isTokenIssuer:  true,
	callStacks:     make([]map[string]string, 0),
	targetInfo:     map[string]string{"appid": "", "appkey": "", "channel": "0", "alias": ""},
	currentInfo:    map[string]string{"appid": "", "appkey": "", "channel": "0"},
	inited:         false}

var gatewayUrl = ""

var once sync.Once

func GetClientInstance(header http.Header) (*client, *CommError) {
	var err *CommError
	once.Do(func() {
		err = clientInstance.parseTokenInfo(header)
		clientInstance.initBaseInfo()
	})

	clientInstance.header = header
	return clientInstance, err
}

func (client *client) parseTokenInfo(header http.Header) *CommError {
	server := GetServerInstance(header)
	if server.tokenExist {
		claim := server.GetTokenData()
		err := client.parseClaims(claim)
		client.inited = true
		return err
	}
	return nil
}

func (client *client) parseClaims(claim map[string]interface{}) *CommError {
	var flag = false
	if value, ok := claim[TO_APPID_KEY]; fmt.Sprintf("%T", value) == "string" && ok {
		if value, ok := claim[TO_APPKEY_KEY]; fmt.Sprintf("%T", value) == "string" && ok {
			if value, ok := claim[TO_CHANNEL]; fmt.Sprintf("%T", value) == "string" && ok {
				client.currentInfo["appid"] = claim[TO_APPID_KEY].(string)
				client.currentInfo["appkey"] = claim[TO_APPKEY_KEY].(string)
				client.currentInfo["channel"] = claim[TO_CHANNEL].(string)
				flag = true
			}
		}
	}
	if !flag {
		return &CommError{TOKEN_INVALID, "The token is not valid"}
	}
	if value, ok := claim[CALL_STACK_KEY]; fmt.Sprintf("%T", value) == "[]map[string]string" && ok {
		client.callStacks = claim[CALL_STACK_KEY].([]map[string]string)
	}
	if value, ok := claim[ACCOUNT_ID_KEY]; fmt.Sprintf("%T", value) == "string" && ok {
		client.accountId = claim[ACCOUNT_ID_KEY].(string)
	}
	if value, ok := claim[SUB_ORG_KEY_KEY]; fmt.Sprintf("%T", value) == "string" && ok {
		client.subOrgKey = claim[SUB_ORG_KEY_KEY].(string)
	}
	if value, ok := claim[USER_INFO_KEY]; fmt.Sprintf("%T", value) == "map[string]string" && ok {

		if client.IsCallerApp() {
			if claim[USER_INFO_KEY].(map[string]string)["name"] != "" {
				client.baseAccountInfo["name"] = claim[USER_INFO_KEY].(map[string]string)["name"]
			}
			if claim[USER_INFO_KEY].(map[string]string)["avatar"] != "" {
				client.baseAccountInfo["avatar"] = claim[USER_INFO_KEY].(map[string]string)["avatar"]
			}
		}
	}
	return nil
}

func (client *client) initBaseInfo() {
	if gatewayUrl == "" {
		envGateway := os.Getenv(GATEWAY_SERVICE_KEY)
		if envGateway != "" {
			gatewayUrl = strings.TrimRight(os.Getenv(GATEWAY_SERVICE_KEY), " \t\n\r/")
			gatewayUrl = gatewayUrl + "/"
		}
	}
}

func (client *client) SetServices(services map[string]string) *client {
	for k, v := range services {
		client.services[k] = strings.TrimRight(v, "/") + "/"
	}
	return client
}

func (client *client) SetAccountId(accountId string) *client {
	if accountId != "" {
		client.accountId = accountId
	}
	return client
}

func (client *client) SetUserInfo(userInfo map[string]string) *client {
	if !client.IsCallerApp() {
		return client
	}
	if userInfo["name"] != "" {
		client.baseAccountInfo["name"] = userInfo["name"]
	}
	if userInfo["avatar"] != "" {
		client.baseAccountInfo["avatar"] = userInfo["avatar"]
	}
	return client
}

func (client *client) IsCallerApp() bool {
	if len(client.callStacks) == 0 {
		return true
	}
	return false
}

func (client *client) SetConnectTimeout(timeOut float64) *client {
	client.connectTimeout = timeOut / 1000
	return client
}

func (client *client) SetTimeout(timeOut float64) *client {
	client.timeout = timeOut / 1000
	return client
}

func (client *client) SetConcurrency(num int) *client {
	if num > 0 && num < MAX_CONCURRENCY {
		client.concurrency = num
	}
	return client
}

func (client *client) SetToken(tokenString string) (*client, *CommError) {
	if tokenString == "" {
		return client, nil
	}
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (i interface{}, e error) {
		return token, nil
	})
	tokenIssuer := token.Claims.(jwt.MapClaims)["iss"]
	isTokenIssuer := false
	if tokenIssuer == ISS {
		isTokenIssuer = true
	}
	if isTokenIssuer && getSigner().Verify(tokenString, token.Signature, client.appSecret) == nil {
		originClaims := token.Claims.(jwt.MapClaims)
		claims := make(map[string]interface{})
		for k, v := range originClaims {
			claims[k] = v
		}
		err := client.parseClaims(claims)
		client.isTokenIssuer = true
		client.inited = true
		return client, err
	}
	return client, nil
}

func getSigner() *jwt.SigningMethodHMAC {
	return jwt.SigningMethodHS256
}

func (client *client) SetSubOrgKey(subOrgKey string) *client {
	if subOrgKey != "" {
		client.subOrgKey = subOrgKey
	}
	return client
}

func (client *client) SetAppInfo(appid string, appkey string, channel string, version string) (*client, *CommError) {
	if !client.IsCallerApp() {
		return nil, &CommError{CAN_NOT_CALL_THIS_METHOD, "This method can only called by first app"}
	}
	if appid == "" || appkey == "" {
		return nil, &CommError{INVALID_PARAM, "appid,appkey,channel can not be null and appid,appkey can not be empty"}
	}
	client.callStacks = append(client.callStacks, generateStackRow(appid, appkey, string(channel), "", version))
	client.currentInfo["appid"] = appid
	client.currentInfo["appkey"] = appkey
	client.currentInfo["channel"] = channel
	client.inited = true
	return client, nil
}

func generateStackRow(appid, appkey, channel, alias, version string) map[string]string {
	return map[string]string{"appid": appid, "appkey": appkey, "channel": channel, "alias": alias, "version": version}
}

//请求服务
//serviceName 	servicekey
//method		post,get,put
//api			服务的路径
//data			要传递的数据
//channelAlias 	别名，传入空值时为"default"
//contentType	发送请求的类型，空值为"application/x-www-form-urlencoded"
//file			要上传的文件
func (client *client) Call(serviceName string,
	method string,
	api string,
	data map[string]interface{},
	channelAlias string,
	contentType string,
	files *fileStruct) ([]byte, *CommError) {
	if !client.inited {
		return nil, &CommError{SDK_NOT_INITED, "The sdk is not full inited to process the request"}
	}
	if channelAlias == "" {
		channelAlias = DEFAULT_CHANNEL_ALIAS
	}
	if contentType == "" {
		contentType = CONTENT_TYPE_FORM
	}
	client.targetInfo["appid"] = serviceName
	client.GetChannelDataFromEnv(serviceName, channelAlias)
	claims := client.claimsForThisRequest()
	client.makeToken(claims)
	if data == nil {
		data = make(map[string]interface{})
	}
	return client.Exec(serviceName, method, api, data, contentType, files)
}

var channelDatas = make(map[string]interface{})

func (client *client) GetChannelDataFromEnv(appid, channelAlias string) {
	if _, ok := channelDatas[client.currentInfo["appkey"]]; !ok {
		channelEnv := os.Getenv(DATA_CHANNEL)
		channelEnv = strings.Trim(channelEnv, `'`)
		if channelEnv != "" {
			channelEnvByte := []byte(channelEnv)
			json.Unmarshal(channelEnvByte, &channelDatas)
		}
	}
	appData := channelDatas[client.currentInfo["appkey"]].(map[string]interface{})
	appData = appData[client.currentInfo["channel"]].(map[string]interface{})
	appData = appData[appid].(map[string]interface{})
	appData = appData[channelAlias].(map[string]interface{})
	appkey := appData["target_appkey"].(string)
	appchannel := strconv.FormatFloat(appData["target_channel"].(float64), 'f', -1, 64)
	client.targetInfo = generateStackRow(
		appid,
		appkey,
		appchannel,
		channelAlias,
		"")
}

func (client *client) claimsForThisRequest() MyClaimsForRequest {
	client.generateStackRecord()
	fromChannel, _ := strconv.Atoi(client.currentInfo["channel"])
	channel, _ := strconv.Atoi(client.targetInfo["channel"])
	claims := MyClaimsForRequest{
		client.currentInfo["appid"],
		client.currentInfo["appkey"],
		fromChannel,
		client.targetInfo["appid"],
		client.targetInfo["appkey"],
		channel,
		client.targetInfo["alias"],
		client.accountId,
		client.subOrgKey,
		client.baseAccountInfo,
		client.generateStackRecord(),
		jwt.StandardClaims{
			ExpiresAt: time.Now().Unix() + 60,
			Issuer:    "ItfarmGoSdk",
			IssuedAt:  time.Now().Unix(),
			NotBefore: time.Now().Unix(),
		},
	}
	return claims
}

func (client client) generateStackRecord() []map[string]string {
	tempStack := client.callStacks
	tempStack = append(tempStack, client.targetInfo)
	return tempStack
}

func (client *client) makeToken(claims MyClaimsForRequest) {
	client.token = client.MakeToken(claims)
}

func (client client) MakeToken(claims MyClaimsForRequest) string {
	token := jwt.NewWithClaims(getSigner(), claims)
	result, _ := token.SignedString([]byte(client.getAppSecret()))
	return result
}

func (client client) getAppSecret() string {
	return client.appSecret
}

func (client *client) Exec(serviceName string,
	method string,
	api string,
	data map[string]interface{},
	contentType string,
	file *fileStruct) ([]byte, *CommError) {
	method = strings.ToUpper(method)
	url1, err := client.checkParam(serviceName, method, data)
	if err != nil {
		return nil, err
	}
	api = strings.TrimLeft(api, " \t\n\r/")
	tr := &http.Transport{TLSHandshakeTimeout: time.Duration(client.connectTimeout) * time.Second,
		ResponseHeaderTimeout: time.Duration(client.timeout) * time.Second}
	theClient := &http.Client{Transport: tr, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	var request *http.Request
	var err1 error
	switch contentType {
	case CONTENT_TYPE_FORM:
		theData := url.Values{}
		for k, v := range data {
			theData.Set(k, fmt.Sprint(v))
		}
		request, err1 = http.NewRequest(method, url1+api, strings.NewReader(theData.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	case CONTENT_TYPE_JSON:
		theData := make(map[string]interface{})
		for k, v := range data {
			theData[k] = v
		}
		bytesData, err := json.Marshal(theData)
		if err != nil {
			return nil, &CommError{402, err.Error()}
		}
		request, err1 = http.NewRequest(method, url1+api, bytes.NewReader(bytesData))
		request.Header.Set("Content-Type", "application/json;charset=UTF-8")
	case CONTENT_TYPE_MULTIPART:
		buff := &bytes.Buffer{}
		bodyWriter := multipart.NewWriter(buff)

		// 写入文件
		fileWriter, err := bodyWriter.CreateFormFile(file.fileKey, file.fileName)
		if err != nil {
			return nil, &CommError{402, err.Error()}
		}

		_, err2 := io.Copy(fileWriter, file.file)
		if err2 != nil {
			return nil, &CommError{402, err2.Error()}
		}

		// 写入其他参数
		for k, v := range data {
			err := bodyWriter.WriteField(k, fmt.Sprint(v))
			if err != nil {
				return nil, &CommError{DATA_WRONG_TYPE, "data type wrong"}
			}
		}

		defer bodyWriter.Close()

		request, err1 = http.NewRequest(method, url1+api, buff)
		request.Header.Set("Content-Type", bodyWriter.FormDataContentType())
	default:
		return nil, &CommError{CONTENT_TYPE_ERROR, "content_type should be " + CONTENT_TYPE_FORM + " or " + CONTENT_TYPE_JSON + " or " + CONTENT_TYPE_MULTIPART}
	}
	if err1 != nil {
		return nil, &CommError{NETWORK_CONNECT_ERROR, "new request failed"}
	}

	if client.token != "" {
		request.Header.Set("Authorization", "Bearer "+client.token)
	}
	request.Header.Set("Accept", "application/json")

	if client.header.Get("HTTP_X_FORWARDED_FOR") != "" {
		for _, v := range client.header["HTTP_X_FORWARDED_FOR"] {
			request.Header.Add("X-FORWARDED-FOR", v)
		}

	}
	if client.header.Get("HTTP_X_FORWARDED_PROTO") != "" {
		for _, v := range client.header["HTTP_X_FORWARDED_PROTO"] {
			request.Header.Add("X-FORWARDED-PROTO", v)
		}

	}
	if client.header.Get("HTTP_FRONT_END_HTTPS") != "" {
		for _, v := range client.header["HTTP_FRONT_END_HTTPS"] {
			request.Header.Add("FRONT-END-HTTPS", v)
		}

	}
	request.Header.Set("User-Agent", USER_AGENT+"/"+VERSION)
	if client.header.Get("HTTP_USER_AGENT") != "" {
		for _, v := range client.header["HTTP_USER_AGENT"] {
			request.Header.Add("User-Agent", v)
		}
	}

	response, err2 := theClient.Do(request)
	if err2 != nil {
		return nil, &CommError{NETWORK_CONNECT_ERROR, "connect failed:" + err2.Error()}
	}
	defer response.Body.Close()
	if response.StatusCode == 200 {
		return parseResponse(response)
	} else {
		return requestError(response)
	}

}

func (client *client) checkParam(serviceName string,
	method string,
	data map[string]interface{}) (string, *CommError) {
	baseUrl, err := client.getServiceUrl(serviceName)
	if err != nil {
		return "", err
	}
	method = strings.ToUpper(method)
	allowMethods := []string{"POST", "GET", "PUT"}
	var flag = false
	for _, v := range allowMethods {
		if v == method {
			flag = true
		}
	}
	if !flag {
		return "", &CommError{METHOD_NOT_ALLOWED, "method not allowed"}
	}
	//phpsdk这里还要判断data是否是数组类型，go中就不判断了
	return baseUrl, nil
}

var configServices map[string]string

//获取服务的路径
func (client *client) getServiceUrl(serviceName string) (string, *CommError) {
	//	不是在中台部署的项目可以将项目名和地址存入client.services[]中，已经调用过的服务也会存在该数组中，不用重新查询
	if client.services[serviceName] != "" {
		return client.services[serviceName], nil
	}

	//	在中台部署的项目会帮你在开发空间设置环境变量
	serviceUrl := os.Getenv("DEPLOYMENT_" + serviceName + "_HOST")
	if serviceUrl != "" {
		serviceUrl = strings.TrimRight(serviceUrl, "/") + "/"
		client.services[serviceName] = serviceUrl
		return client.services[serviceName], nil
	} else {
		serviceUrl = os.Getenv("WORKSPACE_" + serviceName + "_HOST")
		if serviceUrl != "" {
			serviceUrl = strings.TrimRight(serviceUrl, "/") + "/"
			client.services[serviceName] = serviceUrl
			return client.services[serviceName], nil
		}
	}
	//	网关+服务名，暂时没用，该网关也是从环境变量中取得，在client初始化时取得，也是中台设置的
	if gatewayUrl != "" {
		client.services[serviceName] = gatewayUrl + serviceName + "/"
		return client.services[serviceName], nil
	}
	if configServices == nil {
		servicesString := os.Getenv("services")
		if servicesString != "" {
			configServices = make(map[string]string)
			data, err := base64.StdEncoding.DecodeString(servicesString)
			if err != nil {
				return "", &CommError{SERVICE_TYPE_ERROR, "services should be json format"}
			}
			err = json.Unmarshal(data, &configServices)
			if err != nil {
				return "", &CommError{SERVICE_TYPE_ERROR, "services should be json format"}
			}
			for k, v := range configServices {
				client.services[k] = strings.TrimRight(v, "/") + "/"
			}
			if client.services[serviceName] == "" {
				return "", &CommError{SERVICE_NOT_FOUND, "service not set"}
			}
			return client.services[serviceName], nil
		}
	}
	return "", &CommError{SERVICE_NOT_FOUND, "Can not find url of service:" + serviceName}
}

func parseResponse(response *http.Response) ([]byte, *CommError) {
	body := response.Body
	result, err := ioutil.ReadAll(body)
	if err != nil {
		return nil, &CommError{RESPONSE_CONTENT_TYPE_ERROR, "invalid json format"}
	}
	return result, nil
}

func requestError(response *http.Response) ([]byte, *CommError) {
	switch response.StatusCode {
	case 401:
		return nil, &CommError{RESPONSE_401, "Unauthorized"}
	case 403:
		return nil, &CommError{RESPONSE_403, "No permission"}
	case 404:
		return nil, &CommError{RESPONSE_404, "api not exist"}
	default:
		return nil, &CommError{RESPONSE_OTHER, "error response:" + response.Status}
	}

}

func (client *client) CallAsApp(serviceName string,
	method string,
	api string,
	data map[string]interface{},
	contentType string,
	multiPart *fileStruct) ([]byte, *CommError) {
	return client.Exec(serviceName, method, api, data, contentType, multiPart)
}

func (client *client) CallByChain(chains []map[string]string,
	method string,
	api string,
	data map[string]interface{},
	contentType string,
	files *fileStruct) ([]byte, *CommError) {
	if !client.inited {
		return nil, &CommError{SDK_NOT_INITED, "The sdk is not full inited to process the request"}
	}
	if gatewayUrl == "" {
		return nil, &CommError{GATEWAY_MISSING, "Can not find the gateway url, so can not process the request"}
	}
	if chains[0]["appid"] != client.currentInfo["appid"] || chains[0]["appkey"] != client.currentInfo["appkey"] || chains[0]["channel"] != client.currentInfo["channel"] {
		return nil, &CommError{0, "The chain does not match the caller info"}
	}
	var isChainValid = true
	var stack = make(map[string]string)
	for _, chain := range chains {
		if chain["appid"] == "" {
			isChainValid = false
			break
		}
		if chain["channelAlias"] == "" {
			if chain["appkey"] == "" {
				isChainValid = false
				break
			}
		}
		stack = generateStackRow(chain["appid"], chain["appkey"], chain["channel"], chain["channelAlias"], "")
	}
	if !isChainValid {
		return nil, &CommError{INVALID_PARAM, "Invalid chains input"}
	}
	if client.services["gateway_chain"] == "" {
		client.services["gateway_chain"] = gatewayUrl + "chain/"
	}
	claims := client.claimsForChainRequest(stack)
	client.makeTokenByChain(claims)
	return client.Exec("gateway_chain", method, api, data, contentType, files)
}

func (client *client) claimsForChainRequest(stack map[string]string) MyClaimsForChainRequest {
	claims := MyClaimsForChainRequest{
		client.accountId,
		client.subOrgKey,
		client.baseAccountInfo,
		append(client.callStacks, stack),
		jwt.StandardClaims{
			ExpiresAt: time.Now().Unix() + 60,
			Issuer:    "ItfarmGoSdk",
			IssuedAt:  time.Now().Unix(),
			NotBefore: time.Now().Unix(),
		},
	}
	return claims
}

func (client *client) makeTokenByChain(claims MyClaimsForChainRequest) {
	client.token = client.MakeTokenByChain(claims)
}

func (client client) MakeTokenByChain(claims MyClaimsForChainRequest) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	result, err := token.SignedString([]byte(""))
	fmt.Println(err)
	return result
}

func (client *client) CallServiceInstance(appid string,
	appkey string,
	channel string,
	method string,
	api string,
	param map[string]interface{},
	contentType string,
	files *fileStruct) ([]byte, *CommError) {
	if appid == "" || appkey == "" || channel == "" {
		return nil, &CommError{INVALID_PARAM, "Appid ,appkey can not be null or empty string ,channel can not be null"}
	}
	if !client.inited {
		return nil, &CommError{SDK_NOT_INITED, "The sdk is not full inited , can not process this request"}
	}
	client.targetInfo = generateStackRow(appid, appkey, channel, "", "")
	claims := client.claimsForThisRequest()
	client.makeToken(claims)
	return client.Exec(appid, method, api, param, contentType, files)
}

func (client *client) GetCurrentToken(appid, appkey, channel, alias string) string {
	client.targetInfo = generateStackRow(appid, appkey, channel, alias, "")
	claims := client.claimsForThisRequest()
	client.makeToken(claims)
	return client.token
}

func (client *client) UploadFile(serviceName string,
	api string,
	files *fileStruct,
	data map[string]interface{},
	channelAlias string) ([]byte, *CommError) {
	claims := client.claimsForThisRequest()
	if client.isTokenIssuer {
		client.makeToken(claims)
	}
	return client.Call(serviceName, "POST", api, data, channelAlias, CONTENT_TYPE_MULTIPART, files)

}
