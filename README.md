# GO-SDK

go语言版本的中台服务调用的SDK

### 下载
* 使用git直接clone到本地的$GOPATH/src下

```bash
mkdir -p $GOPATH/src/gosdk
git clone git@gitlab.oneitfarm.com:itfarm/platform_1b6d87f5f7634661b1608918ce25d12f_group/app_r0g2c3ed6rlyqftmbgofqzdavwz1i8km/repo_948e65ad93c04fb8a336a3c5afac30fd.git $GOPATH/src/gosdk

```

* 或使用go mod

```bash
# 修改~/.gitconfig文件，添加
[url "git@gitlab.oneitfarm.com:itfarm/platform_1b6d87f5f7634661b1608918ce25d12f_group/app_r0g2c3ed6rlyqftmbgofqzdavwz1i8km/repo_948e65ad93c04fb8a336a3c5afac30fd.git"]
        insteadOf = https://gitlab.oneitfarm.com/itfarm/gosdk.git
# []中的地址是gosdk在仓库中的地址，insteadof后面是写在项目的go.mod中的地址
# 在go.mod中写（这里可以修改，只要与上面insteadof后面的保持一致即可）
gitlab.oneitfarm.com/itfarm/gosdk latest

# 执行go mod vendor
go mod vendor
```

该sdk使用了github.com/dgrijalva/jwt-go包，使用时请确保$GOPATH/src下有该包，或go.mod中引用该包

### 基本使用

```
// 获取对象，head是请求的HEAD字段，用来解析HEAD中的Authorization中的token
client, err:=gosdk.GetClientInstance(head)

// 对Authorization中的token解析，或对SetToken()中token解析，或SetAppInfo()
client, err = client.SetToken(token)
client, err = client.SetAppInfo(appid, appkey, channel, version)

// 可以使用SetServices()自定义服务地址，或通过serviceKey从环境变量中寻找服务地址（前者优先级高）
// services是map[string]string，key是serviceKey，value是服务地址
client = client.SetServices(services)

// 调用服务
// serviceKey对应服务地址；method是请求的方法，如post、get；api是具体请求的接口地址；params是要传递的参数，是map[string]interface{}的类型；
// alias是服务的别名；contentType是请求的格式，如application/x-www-form-urlencoded;file是上传文件时使用，一般为nil。
resp, err1 = client.Call(serviceKey, method, api, params, alias, contentType, file)

// resp是服务返回的结果，是[]byte数组，转化为string，优化内存
str := (*string)(unsafe.Pointer(&respBytes))

```
