package main

import (
	"fmt"
	"gosdk"
	"net/http"
)

func main() {
	head := http.Header{}
	client, err := gosdk.GetClientInstance(head)
	if err != nil {
		fmt.Println(err)
	}
	client.SetConnectTimeout(10000)
	client.SetTimeout(10000)
	service := "doatnnuotjlwbh6r83jed1m7yvwrps5q"
	method := "POST"
	api := "/main.php/json/register/phone"
	data := map[string]interface{}{"phone": "18612345616", "appkey": "1d73844a68294b76a717e7723f3f52a5", "channel": "2", "captcha": "8888", "password": "123456", "confirm_password": "123456"}
	result, _ := client.Call(service, method, api, data, "default", "application/x-www-form-urlencoded", nil)
	//fmt.Println(string(result))
	//fmt.Println(err)
	//fmt.Println(result)
	fmt.Println(string(result))
	fmt.Println(data)
	fmt.Println(client)
}
