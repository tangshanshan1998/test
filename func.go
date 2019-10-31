package gosdk

import (
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func GetIp() string {
	var ip string
	if os.Getenv("SERVER_ADDR") != "" && !strings.EqualFold(os.Getenv("SERVER_ADDR"), "unknown") {
		ip = os.Getenv("SERVER_ADDR")
	}
	if ip == "" {
		ip = "0.0.0.0"
	}
	//7位-15位，由数字和.组成
	regs, _ := regexp.Compile(`[\d.]{7,15}`)
	str := regs.FindAllString(ip, -1)
	if len(str) > 0 {
		return str[0]
	}
	return ""
}

func GetPort(head http.Header) string {
	if head.Get("SERVER_PORT") != "" {
		return head.Get("SERVER_PORT")
	}
	return "0"
}

func Zipkin_timestamp() string {
	localTime := time.Now().UnixNano()
	return strconv.FormatInt(localTime/1000, 10)
}
