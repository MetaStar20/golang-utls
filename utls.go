package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	tls "github.com/refraction-networking/utls"
	uuid "github.com/satori/go.uuid"
	"github.com/tidwall/gjson"
	"golang.org/x/net/http2"
)

type Bearer_Response struct {
	//Token_type       string `json:"token_type"`
	//Api_product_list string `json:"api_product_list"`
	//Issued_at        string `json:"issued_at"`
	Access_token string `json:"access_token"`
	//Scope            string `json:"scope"`
	//Expires_in       string `json:"expires_in"`
	//Status           string `json:"status"`
	X map[string]interface{} `json:"-"` // Rest of the fields should go here.
}

type Guest_Identity struct {
	Access_token  string `json:"access_token"`
	Refresh_token string `json:"refresh_token"`
}

type Cart struct {
	Cartid string                 `json:"cartId"`
	X      map[string]interface{} `json:"-"` // Rest of the fields should go here.
}

var hostname = "api-prod.lowes.com"     // speaks http2 and TLS 1.3
var hostAddr = "api-prod.lowes.com:443" //23.40.124.118:443
var addr = "api-prod.lowes.com:443"     //23.40.124.118:443
var dialTimeout = time.Duration(15) * time.Second

/**************************** simulate the handshake from wireshark ******************/

func handShakeFromWhareSharkBytes() {

	/**************************************    ClientHelloSpec structure    **************************************************
	type ClientHelloSpec struct {
	CipherSuites       []uint16       // nil => default
	CompressionMethods []uint8        // nil => no compression
	Extensions         []TLSExtension // nil => no extensions
	TLSVersMin uint16 // [1.0-1.3] default: parse from .Extensions, if SupportedVersions ext is not present => 1.0
	TLSVersMax uint16 // [1.2-1.3] default: parse from .Extensions, if SupportedVersions ext is not present => 1.2
	GetSessionID func(ticket []byte) [32]byte
	}	**********************************************************************************************************************/

	config := tls.Config{ServerName: hostname, MinVersion: tls.VersionTLS12}

	dialConn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		fmt.Println("net.DialTimeout error: %+v", err)
	}

	/* establish UClient of UTLS...*/
	uTlsConn := tls.UClient(dialConn, &config, tls.HelloCustom)
	defer uTlsConn.Close()

	// make custom TLS generatedSpec from wireshark captured data.
	byteString := []byte("1603010200010001fc03034243e7dc703824d08998cf9d85325252ee3e600879b05f6e23c0d8812209611d20748229aa4d73af238a22efb6d3ee045f6febd8819edbc2a1ad6b20a0bc4d373c0022130113021303c02cc02bc024c023c00ac009cca9c030c02fc028c027c014c013cca801000191ff010001000000001700150000126170692d70726f642e6c6f7765732e636f6d00170000000d0018001604030804040105030203080508050501080606010201000500050100000000001200000010000e000c02683208687474702f312e31000b00020100003300260024001d002062dcea24a887376e333d5bc6c6a1ae2eda1309e8458942a246feccde1aeed370002d00020101002b00050403040303000a000a0008001d001700180019001500e1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	helloBytes := make([]byte, hex.DecodedLen(len(byteString)))
	_, err = hex.Decode(helloBytes, byteString)
	if err != nil {
		fmt.Println("Hex Decode error..........")
	}

	/* establish UClient of UTLS...*/

	f := &tls.Fingerprinter{}
	generatedSpec, err := f.FingerprintClientHello(helloBytes)

	/* confirm genericSpec... */
	err = uTlsConn.ApplyPreset(generatedSpec)

	if err != nil {
		fmt.Println("uTlsConn.Handshake() ApplyPreset: %+v", err)
	}

	// Handshake runs the client handshake using given clientHandshakeState
	// Requires hs.hello, and, optionally, hs.session to be set.

	err = uTlsConn.Handshake()
	if err != nil {
		fmt.Println("uTlsConn.Handshake() Handshake: %+v", err)
	}

	fmt.Println(".............  UTLS HandShake is completed Successfully  ..........")

}

func httpGetOverConn(conn net.Conn, alpn string) (*http.Response, error) {
	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Host: "www." + hostname + "/"},
		Header: make(http.Header),
		Host:   "www." + hostname,
	}

	switch alpn {
	case "h2":
		req.Proto = "HTTP/2.0"
		req.ProtoMajor = 2
		req.ProtoMinor = 0

		tr := http2.Transport{}
		cConn, err := tr.NewClientConn(conn)
		if err != nil {
			return nil, err
		}
		return cConn.RoundTrip(req)
	case "http/1.1", "":
		req.Proto = "HTTP/1.1"
		req.ProtoMajor = 1
		req.ProtoMinor = 1

		err := req.Write(conn)
		if err != nil {
			return nil, err
		}
		return http.ReadResponse(bufio.NewReader(conn), req)
	default:
		return nil, fmt.Errorf("unsupported ALPN: %v", alpn)
	}
}

func getHttp1xResponse(req *http.Request, conn net.Conn) (*http.Response, error) {
	req.Proto = "HTTP/1.1"
	req.ProtoMajor = 1
	req.ProtoMinor = 1

	err := req.Write(conn)
	if err != nil {
		return nil, err
	}
	return http.ReadResponse(bufio.NewReader(conn), req)
}

func getHttp2Response(req *http.Request, conn net.Conn) (*http.Response, error) {
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0

	tr := http2.Transport{}
	cConn, err := tr.NewClientConn(conn)
	if err != nil {
		return nil, err
	}
	return cConn.RoundTrip(req)
}

func getHttp2ResponseUsingConn(req *http.Request, cCon *http2.ClientConn) (*http.Response, error) {
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	return cCon.RoundTrip(req)
}

func main() {

	// Note that hardcoding the address is not necessary here. Only
	// do that if you want to ignore the DNS lookup that already
	// happened behind the scenes.

	// siumlate utls client hello using packet captured in wireshark.

	byteString := []byte("1603010200010001fc03034243e7dc703824d08998cf9d85325252ee3e600879b05f6e23c0d8812209611d20748229aa4d73af238a22efb6d3ee045f6febd8819edbc2a1ad6b20a0bc4d373c0022130113021303c02cc02bc024c023c00ac009cca9c030c02fc028c027c014c013cca801000191ff010001000000001700150000126170692d70726f642e6c6f7765732e636f6d00170000000d0018001604030804040105030203080508050501080606010201000500050100000000001200000010000e000c02683208687474702f312e31000b00020100003300260024001d002062dcea24a887376e333d5bc6c6a1ae2eda1309e8458942a246feccde1aeed370002d00020101002b00050403040303000a000a0008001d001700180019001500e1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	helloBytes := make([]byte, hex.DecodedLen(len(byteString)))
	_, err := hex.Decode(helloBytes, byteString)
	if err != nil {
		// TLSv1t.Errorf("got error: %v; expected to succeed", err)
		// return nil
		fmt.Println("Hex Decode error..........")
	}

	f := &tls.Fingerprinter{}
	generatedSpec, err := f.FingerprintClientHello(helloBytes)
	if err != nil {
		// t.Errorf("got error: %v; expected to succeed", err)
		fmt.Println("FingerprintClientHello error..........")
	}

	// config := tls.Config{ServerName: "api-prod.lowes.com"}
	// tcpConn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
	// if err != nil {
	// 	fmt.Println("net.DialTimeout error..........")
	// 	return nil, err
	// }

	config := tls.Config{ServerName: hostname, MinVersion: tls.VersionTLS12}

	dialConn, err := net.DialTimeout("tcp", hostAddr, dialTimeout)
	if err != nil {
		fmt.Println("net.DialTimeout error: %+v", err)
	}

	/* establish UClient of UTLS...*/
	uTlsConn := tls.UClient(dialConn, &config, tls.HelloCustom)
	// defer uTlsConn.Close()

	err = uTlsConn.ApplyPreset(generatedSpec)

	if err != nil {
		fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
		fmt.Println("Handshake error..........")
	}

	err = uTlsConn.Handshake()
	if err != nil {
		fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
		fmt.Println("uTlsConn Handshake error..........")
	}

	tr := http2.Transport{}
	cConn, err := tr.NewClientConn(uTlsConn)

	//Setting up first post request to get bearer authorization
	req, err := http.NewRequest("POST", "https://api-prod.lowes.com/oauth2/accesstoken", strings.NewReader("client_id=pGAW7y8NJVlZvoWijVia21K4HzOqskRU&client_secret=zbwMYDyPp4XQS00E&grant_type=client_credentials"))
	//adding header values for accesstoken from iOS mobile app
	req.Header.Add("Host", "api-prod.lowes.com")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", "103")
	req.Header.Add("User-Agent", "LowesMobileApp")
	req.Header.Add("Host", "api-prod.lowes.com")
	//req.Header.Add("Accept-Encoding", "gzip")//disabled since i dont know how to unpack the gzip yet

	// resp, err := client.Do(req)
	resp, err := getHttp2ResponseUsingConn(req, cConn)
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)

	// Error checking of the ioutil.ReadAll() request
	if err != nil {
		log.Fatal(err)
	}

	bodyString := string(bodyBytes)

	fmt.Println("Access Token Response: ", resp.StatusCode)

	bearer_json := new(Bearer_Response)

	if err := json.Unmarshal([]byte(bodyString), bearer_json); err != nil {
		panic(err)
	}
	//fmt.Println(err)
	//fmt.Println(bearer_json)
	//fmt.Println(bearer_json.Access_token)
	bearer_access_token := "Bearer " + string(bearer_json.Access_token)
	x_lowes_uuid := uuid.NewV4().String()
	//fmt.Println(x_lowes_uuid)
	fmt.Println(" - ", bearer_access_token)
	//var x_acf_sensor_data string
	var x_acf_sensor_data string = `2,i,I5Od8wc7Mx8TXBLYDx0GUA2wL92QZXIJ4Cw0hR8AHEwF/gnboZxWa5tpkRhoreYa2kQZAYmoaXiEf4Xybx8BYYFY5fhnZYsAL5rB50U0KjlHGVR2+4ZpXqA3rcsXOMUpdamuhVYLifTvyfJc4TgGp1XUwHkK36cor+hHWa1s9Ps=,gSgpvT5IPcoZi7krwRUi/vBUu8c3OUEMQfr6l/jnsiTesC3luozWcq6ktZqINuIDFKeb8w4yZZh6qqptPeZPVpjFeRI6YaZ0mLDBUOewHXT5F/MGJPTmuX8TKVbC/Hu08wnH0qyLB5E6NumUQvCnHocZ7axuGIQRXYvKTk0DgoY=$rYdDwdDbpPQlWLn15479uHKtjKM9YdE3s6e6B5FM+ZnWtnNyXhU+kCt4uv7681qFCfnlx0rrNN8LspnmrGInGopoZCX6W3jqlNb5zm5zWGUQ+J+WiJ3MNgAg6N/LQ0RNHkbYh0Xmd0eqDsUNf8GHg+Ihhzd5aXYV9I0TS1nFGdouaSikBj28qyewfnIEUQG2Dyj+Uv4CS4hutPlc+ULYcP+T3leYW1RCUrVmKNwLL8+w1oIQH2kodFjsg4vJprU9CEHy90uRyln1gQ+SMcA2GrtFvSr77waVD99H7X315K/o7pucpUQoFiDXggxn6lPoVd33/+qdPEAYk0foF5Hfsg5jmq+W5yZLvZrBcVyKWbJJ8HY0Y/2koL76jUd4YbGVreAhCDFFnJ0JergaupdGOmbgXN2zkRwy+tak9z36m4ef5sCyySAMTFIL8Tdq1/w2ZADT051V7dEZm+heCTAx59zrn/K77F/x72tgVH1hfU9e6UekM12QYlnZ9BUQtRyv518+9tbZ/LN0ojpxYPzeT2ED6EVxlRHgfORY7LgP47l4GSMW41pDe9+CsIPJU7cfzf65bFFh3Y6wnIS3K09GLpMugw/y4VySKKoeR4t3RS/5uFrjsXLUzwyQiL+3LfknSEBOukh0crxeHCR2rgcukSqsslHR88dWWyiuBloSReYc6TpoP4z+aR8CDedBLohmfSaMBoUacw2RDde1l0YfNOrRwn5qXcFHOjePpNFha8fenyQ1wbVZVfmgh8VZ4BYQ25uIYVz+CQyqdVZ/KklY5UgAOnXsa4psgkRQfemM6Nw=$7,5,5$$`
	//var x_acf_sensor_data string = `2,a,A4rFM8O8M0uKbLiXca5Nn/m5E2SCxK6L+qd/e5+SVqouh8lMUWIH7w6To6RoSrY72BbWW6wckpYX90oLH+9IrrsHEH97bpe/kmh1nbSCEN7Afp0YpjKmfArrA+0dc8IpHA6yMiEXWbuGWzxXs93NaQ0hSxmMTTKwQK2obh3oHSU=,C0XzFkP7g9r0W9JEGIk6/oYgVsGplI6f4704xZ4z7CC8lL3NTvEEinUS+V+XQsqCWeMpej4+LpcF1OFpW1utDHeyqXa7vZQxTIWvvfSJDoqBi/K6nEfJWe+L+idWXhDsV6YlzZUeYtWQ+jezKVEAlDI4uSGsDEirYA+jo2obiww=$/ApGtejgS86XEDtAV+xqU9AxiKS0vD3hM3SRxw8F+9VMLvW4fLXVyoucwOZYySRk7JaHiGjp+9/4CDhkHykg7rdw3RrHhPVtvGW8TnZAc+HEeLNeHwZ+WI8QVap5jsgHXxVPqE9hdICYZAvBEqwbfcU3iMYImNhKLS5FVpy6+atfQEROa3fGbDHK9BeZ2ST9xALAnDOAIY5pJSJVW6y7uqFQHoZCBg2qqx5DVEQbomFpPKjAAb2fOGBfciuW/MSkR6ljJomfTdNbsffWgSK5W7XAh51N1XX+HrnGKMnEMy8Xz1H6fDROOMFVIxGrBiIByi22EZ/Gt86VYbgGQgrcs9yvhVFsygVsLFvA9JfxvgpLJ20F55uPNQaPn4wi/yVS1IlgfyisCGhmhwx4V1sBWrgL00Y6cUCXDPv17V88f9XLRHluDQTMQH7/iGqA5839JqhpLhnlDIiss5a7Nxuy1oOpVXrdLNVneFes4uKTVp7TNt99d+jfqo/xEcmGWzaKHzedQDvX9t+3pl9EvNzyhJwO+cL4os4c0Ojr6J82e26Qkw4z7EQ7fWyivfV7rWrZWRuVPtRY4Xxo4JwVn+h6B/amKyk9JCj3MVGYQQhcdHq76ktVCw2qqHal3nGY+sTMsqDprHbbnYPQm2va8Ram81pJA5Z4Dkauv5Eo+UIfPMW2k2G0wTvsMz1AwdDsRgGrqV1e6Q0GpEJgeN7fxdhyjcj2RJx44vK9uKv/r4YEcZlrtfZCT+TwsOWo1PC/sfNfs9QsuzCsOVUFvuRwP+sT4IcSGwZyNkhVHNVmTlSe6kdVettbHaOw6slG6M6Of8YQaPmwCj6yHwhaClTC/yTDKlxtOvdP53fOZS+4Yp8rq+XvuoZUVQR9IUppixvtNUe2F+MCQoXxkz/p1QaOHH9UFiDot5xPbp1P4atnxTrl3Djio0C9RnWi29WGRW3Q/WoJMWDdN2ObYunYJr6Kc3P7xgubEWk+h6sS1wZeGqG+XureH/DGjh/xLFqYxMLL5uJuaDASD2nX74VqxFl7W1p/iyaaJ/jRGc9FNJ6jQAouhwM=$0,4000,0$$`
	//fmt.Println(x_acf_sensor_data)
	time.Sleep(1 * time.Second)
	req2, err := http.NewRequest("POST", "https://api-prod.lowes.com/v1/customer-identity-services/guestidentity/tokens", nil)
	//adding header values for guestidentify from android mobile app
	req2.Header.Add("User-Agent", "LowesMobileApp/21.1.3(Android 5.1.1;LVY48F)")
	req2.Header.Add("Host", "api-prod.lowes.com")
	req2.Header.Add("X-acf-sensor-data", x_acf_sensor_data) //"2,i,I5Od8wc7Mx8TXBLYDx0GUA2wL92QZXIJ4Cw0hR8AHEwF/gnboZxWa5tpkRhoreYa2kQZAYmoaXiEf4Xybx8BYYFY5fhnZYsAL5rB50U0KjlHGVR2+4ZpXqA3rcsXOMUpdamuhVYLifTvyfJc4TgGp1XUwHkK36cor+hHWa1s9Ps=,gSgpvT5IPcoZi7krwRUi/vBUu8c3OUEMQfr6l/jnsiTesC3luozWcq6ktZqINuIDFKeb8w4yZZh6qqptPeZPVpjFeRI6YaZ0mLDBUOewHXT5F/MGJPTmuX8TKVbC/Hu08wnH0qyLB5E6NumUQvCnHocZ7axuGIQRXYvKTk0DgoY=$rYdDwdDbpPQlWLn15479uHKtjKM9YdE3s6e6B5FM+ZnWtnNyXhU+kCt4uv7681qFCfnlx0rrNN8LspnmrGInGopoZCX6W3jqlNb5zm5zWGUQ+J+WiJ3MNgAg6N/LQ0RNHkbYh0Xmd0eqDsUNf8GHg+Ihhzd5aXYV9I0TS1nFGdouaSikBj28qyewfnIEUQG2Dyj+Uv4CS4hutPlc+ULYcP+T3leYW1RCUrVmKNwLL8+w1oIQH2kodFjsg4vJprU9CEHy90uRyln1gQ+SMcA2GrtFvSr77waVD99H7X315K/o7pucpUQoFiDXggxn6lPoVd33/+qdPEAYk0foF5Hfsg5jmq+W5yZLvZrBcVyKWbJJ8HY0Y/2koL76jUd4YbGVreAhCDFFnJ0JergaupdGOmbgXN2zkRwy+tak9z36m4ef5sCyySAMTFIL8Tdq1/w2ZADT051V7dEZm+heCTAx59zrn/K77F/x72tgVH1hfU9e6UekM12QYlnZ9BUQtRyv518+9tbZ/LN0ojpxYPzeT2ED6EVxlRHgfORY7LgP47l4GSMW41pDe9+CsIPJU7cfzf65bFFh3Y6wnIS3K09GLpMugw/y4VySKKoeR4t3RS/5uFrjsXLUzwyQiL+3LfknSEBOukh0crxeHCR2rgcukSqsslHR88dWWyiuBloSReYc6TpoP4z+aR8CDedBLohmfSaMBoUacw2RDde1l0YfNOrRwn5qXcFHOjePpNFha8fenyQ1wbVZVfmgh8VZ4BYQ25uIYVz+CQyqdVZ/KklY5UgAOnXsa4psgkRQfemM6Nw=$7,5,5$$")
	req2.Header.Add("x-lowes-originating-server-hostname", "Android")
	req2.Header.Add("x-lowes-uuid", x_lowes_uuid)
	req2.Header.Add("Authorization", bearer_access_token)
	req2.Header.Add("x-api-version", "v1")
	req2.Header.Add("Content-Length", "0")

	// resp, err = client.Do(req2)
	resp, err = getHttp2ResponseUsingConn(req2, cConn)
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()
	fmt.Println("Guest Identity Response: ", resp.StatusCode)
	if resp.StatusCode == 200 {
		bodyBytes, err = ioutil.ReadAll(resp.Body)

		// Error checking of the ioutil.ReadAll() request
		if err != nil {
			log.Fatal(err)
		}

		bodyString = string(bodyBytes)
		guestidentity_json := new(Guest_Identity)

		if err := json.Unmarshal([]byte(bodyString), guestidentity_json); err != nil {
			panic(err)
		}

		//saving access token for subsequent requests
		var x_access_token string = guestidentity_json.Access_token
		//var x_refresh_token string = guestidentity_json.Refresh_token
		//fmt.Println(" - x-token: ", x_access_token)
		//fmt.Println(" - refresh-token: ", x_refresh_token)

		time.Sleep(2 * time.Second)

		var store_id string = "1019"
		var add_product_data string = `{"cartItems":[{"productInfo":{"omniItemId":"50303879","itemType":"RGL"},"quantity":1}],"zippedInStore":{"storeId":"` + store_id + `"}}`
		//fmt.Println(add_product_data)
		req3, err := http.NewRequest("POST", "https://api-prod.lowes.com/v1/cart-services/additems", strings.NewReader(add_product_data))
		req3.Header.Add("User-Agent", "LowesMobileApp/21.1.3(Android 5.1.1;LVY48F)")
		//req3.Header.Add("X-acf-sensor-data", x_acf_sensor_data) //"2,i,I5Od8wc7Mx8TXBLYDx0GUA2wL92QZXIJ4Cw0hR8AHEwF/gnboZxWa5tpkRhoreYa2kQZAYmoaXiEf4Xybx8BYYFY5fhnZYsAL5rB50U0KjlHGVR2+4ZpXqA3rcsXOMUpdamuhVYLifTvyfJc4TgGp1XUwHkK36cor+hHWa1s9Ps=,gSgpvT5IPcoZi7krwRUi/vBUu8c3OUEMQfr6l/jnsiTesC3luozWcq6ktZqINuIDFKeb8w4yZZh6qqptPeZPVpjFeRI6YaZ0mLDBUOewHXT5F/MGJPTmuX8TKVbC/Hu08wnH0qyLB5E6NumUQvCnHocZ7axuGIQRXYvKTk0DgoY=$rYdDwdDbpPQlWLn15479uHKtjKM9YdE3s6e6B5FM+ZnWtnNyXhU+kCt4uv7681qFCfnlx0rrNN8LspnmrGInGopoZCX6W3jqlNb5zm5zWGUQ+J+WiJ3MNgAg6N/LQ0RNHkbYh0Xmd0eqDsUNf8GHg+Ihhzd5aXYV9I0TS1nFGdouaSikBj28qyewfnIEUQG2Dyj+Uv4CS4hutPlc+ULYcP+T3leYW1RCUrVmKNwLL8+w1oIQH2kodFjsg4vJprU9CEHy90uRyln1gQ+SMcA2GrtFvSr77waVD99H7X315K/o7pucpUQoFiDXggxn6lPoVd33/+qdPEAYk0foF5Hfsg5jmq+W5yZLvZrBcVyKWbJJ8HY0Y/2koL76jUd4YbGVreAhCDFFnJ0JergaupdGOmbgXN2zkRwy+tak9z36m4ef5sCyySAMTFIL8Tdq1/w2ZADT051V7dEZm+heCTAx59zrn/K77F/x72tgVH1hfU9e6UekM12QYlnZ9BUQtRyv518+9tbZ/LN0ojpxYPzeT2ED6EVxlRHgfORY7LgP47l4GSMW41pDe9+CsIPJU7cfzf65bFFh3Y6wnIS3K09GLpMugw/y4VySKKoeR4t3RS/5uFrjsXLUzwyQiL+3LfknSEBOukh0crxeHCR2rgcukSqsslHR88dWWyiuBloSReYc6TpoP4z+aR8CDedBLohmfSaMBoUacw2RDde1l0YfNOrRwn5qXcFHOjePpNFha8fenyQ1wbVZVfmgh8VZ4BYQ25uIYVz+CQyqdVZ/KklY5UgAOnXsa4psgkRQfemM6Nw=$7,5,5$$")
		req3.Header.Add("x-lowes-originating-server-hostname", "Android")
		req3.Header.Add("x-lowes-uuid", x_lowes_uuid)
		req3.Header.Add("Authorization", bearer_access_token)
		req3.Header.Add("x-api-version", "v1")
		req3.Header.Add("x-token", x_access_token)
		req3.Header.Add("business-channel", "DIGITAL_LOWESANDROIDAPP")
		req3.Header.Add("locale", "US")
		req3.Header.Add("customer-segment", `["REGULAR"]`)
		req3.Header.Add("ipAddress", "10.0.0.1")
		req3.Header.Add("x-feature-ods", "true")
		req3.Header.Add("Content-Type", "application/json; charset=UTF-8")
		req3.Header.Add("x-request-client", "android")
		req3.Header.Add("Host", "api-prod.lowes.com")
		//req3.Header.Add("Connection", "Keep-Alive")
		//req3.Header.Add("Accept-Encoding", "gzip")//disabled since i dont know how to unpack the gzip yet

		// resp, err = client.Do(req3)
		resp, err = getHttp2ResponseUsingConn(req3, cConn)
		if err != nil {
			log.Fatalln(err)
		}
		defer resp.Body.Close()
		fmt.Println("Add to cart response: ", resp.StatusCode)

		bodyBytes, err = ioutil.ReadAll(resp.Body)

		if resp.StatusCode == 201 {
			bodyString = string(bodyBytes)
			//fmt.Println(bodyString)
			//Extracting CartId from payload json repsonse
			cart_json := new(Cart)
			if err := json.Unmarshal([]byte(bodyString), cart_json); err != nil {
				panic(err)
			}
			//fmt.Println(cart_json)
			// Error checking of the ioutil.ReadAll() request
			if err != nil {
				log.Fatal(err)
			}
			var cart_id string = cart_json.Cartid
			fmt.Println(" - Cart Id: ", cart_id)

			promo_code := "445455445554556"
			var add_promo_url string = "https://api-prod.lowes.com/v1/cart-services/cartid/" + cart_id + "/promocode"
			var add_promo_data string = `{"promoCodes":["` + promo_code + `"]}`
			//fmt.Println(add_promo_url)

			var loop int = 5
			for i := 1; i <= loop; i++ {
				req4, err := http.NewRequest("PATCH", add_promo_url, strings.NewReader(add_promo_data))
				req4.Header.Add("User-Agent", "LowesMobileApp/21.1.3(Android 5.1.1;LVY48F)")
				req4.Header.Add("X-acf-sensor-data", x_acf_sensor_data)
				req4.Header.Add("x-lowes-originating-server-hostname", "Android")
				req4.Header.Add("x-lowes-uuid", x_lowes_uuid)
				req4.Header.Add("Authorization", bearer_access_token)
				req4.Header.Add("x-api-version", "v1")
				req4.Header.Add("x-request-client", "android")
				req4.Header.Add("x-token", x_access_token)
				req4.Header.Add("business-channel", "DIGITAL_LOWESANDROIDAPP")
				req4.Header.Add("locale", "US")
				req4.Header.Add("customer-segment", `["REGULAR"]`)
				req4.Header.Add("ipAddress", "10.0.0.1")
				req4.Header.Add("x-feature-ods", "true")
				req4.Header.Add("Content-Type", "application/json; charset=UTF-8")
				req4.Header.Add("Content-Length", "34")
				req4.Header.Add("Host", "api-prod.lowes.com")
				req4.Header.Add("Host", "api-prod.lowes.com")
				//req3.Header.Add("Connection", "Keep-Alive")
				//req3.Header.Add("Accept-Encoding", "gzip")//disabled since i dont know how to unpack the gzip yet
				time.Sleep(1 * time.Second)
				//add coupon to shopping cart

				resp, err = getHttp2ResponseUsingConn(req4, cConn)
				if err != nil {
					log.Fatalln(err)
				}
				defer resp.Body.Close()
				fmt.Println("Add promocode response: ", resp.StatusCode)

				bodyBytes, err = ioutil.ReadAll(resp.Body)
				if resp.StatusCode == 403 {
					fmt.Printf("*****We have been banned after %d attempts. Need to wait 15 minutes now. Exiting", i)
					break
				}
				if resp.StatusCode == 200 {
					bodyString = string(bodyBytes)

					// Save validation response into variable
					var isValid = gjson.Get(bodyString, "coupons.#.isValid").Bool()
					fmt.Println(isValid)
					if isValid {
						fmt.Println(" - Promocode is Valid: ", promo_code)
					} else {
						fmt.Println(" - Promocode is not Valid: ", promo_code)
					}

				}
				time.Sleep(time.Duration(rand.Intn(1500)) * time.Millisecond)
			}

		}
	} else {
		fmt.Println("GuestIdentity blocked: ", resp.StatusCode)
	}

}
