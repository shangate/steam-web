package utils

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	HTTP_SUCC = iota
	HTTP_FAIL
	HTTP_ERROR
)

type HttpError struct {
	ErrorCode int
	HttpCode  int
	ErrorMsg  string
}

func NewError(code int, httpCode int, msg string) *HttpError {
	return &HttpError{
		ErrorCode: code,
		HttpCode:  httpCode,
		ErrorMsg:  msg,
	}
}

var globalProxy *url.URL
var globalTransfer *url.URL

func SetGlobalHttpProxy(u string) (err error) {
	globalProxy, err = url.Parse(u)
	return err
}

func SetGlobalHttpTransfer(u string) (err error) {
	globalTransfer, err = url.Parse(u)
	return err
}

func (e *HttpError) Error() string {
	return e.ErrorMsg
}

func HttpWebRequest(method string, requestUrl string, header url.Values,
	query url.Values, cookies []*http.Cookie, body []byte, insecure bool, redirect bool) (
	responseUrl string,
	responseHeader url.Values,
	responseQuery url.Values,
	responseBody []byte,
	responseCookies []*http.Cookie,
	httpError *HttpError,
) {
	oriRequestUrl := requestUrl
	if globalTransfer != nil {
		requestUrl = globalTransfer.String()
	}
	var queryString string
	if len(query) > 0 {
		queryString = query.Encode()
		if queryString != "" {
			requestUrl += "?" + queryString
		}
	}

	var bodyStr string
	if body != nil {
		bodyStr = string(body)
	}

	if bodyStr == "" {
		if method == "POST" && queryString != "" {
			bodyStr = queryString
		}
	}

	req, e := http.NewRequest(method, requestUrl, strings.NewReader(bodyStr))
	if e != nil {
		errorMsg := fmt.Sprintf("httpPost %s new request error", requestUrl)
		return responseUrl, responseHeader, responseQuery, nil, nil, NewError(HTTP_ERROR, 0, errorMsg)
	}
	if header != nil {
		for k, vs := range header {
			for _, v := range vs {
				req.Header.Set(k, v)
			}
		}
	}
	if globalTransfer != nil {
		req.Header.Set("transfer_url", oriRequestUrl)
	}

	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}

	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: insecure},
		DisableKeepAlives: true,
	}
	if globalProxy != nil {
		tr.Proxy = http.ProxyURL(globalProxy)
	}

	client := http.Client{
		Transport: tr,
		Timeout:   30 * time.Second,
	}
	resp, e := client.Do(req)
	var statusCode int
	if resp != nil {
		statusCode = resp.StatusCode
		responseUrl = resp.Request.URL.String()
		responseHeader = make(url.Values)
		for k, vs := range resp.Header {
			for _, v := range vs {
				responseHeader.Add(k, v)
			}
		}
		if len(responseUrl) > 0 {
			u, err := url.Parse(responseUrl)
			if err == nil {
				responseQuery, _ = url.ParseQuery(u.RawQuery)
			}
		}
	}
	if e != nil {
		errorMsg := fmt.Sprintf("httpPost %s do request error", requestUrl)
		return responseUrl, responseHeader, responseQuery, nil, nil, NewError(HTTP_FAIL, statusCode, errorMsg)
	}
	defer resp.Body.Close()
	bodyBytes, e := ioutil.ReadAll(resp.Body)
	if e != nil {
		errorMsg := fmt.Sprintf("httpPost %s output data error", requestUrl)
		return responseUrl, responseHeader, responseQuery, nil, resp.Cookies(), NewError(HTTP_FAIL, statusCode, errorMsg)
	}

	var domain string
	u, err := url.Parse(requestUrl)
	if err == nil {
		domain = u.Hostname()
	}

	cookies = resp.Cookies()
	for i, _ := range cookies {
		if cookies[i].Domain == "" && domain != "" {
			cookies[i].Domain = domain
		}
	}

	return responseUrl, responseHeader, responseQuery, bodyBytes, cookies, httpError
}
