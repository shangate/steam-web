package api

import (
	"net/http"
)

const (
	STEAM_API_WEB_BASE       = "https://api.steampowered.com"
	STEAM_COMMUNITY_WEB_BASE = "https://steamcommunity.com"
	STEAM_STORE_WEB_BASE     = "https://store.steampowered.com"
	STEAM_LOGIN_WEB_BASE     = "https://login.steampowered.com"
	STEAM_HELP_WEB_BASE      = "https://help.steampowered.com"

	STEAM_MOBILE_REQUEST_REFER = STEAM_COMMUNITY_WEB_BASE + "/mobilelogin?oauth_client_id=DE45CD61&oauth_scope=read_profile%20write_profile%20read_client%20write_client"
)

const (
	STEAM_REQUEST_OK = iota
	STEAM_REQUEST_FAIL
	STEAM_REQUEST_ERROR
	STEAM_REQUEST_RETRY
	STEAM_REQUEST_FREQ
	STEAM_REQUEST_INCOMP
)

func getDefaultMobileHeader() map[string][]string {
	return map[string][]string{
		"sec-fetch-site":   {"cross-site"},
		"sec-fetch-mode":   {"cors"},
		"sec-fetch-dest":   {"empty"},
		"X-Requested-With": {"com.valvesoftware.android.steam.community"},
		"Content-Type":     {"application/x-www-form-urlencoded; charset=UTF-8"},
		"Accept":           {"text/javascript, text/html, application/xml, text/xml, */*"},
		"User-Agent":       {"Mozilla/5.0 (Linux; U; Android 4.1.1; en-us; Google Nexus 4 - 4.1.1 - API 16 - 768x1280 Build/JRO03S) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30"},
		"cookie":           {"mobileClient=android; mobileClientVersion=777777 2.1.3"},
		"Referer":          {STEAM_MOBILE_REQUEST_REFER},
	}
}

func getDefaultMobileCooKies() []*http.Cookie {
	return []*http.Cookie{
		{
			Name:   "mobileClientVersion",
			Value:  "0 (2.1.3)",
			Path:   "/",
			Domain: ".steamcommunity.com",
		},
		{
			Name:   "mobileClient",
			Value:  "android",
			Path:   "/",
			Domain: ".steamcommunity.com",
		},
		{
			Name:   "Steam_Language",
			Value:  "english",
			Path:   "/",
			Domain: ".steamcommunity.com",
		},
	}
}

func getCookies(cookies []*http.Cookie, key, domain string) *http.Cookie {
	for _, c := range cookies {
		if c.Domain == domain && c.Name == key {
			return c
		}
	}
	return nil
}
