package api

import (
	"encoding/json"
	"fmt"
	"github.com/shangate/steam-web/status"
	"github.com/shangate/steam-web/utils"
)

const (
	STEAM_USER_DATA_WEBAPI          = STEAM_STORE_WEB_BASE + "/dynamicstore/userdata"
	STEAM_REGISTER_CDKEY_WEBAPI     = STEAM_STORE_WEB_BASE + "/account/ajaxregisterkey"
	STEAM_REDEEM_WALLET_CODE_WEBAPI = STEAM_STORE_WEB_BASE + "/account/ajaxredeemwalletcode"
)

const (
	STEAM_STORE_REQUEST_ERROR = iota + 300000
	GET_USER_OWNED_APPS_ERROR
	REGISTER_CDKEY_ERROR
)

type UserData struct {
	OwnedApps []int `json:"rgOwnedApps"`
}

func GetUserData(session SteamCommunitySession) (useData UserData, err *status.Exception) {
	headers := getDefaultMobileHeader()
	if session.Cookies == nil {
		session.Cookies = getSteamAuthCookies(session)
	}

	_, _, _, responseData, _, httpError := utils.HttpWebRequest("GET", STEAM_USER_DATA_WEBAPI, headers, nil, session.Cookies, nil, false, false)
	if httpError != nil {
		return useData, status.NewError(GET_USER_OWNED_APPS_ERROR, fmt.Sprintf("Get User owned apps error %s", httpError.Error()))
	}
	e := json.Unmarshal(responseData, &useData)
	if e != nil {
		return useData, status.NewError(STEAM_REQUEST_INCOMP, fmt.Sprintf("Data incompatible error %s", e.Error()))
	}
	return useData, nil
}

func RegisterCDKey(session SteamCommunitySession, cdKey string) (bool, *status.Exception) {
	headers := getDefaultMobileHeader()
	if session.Cookies == nil {
		session.Cookies = getSteamAuthCookies(session)
	}

	query := map[string][]string{
		"product_key": {cdKey},
		"sessionid":   {session.SessionId},
	}

	_, _, _, _, _, httpError := utils.HttpWebRequest("POST", STEAM_REGISTER_CDKEY_WEBAPI, headers, query, session.Cookies, nil, false, false)
	if httpError != nil {
		return false, status.NewError(REGISTER_CDKEY_ERROR, fmt.Sprintf("register cdkey error %s", httpError.Error()))
	}
	return true, nil
}

func RedeemWalletCode(session SteamCommunitySession, code string) (bool, *status.Exception) {
	headers := getDefaultMobileHeader()
	if session.Cookies == nil {
		session.Cookies = getSteamAuthCookies(session)
	}

	query := map[string][]string{
		"wallet_code": {code},
		"sessionid":   {session.SessionId},
	}

	_, _, _, _, _, httpError := utils.HttpWebRequest("POST", STEAM_REDEEM_WALLET_CODE_WEBAPI, headers, query, session.Cookies, nil, false, false)
	if httpError != nil {
		return false, status.NewError(REGISTER_CDKEY_ERROR, fmt.Sprintf("register cdkey error %s", httpError.Error()))
	}
	return true, nil
}
