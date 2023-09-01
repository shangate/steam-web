package api

import (
	"encoding/json"
	"fmt"
	"github.com/shangate/steam-web/status"
	"github.com/shangate/steam-web/utils"
	"html"
	"regexp"
	"strconv"
)

const (
	STEAM_USER_DATA_WEBAPI               = STEAM_STORE_WEB_BASE + "/dynamicstore/userdata"
	STEAM_REGISTER_CDKEY_WEBAPI          = STEAM_STORE_WEB_BASE + "/account/ajaxregisterkey"
	STEAM_REDEEM_WALLET_CODE_WEBAPI      = STEAM_STORE_WEB_BASE + "/account/ajaxredeemwalletcode"
	STEAM_DEAUTHORIZE_ALL_DEVICES_WEBAPI = STEAM_STORE_WEB_BASE + "/twofactor/manage_action"
	STEAM_ADD_FREE_LICENSE_WEBAPI        = "https://checkout.steampowered.com/checkout/addfreelicense"
)

const (
	STEAM_STORE_REQUEST_ERROR = iota + 300000
	REGISTER_CDKEY_ERROR
	REGISTER_CDKEY_INCOMPATIBLE_ERROR
	REGISTER_CDKEY_ALREADY_ACTIVATED_IN_THIS_ACCOUNT
	REGISTER_CDKEY_ALREADY_ACTIVATED_IN_OTHER_ACCOUNT
	REGISTER_CDKEY_INVALID_KEY
	REGISTER_CDKEY_ACCOUNT_REGION_INCONSISTENT
	REGISTER_CDKEY_ACCOUNT_NEED_MAIN_GAME
	REGISTER_CDKEY_ACCOUNT_TOO_MANY_REQUEST
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
		return useData, status.NewError(STEAM_STORE_REQUEST_ERROR, fmt.Sprintf("Get User owned apps error %s", httpError.Error()))
	}
	e := json.Unmarshal(responseData, &useData)
	if e != nil {
		return useData, status.NewError(STEAM_REQUEST_INCOMP, fmt.Sprintf("Data incompatible error %s", e.Error()))
	}
	return useData, nil
}

type registerCDKeyResponse struct {
	Success              int `json:"success"`
	PurchaseResultDetail int `json:"purchase_result_details"`
	PurchaseReceiptInfo  struct {
		PurchaseStatus int    `json:"purchase_status"`
		ResultDetail   int    `json:"result_detail"`
		ErrorString    string `json:"error_string"`
	} `json:"purchase_receipt_info"`
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

	_, _, _, responseData, _, httpError := utils.HttpWebRequest("POST", STEAM_REGISTER_CDKEY_WEBAPI, headers, query, session.Cookies, nil, false, false)
	if httpError != nil {
		return false, status.NewError(STEAM_STORE_REQUEST_ERROR, fmt.Sprintf("register cdkey error %s", httpError.Error()))
	}
	var response registerCDKeyResponse
	e := json.Unmarshal(responseData, &response)
	if e != nil {
		return false, status.NewError(REGISTER_CDKEY_INCOMPATIBLE_ERROR, fmt.Sprintf("register cdkey error %s", e.Error()))
	}
	if response.Success != 1 {
		if response.PurchaseResultDetail == 9 {
			return false, status.NewError(REGISTER_CDKEY_ALREADY_ACTIVATED_IN_THIS_ACCOUNT, response.PurchaseReceiptInfo.ErrorString)
		} else if response.PurchaseResultDetail == 13 {
			return false, status.NewError(REGISTER_CDKEY_ACCOUNT_REGION_INCONSISTENT, response.PurchaseReceiptInfo.ErrorString)
		} else if response.PurchaseResultDetail == 14 {
			return false, status.NewError(REGISTER_CDKEY_INVALID_KEY, response.PurchaseReceiptInfo.ErrorString)
		} else if response.PurchaseResultDetail == 15 {
			return false, status.NewError(REGISTER_CDKEY_ALREADY_ACTIVATED_IN_OTHER_ACCOUNT, response.PurchaseReceiptInfo.ErrorString)
		} else if response.PurchaseResultDetail == 24 {
			return false, status.NewError(REGISTER_CDKEY_ACCOUNT_NEED_MAIN_GAME, response.PurchaseReceiptInfo.ErrorString)
		} else if response.PurchaseResultDetail == 53 {
			return false, status.NewError(REGISTER_CDKEY_ACCOUNT_TOO_MANY_REQUEST, response.PurchaseReceiptInfo.ErrorString)
		}
		return false, status.NewError(REGISTER_CDKEY_INVALID_KEY, response.PurchaseReceiptInfo.ErrorString)
	}
	return response.Success == 1, nil
}

func RedeemWalletCode(session *SteamCommunitySession, code string) (bool, *status.Exception) {
	headers := getDefaultMobileHeader()
	if session.Cookies == nil {
		session.Cookies = getSteamAuthCookies(*session)
	}

	query := map[string][]string{
		"wallet_code": {code},
		"sessionid":   {session.SessionId},
	}

	_, _, _, _, _, httpError := utils.HttpWebRequest("POST", STEAM_REDEEM_WALLET_CODE_WEBAPI, headers, query, session.Cookies, nil, false, false)
	if httpError != nil {
		return false, status.NewError(STEAM_STORE_REQUEST_ERROR, fmt.Sprintf("register cdkey error %s", httpError.Error()))
	}
	return true, nil
}

func DeauthorizeAllDevices(session SteamCommunitySession) *status.Exception {
	headers := getDefaultMobileHeader()
	if session.Cookies == nil {
		session.Cookies = getSteamAuthCookies(session)
	}

	query := map[string][]string{
		"action":    {"deauthorize"},
		"sessionid": {session.SessionId},
	}

	_, _, _, _, _, httpError := utils.HttpWebRequest("POST", STEAM_DEAUTHORIZE_ALL_DEVICES_WEBAPI, headers, query, session.Cookies, nil, false, false)
	if httpError != nil {
		return status.NewError(STEAM_STORE_REQUEST_ERROR, fmt.Sprintf("register cdkey error %s", httpError.Error()))
	}

	return nil
}

func AddFreeLicense(session SteamCommunitySession, licenseId string) *status.Exception {
	headers := getDefaultMobileHeader()
	if session.Cookies == nil {
		session.Cookies = getSteamAuthCookies(session)
	}

	query := map[string][]string{
		"ajax":      {"true"},
		"sessionid": {session.SessionId},
	}

	_, _, _, _, _, httpError := utils.HttpWebRequest("POST", STEAM_ADD_FREE_LICENSE_WEBAPI, headers, query, session.Cookies, nil, false, false)
	if httpError != nil {
		return status.NewError(STEAM_STORE_REQUEST_ERROR, fmt.Sprintf("register cdkey error %s", httpError.Error()))
	}

	return nil
}

func GetAccountId(session SteamCommunitySession) (accountId string, err *status.Exception) {
	headers := getDefaultMobileHeader()
	if session.Cookies == nil {
		session.Cookies = getSteamAuthCookies(session)
	}

	_, _, _, responseData, _, httpError := utils.HttpWebRequest("GET", STEAM_COMMUNITY_WEB_BASE+"/profiles/"+session.SteamId, headers, nil, session.Cookies, nil, false, false)
	if httpError != nil {
		return "", status.NewError(STEAM_STORE_REQUEST_ERROR, fmt.Sprintf("get account id error %s", httpError.Error()))
	}
	var userInfoRegex = regexp.MustCompile(`data-userinfo="({.+})`)
	match := userInfoRegex.FindStringSubmatch(string(responseData))
	if len(match) >= 2 {
		jsonStr := html.UnescapeString(match[1])
		var userInfo map[string]interface{}
		if e := json.Unmarshal([]byte(jsonStr), &userInfo); e == nil {
			if accountIdNum, ok := userInfo["accountid"]; ok {
				accountIdInt := int64(0)
				if accountIdInt, ok = accountIdNum.(int64); !ok {
					if accountIdFloat, ok := accountIdNum.(float64); ok {
						accountIdInt = int64(accountIdFloat)
					}
				}
				if accountIdInt != 0 {
					accountId = strconv.FormatInt(accountIdInt, 10)
					return accountId, nil
				}
			}
		}
	}

	return "", status.NewError(REGISTER_CDKEY_INCOMPATIBLE_ERROR, fmt.Sprintf("get account id error data imcompatible"))
}
