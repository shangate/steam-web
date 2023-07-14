package api

import (
	"encoding/json"
	"fmt"
	"github.com/shangate/steam-web/status"
	"github.com/shangate/steam-web/utils"
	"strings"
)

const (
	STEAM_PARENTAL_UNLOCK_WEBAPI = STEAM_COMMUNITY_WEB_BASE + "/parental/ajaxunlock"
)

const (
	STEAM_PARENTAL_REQUEST_ERROR = iota + 600000
)

type parentalResponse struct {
	Success bool `json:"success"`
	EResult int  `json:"eresult"`
}

func IsNeedParentalLock(session SteamCommunitySession) (bool, *status.Exception) {
	headers := getDefaultMobileHeader()
	if session.Cookies == nil {
		session.Cookies = getSteamAuthCookies(session)
	}

	_, _, _, responseData, _, httpError := utils.HttpWebRequest("GET", STEAM_STORE_WEB_BASE, headers, nil, session.Cookies, nil, false, false)
	if httpError != nil {
		return false, status.NewError(STEAM_PARENTAL_REQUEST_ERROR, fmt.Sprintf("unlock parental lock error %s", httpError.Error()))
	}
	return strings.Contains(string(responseData), "家庭监护") || strings.Contains(string(responseData), "Family View"), nil
}

func UnlockParentalLock(session *SteamCommunitySession, code string) (bool, *status.Exception) {
	headers := getDefaultMobileHeader()
	if session.Cookies == nil {
		session.Cookies = getSteamAuthCookies(*session)
	}

	query := map[string][]string{
		"pin":       {code},
		"sessionid": {session.SessionId},
	}

	_, _, _, responseData, responseCookies, httpError := utils.HttpWebRequest("POST", STEAM_PARENTAL_UNLOCK_WEBAPI, headers, query, session.Cookies, nil, false, false)
	if httpError != nil {
		return false, status.NewError(STEAM_PARENTAL_REQUEST_ERROR, fmt.Sprintf("unlock parental lock error %s", httpError.Error()))
	}
	var response parentalResponse
	e := json.Unmarshal(responseData, &response)
	if e != nil {
		return false, status.NewError(STEAM_PARENTAL_REQUEST_ERROR, fmt.Sprintf("unlock parental lock error %s", e.Error()))
	}
	if response.Success {
		session.Cookies = append(session.Cookies, responseCookies...)
	}
	return response.Success, nil
}
