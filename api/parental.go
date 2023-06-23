package api

import (
	"fmt"
	"net/http"
	"steam-web/status"
	"steam-web/utils"
)

const (
	STEAM_PARENTAL_WEBAPI        = STEAM_COMMUNITY_WEB_BASE + "/parental"
	STEAM_PARENTAL_UNLOCK_WEBAPI = STEAM_COMMUNITY_WEB_BASE + "/parental/ajaxunlock"
)

const (
	STEAM_PARENTAL_REQUEST_ERROR = iota + 600000
)

func requestParental(session SteamCommunitySession) ([]*http.Cookie, *status.Exception) {
	headers := getDefaultMobileHeader()
	if session.Cookies == nil {
		session.Cookies = getSteamAuthCookies(session)
	}
	_, _, _, _, responseCookies, httpError := utils.HttpWebRequest("GET", STEAM_PARENTAL_WEBAPI, headers, nil, session.Cookies, nil, false, true)
	if httpError != nil {
		return nil, status.NewError(STEAM_PARENTAL_REQUEST_ERROR, fmt.Sprintf("Unlock parental error %s", httpError.Error()))
	}
	return responseCookies, nil
}

func UnlockParental(session SteamCommunitySession, pin string) (bool, *status.Exception) {
	parentalCookies, err := requestParental(session)
	if err != nil {
		return false, err
	}
	headers := getDefaultMobileHeader()
	if session.Cookies == nil {
		session.Cookies = getSteamAuthCookies(session)
		session.Cookies = append(session.Cookies, parentalCookies...)
	}

	query := map[string][]string{
		"pin":       {pin},
		"sessionid": {session.SessionId},
	}

	_, _, _, responseData, _, httpError := utils.HttpWebRequest("POST", STEAM_PARENTAL_UNLOCK_WEBAPI, headers, query, session.Cookies, nil, false, false)
	if httpError != nil {
		return false, status.NewError(STEAM_PARENTAL_REQUEST_ERROR, fmt.Sprintf("Unlock parental error %s", httpError.Error()))
	}
	fmt.Println(string(responseData))

	return true, nil
}
