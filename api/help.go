package api

import (
	"encoding/json"
	"fmt"
	"github.com/shangate/steam-web/status"
	"github.com/shangate/steam-web/utils"
	"strconv"
	"time"
)

const (
	STEAM_HELP_CHANGE_PASSWORD               = STEAM_HELP_WEB_BASE + "/wizard/HelpChangePassword?redir=store/account"
	STEAM_HELP_WITH_LOGIN_INFO_ENTER_CODE    = STEAM_HELP_WEB_BASE + "/wizard/HelpWithLoginInfoEnterCode"
	STEAM_SEND_ACCOUNT_RECOVERY_CODE         = STEAM_HELP_WEB_BASE + "/wizard/AjaxSendAccountRecoveryCode"
	STEAM_POLL_ACCOUNT_RECOVERY_CONFIRMATION = STEAM_HELP_WEB_BASE + "/wizard/AjaxPollAccountRecoveryConfirmation"
	STEAM_VERIFY_ACCOUNT_RECOVERY_CODE       = STEAM_HELP_WEB_BASE + "/wizard/AjaxVerifyAccountRecoveryCode"
	STEAM_ACCOUNT_RECOVERY_GET_NEXT_STEP     = STEAM_HELP_WEB_BASE + "/wizard/AjaxAccountRecoveryGetNextStep"
	STEAM_ACCOUNT_RECOVERY_VERIFY_PASSWORD   = STEAM_HELP_WEB_BASE + "/wizard/AjaxAccountRecoveryVerifyPassword"
	STEAM_CHECK_PASSWORD_AVAILABLE           = STEAM_HELP_WEB_BASE + "/wizard/AjaxCheckPasswordAvailable"
	STEAM_ACCOUNT_RECOVERY_CHANGE_PASSWORD   = STEAM_HELP_WEB_BASE + "/wizard/AjaxAccountRecoveryChangePassword"
)

const (
	STEAM_HELP_REQUEST_ERROR = iota + 200000
	RECEIVE_PASSWORD_CHANGE_PARAMS_ERROR
	LOGIN_INFO_ENTER_CODE_ERROR
	SEND_ACCOUNT_RECOVERY_CODE_ERROR
	POLL_ACCOUNT_RECOVERY_CONFIRMATION_ERROR
	VERIFY_ACCOUNT_RECOVERY_CODE_ERROR
	RECOVER_VERIFY_PASSWORD_ERROR
	GET_NEXT_STEP_FOR_ACCOUNT_RECOVERY_ERROR
	CHECK_PASSWORD_AVAILABLE_ERROR
	CHANGE_PASSWORD_REQUEST_ERROR
	CHANGE_PASSWORD_REQUEST_FAIL
)

type PasswordChangeParams struct {
	S            int `json:"s"`
	Account      int `json:"account"`
	Reset        int `json:"reset"`
	Issueid      int `json:"issueid"`
	Lost         int `json:"lost"`
	NeedPassword int `json:"need_password"`
}

func receivePasswordChangeParams(session SteamCommunitySession) (params PasswordChangeParams, err *status.Exception) {
	if session.Cookies == nil {
		session.Cookies = getSteamAuthCookies(session)
	}
	header := map[string][]string{
		"Content-Type": {"application/x-www-form-urlencoded; charset=UTF-8"},
		"Accept":       {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
		"User-Agent":   {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"},
		"cookie":       {"mobileClient=android; mobileClientVersion=777777 3.0.0"},
		"Referer":      {STEAM_STORE_WEB_BASE},
	}
	_, _, responseQuery, _, _, requestError := utils.HttpWebRequest("GET", STEAM_HELP_CHANGE_PASSWORD, header, nil, session.Cookies, nil, true, true)
	if requestError != nil {
		return params, status.NewError(RECEIVE_PASSWORD_CHANGE_PARAMS_ERROR, fmt.Sprintf("Receive password change params Error %s", requestError.Error()))
	}

	if needPassword, ok := responseQuery["need_password"]; ok && len(needPassword) >= 0 {
		params.NeedPassword, _ = strconv.Atoi(needPassword[0])
		if params.NeedPassword == 1 {
			return params, status.NewError(CHANGE_PASSWORD_REQUEST_FAIL, fmt.Sprintf("Change password failed need password!"))
		}
	}
	if account, ok := responseQuery["account"]; !ok || len(account) <= 0 {
		return params, status.NewError(STEAM_REQUEST_INCOMP, fmt.Sprintf("Data incompatible error doesn't have account!"))
	} else {
		params.Account, _ = strconv.Atoi(account[0])
	}
	if s, ok := responseQuery["s"]; !ok || len(s) <= 0 {
		return params, status.NewError(STEAM_REQUEST_INCOMP, fmt.Sprintf("Data incompatible error doesn't have s!"))
	} else {
		params.S, _ = strconv.Atoi(s[0])
	}
	if issueId, ok := responseQuery["issueid"]; !ok || len(issueId) <= 0 {
		return params, status.NewError(STEAM_REQUEST_INCOMP, fmt.Sprintf("Data incompatible error doesn't have issueid!"))
	} else {
		params.Issueid, _ = strconv.Atoi(issueId[0])
	}
	if lost, ok := responseQuery["lost"]; ok && len(lost) > 0 {
		params.Lost, _ = strconv.Atoi(lost[0])
	}
	if reset, ok := responseQuery["reset"]; ok && len(reset) > 0 {
		params.Reset, _ = strconv.Atoi(reset[0])
	}
	return params, nil
}

func loginInfoEnterCode(session SteamCommunitySession, params PasswordChangeParams) *status.Exception {
	header := map[string][]string{
		"X-Requested-With": {"XMLHttpRequest"},
		"Content-Type":     {"application/x-www-form-urlencoded; charset=UTF-8"},
		"Accept":           {"*/*"},
		"User-Agent":       {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"},
	}
	query := map[string][]string{
		"s":           {strconv.FormatInt(int64(params.S), 10)},
		"account":     {strconv.FormatInt(int64(params.Account), 10)},
		"reset":       {strconv.FormatInt(int64(params.Reset), 10)},
		"lost":        {strconv.FormatInt(int64(params.Lost), 10)},
		"issueid":     {strconv.FormatInt(int64(params.Issueid), 10)},
		"wizard_ajax": {"1"},
		"gamepad":     {"0"},
	}
	if session.Cookies != nil {
		cookie := getCookies(session.Cookies, "sessionid", "help.steampowered.com")
		if cookie != nil {
			query["sessionid"] = []string{cookie.Value}
		}
	} else {
		session.Cookies = getSteamAuthCookies(session)
	}
	_, _, _, _, _, requestError := utils.HttpWebRequest("GET", STEAM_HELP_WITH_LOGIN_INFO_ENTER_CODE, header, query, session.Cookies, nil, true, true)
	if requestError != nil {
		return status.NewError(LOGIN_INFO_ENTER_CODE_ERROR, fmt.Sprintf("Login info enter code error %s", requestError.Error()))
	}
	return nil
}

type SendAccountRecoveryCodeResponse struct {
	Success bool `json:"success"`
}

func sendAccountRecoveryCode(session SteamCommunitySession, params PasswordChangeParams) (SendAccountRecoveryCodeResponse, *status.Exception) {
	header := map[string][]string{
		"X-Requested-With": {"XMLHttpRequest"},
		"Content-Type":     {"application/x-www-form-urlencoded; charset=UTF-8"},
		"Accept":           {"*/*"},
		"User-Agent":       {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"},
		"Origin":           {STEAM_HELP_WEB_BASE},
	}
	query := map[string][]string{
		"s":           {strconv.FormatInt(int64(params.S), 10)},
		"wizard_ajax": {"1"},
		"gamepad":     {"0"},
		"method":      {"8"},
		"link":        {""},
	}
	if session.Cookies != nil {
		cookie := getCookies(session.Cookies, "sessionid", "help.steampowered.com")
		if cookie != nil {
			query["sessionid"] = []string{cookie.Value}
		}
	} else {
		session.Cookies = getSteamAuthCookies(session)
	}
	var response SendAccountRecoveryCodeResponse
	_, _, _, responseData, _, requestError := utils.HttpWebRequest("POST", STEAM_SEND_ACCOUNT_RECOVERY_CODE, header, query, session.Cookies, nil, true, true)
	if requestError != nil {
		return response, status.NewError(SEND_ACCOUNT_RECOVERY_CODE_ERROR, fmt.Sprintf("send account recovery code error %s", requestError.Error()))
	}
	e := json.Unmarshal(responseData, &response)
	if e != nil {
		return response, status.NewError(STEAM_REQUEST_INCOMP, "Data incompatible error with SendAccountRecoveryCodeResponse!")
	}
	return response, nil
}

type PollAccountRecoveryConfirmation struct {
	Success  bool `json:"success"`
	Continue bool `json:"continue"`
}

func pollAccountRecoveryConfirmation(session SteamCommunitySession, params PasswordChangeParams) (PollAccountRecoveryConfirmation, *status.Exception) {
	header := map[string][]string{
		"X-Requested-With": {"XMLHttpRequest"},
		"Content-Type":     {"application/x-www-form-urlencoded; charset=UTF-8"},
		"Accept":           {"*/*"},
		"User-Agent":       {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"},
		"Origin":           {STEAM_HELP_WEB_BASE},
	}
	query := map[string][]string{
		"s":           {strconv.FormatInt(int64(params.S), 10)},
		"reset":       {strconv.FormatInt(int64(params.Reset), 10)},
		"lost":        {strconv.FormatInt(int64(params.Lost), 10)},
		"issueid":     {strconv.FormatInt(int64(params.Issueid), 10)},
		"wizard_ajax": {"1"},
		"gamepad":     {"0"},
		"method":      {"8"},
	}
	if session.Cookies != nil {
		cookie := getCookies(session.Cookies, "sessionid", "help.steampowered.com")
		if cookie != nil {
			query["sessionid"] = []string{cookie.Value}
		}
	} else {
		session.Cookies = getSteamAuthCookies(session)
	}
	var response PollAccountRecoveryConfirmation
	_, _, _, responseData, _, requestError := utils.HttpWebRequest("POST", STEAM_POLL_ACCOUNT_RECOVERY_CONFIRMATION, header, query, session.Cookies, nil, true, true)
	if requestError != nil {
		return response, status.NewError(POLL_ACCOUNT_RECOVERY_CONFIRMATION_ERROR, fmt.Sprintf("Poll account recovery confirmation error %s", requestError.Error()))
	}
	e := json.Unmarshal(responseData, &response)
	if e != nil {
		return response, status.NewError(STEAM_REQUEST_INCOMP, "Data incompatible error with PollAccountRecoveryConfirmation!")
	}
	return response, nil
}

type VerifyAccountRecoveryCodeResponse struct {
	Hash     string `json:"hash"`
	ErrorMsg string `json:"errorMsg"`
}

func verifyAccountRecoveryCode(session SteamCommunitySession, params PasswordChangeParams) (VerifyAccountRecoveryCodeResponse, *status.Exception) {
	header := map[string][]string{
		"X-Requested-With": {"XMLHttpRequest"},
		"Content-Type":     {"application/x-www-form-urlencoded; charset=UTF-8"},
		"Accept":           {"*/*"},
		"User-Agent":       {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"},
		"Origin":           {STEAM_HELP_WEB_BASE},
	}
	query := map[string][]string{
		"code":        {""},
		"s":           {strconv.FormatInt(int64(params.S), 10)},
		"reset":       {strconv.FormatInt(int64(params.Reset), 10)},
		"lost":        {strconv.FormatInt(int64(params.Lost), 10)},
		"method":      {"8"},
		"account":     {strconv.FormatInt(int64(params.Account), 10)},
		"issueid":     {strconv.FormatInt(int64(params.Issueid), 10)},
		"wizard_ajax": {"1"},
		"gamepad":     {"0"},
	}
	if session.Cookies != nil {
		cookie := getCookies(session.Cookies, "sessionid", "help.steampowered.com")
		if cookie != nil {
			query["sessionid"] = []string{cookie.Value}
		}
	} else {
		session.Cookies = getSteamAuthCookies(session)
	}

	var response VerifyAccountRecoveryCodeResponse
	_, _, _, responseData, _, requestError := utils.HttpWebRequest("POST", STEAM_VERIFY_ACCOUNT_RECOVERY_CODE, header, query, session.Cookies, nil, true, true)
	if requestError != nil {
		return response, status.NewError(VERIFY_ACCOUNT_RECOVERY_CODE_ERROR, fmt.Sprintf("Verify account recovery code error %s", requestError.Error()))
	}
	e := json.Unmarshal(responseData, &response)
	if e != nil {
		return response, status.NewError(STEAM_REQUEST_INCOMP, "Data incompatible error with VerifyAccountRecoveryCodeResponse!")
	}
	if response.ErrorMsg != "" {
		return response, status.NewError(CHANGE_PASSWORD_REQUEST_FAIL, response.ErrorMsg)
	}
	return response, nil
}

type RecoveryPasswordResponse struct {
	Hash     string `json:"hash"`
	ErrorMsg string `json:"errorMsg"`
}

func recoveryVerifyPassword(session SteamCommunitySession, encryptedPassword string, rsaTimestamp uint64, params PasswordChangeParams) (RecoveryPasswordResponse, *status.Exception) {
	header := map[string][]string{
		"X-Requested-With": {"XMLHttpRequest"},
		"Content-Type":     {"application/x-www-form-urlencoded; charset=UTF-8"},
		"Accept":           {"*/*"},
		"User-Agent":       {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"},
		"Origin":           {STEAM_HELP_WEB_BASE},
	}
	query := map[string][]string{
		"s":            {strconv.FormatInt(int64(params.S), 10)},
		"lost":         {"2"},
		"reset":        {"1"},
		"password":     {encryptedPassword},
		"rsatimestamp": {strconv.FormatUint(rsaTimestamp, 10)},
	}
	if session.Cookies != nil {
		cookie := getCookies(session.Cookies, "sessionid", "help.steampowered.com")
		if cookie != nil {
			query["sessionid"] = []string{cookie.Value}
		}
	} else {
		session.Cookies = getSteamAuthCookies(session)
	}

	var response RecoveryPasswordResponse
	_, _, _, responseData, _, requestError := utils.HttpWebRequest("POST", STEAM_ACCOUNT_RECOVERY_VERIFY_PASSWORD, header, query, session.Cookies, nil, true, true)
	if requestError != nil {
		return response, status.NewError(RECOVER_VERIFY_PASSWORD_ERROR, fmt.Sprintf("Recovery verify password error %s", requestError.Error()))
	}
	e := json.Unmarshal(responseData, &response)
	if e != nil {
		return response, status.NewError(STEAM_REQUEST_INCOMP, "Data incompatible error with RecoveryPasswordResponse!")
	}
	if response.ErrorMsg != "" {
		return response, status.NewError(CHANGE_PASSWORD_REQUEST_FAIL, response.ErrorMsg)
	}
	return response, nil
}

func getNextStepForAccountRecovery(session SteamCommunitySession, params PasswordChangeParams) *status.Exception {
	header := map[string][]string{
		"X-Requested-With": {"XMLHttpRequest"},
		"Content-Type":     {"application/x-www-form-urlencoded; charset=UTF-8"},
		"Accept":           {"*/*"},
		"User-Agent":       {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"},
		"Origin":           {STEAM_HELP_WEB_BASE},
	}
	query := map[string][]string{
		"s":           {strconv.FormatInt(int64(params.S), 10)},
		"account":     {strconv.FormatInt(int64(params.Account), 10)},
		"reset":       {strconv.FormatInt(int64(params.Reset), 10)},
		"issueid":     {strconv.FormatInt(int64(params.Issueid), 10)},
		"wizard_ajax": {"1"},
		"lost":        {"2"},
	}
	if session.Cookies != nil {
		cookie := getCookies(session.Cookies, "sessionid", "help.steampowered.com")
		if cookie != nil {
			query["sessionid"] = []string{cookie.Value}
		}
	} else {
		session.Cookies = getSteamAuthCookies(session)
	}
	_, _, _, _, _, requestError := utils.HttpWebRequest("GET", STEAM_ACCOUNT_RECOVERY_GET_NEXT_STEP, header, query, session.Cookies, nil, true, true)
	if requestError != nil {
		return status.NewError(GET_NEXT_STEP_FOR_ACCOUNT_RECOVERY_ERROR, fmt.Sprintf("Get next step for account recovery Error %s", requestError.Error()))
	}
	return nil
}

func checkPasswordAvailable(session SteamCommunitySession, password string) (bool, *status.Exception) {
	header := map[string][]string{
		"User-Agent": {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"},
		"Origin":     {STEAM_HELP_WEB_BASE},
	}
	query := map[string][]string{
		"password":    {password},
		"wizard_ajax": {"1"},
	}
	if session.Cookies != nil {
		cookie := getCookies(session.Cookies, "sessionid", "help.steampowered.com")
		if cookie != nil {
			query["sessionid"] = []string{cookie.Value}
		}
	} else {
		session.Cookies = getSteamAuthCookies(session)
	}
	_, _, _, _, _, requestError := utils.HttpWebRequest("POST", STEAM_CHECK_PASSWORD_AVAILABLE, header, query, session.Cookies, nil, true, true)
	if requestError != nil {
		return false, status.NewError(CHECK_PASSWORD_AVAILABLE_ERROR, fmt.Sprintf("check password available Error %s", requestError.Error()))
	}
	return true, nil
}

type ChangePasswordResponse struct {
	Hash     string `json:"hash"`
	ErrorMsg string `json:"errorMsg"`
}

func changePasswordRequest(session SteamCommunitySession, encryptedPassword string, rsaTimestamp uint64, params PasswordChangeParams) (ChangePasswordResponse, *status.Exception) {
	header := map[string][]string{
		"X-Requested-With": {"XMLHttpRequest"},
		"Content-Type":     {"application/x-www-form-urlencoded; charset=UTF-8"},
		"Accept":           {"*/*"},
		"User-Agent":       {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"},
		"Origin":           {STEAM_HELP_WEB_BASE},
	}
	query := map[string][]string{
		"wizard_ajax":  {"1"},
		"s":            {strconv.FormatInt(int64(params.S), 10)},
		"account":      {strconv.FormatInt(int64(params.Account), 10)},
		"password":     {encryptedPassword},
		"rsatimestamp": {strconv.FormatUint(rsaTimestamp, 10)},
	}
	if session.Cookies != nil {
		cookie := getCookies(session.Cookies, "sessionid", "help.steampowered.com")
		if cookie != nil {
			query["sessionid"] = []string{cookie.Value}
		}
	} else {
		session.Cookies = getSteamAuthCookies(session)
	}
	var response ChangePasswordResponse
	_, _, _, responseData, _, requestError := utils.HttpWebRequest("POST", STEAM_ACCOUNT_RECOVERY_CHANGE_PASSWORD, header, query, session.Cookies, nil, true, true)

	if requestError != nil {
		return response, status.NewError(CHANGE_PASSWORD_REQUEST_ERROR, fmt.Sprintf("Change password request error %s", requestError.Error()))
	}
	e := json.Unmarshal(responseData, &response)
	if e != nil {
		return response, status.NewError(STEAM_REQUEST_INCOMP, fmt.Sprintf("Data incompatible error with ChangePasswordResponse!"))
	}
	if response.ErrorMsg != "" {
		return response, status.NewError(CHANGE_PASSWORD_REQUEST_FAIL, response.ErrorMsg)
	}
	return response, nil
}

func ChangePassword(session SteamCommunitySession, auth Authenticator, username, password, newPassword string) (bool, *status.Exception) {
	params, err := receivePasswordChangeParams(session)
	if err != nil {
		return false, err
	}

	err = loginInfoEnterCode(session, params)
	if err != nil {
		return false, err
	}

	sendResponse, err := sendAccountRecoveryCode(session, params)
	if err != nil {
		return false, err
	}
	if !sendResponse.Success {
		return sendResponse.Success, err
	}

	for i := 0; i < 3; i++ {
		ok, err := ConfirmByTradeOfferIdFromMobile(session, auth, int64(params.S))
		if err != nil || !ok {
			time.Sleep(time.Second * 3)
			continue
		} else {
			break
		}
	}

	pollResponse, err := pollAccountRecoveryConfirmation(session, params)
	if err != nil {
		return false, err
	}
	if !pollResponse.Success {
		return false, nil
	}

	_, err = verifyAccountRecoveryCode(session, params)
	if err != nil {
		return false, err
	}
	err = getNextStepForAccountRecovery(session, params)
	if err != nil {
		return false, err
	}

	encryptedData, err := EncryptPasswordWithRSA(username, password)
	if err != nil {
		return false, err
	}

	_, err = recoveryVerifyPassword(session, encryptedData.EncryptPassword, encryptedData.Timestamp, params)
	if err != nil {
		return false, err
	}

	encryptedData, err = EncryptPasswordWithRSA(username, newPassword)
	if err != nil {
		return false, err
	}
	ok, err := checkPasswordAvailable(session, newPassword)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}
	_, err = changePasswordRequest(session, encryptedData.EncryptPassword, encryptedData.Timestamp, params)
	if err != nil {
		return false, err
	}

	return true, nil
}
