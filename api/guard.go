package api

import (
	"encoding/json"
	"fmt"
	"github.com/shangate/steam-web/status"
	"github.com/shangate/steam-web/utils"
)

const (
	STEAM_PHONE_GUARD_WEBAPI      = STEAM_COMMUNITY_WEB_BASE + "/steamguard/phoneajax"
	STEAM_PHONE_VALIDATION_WEBAPI = STEAM_STORE_WEB_BASE + "/phone/validate"
	STEAM_PHONE_ADD_WEBAPI        = STEAM_STORE_WEB_BASE + "/phone/add_ajaxop"
)

const (
	STEAM_GUARD_REQUEST_ERROR = iota + 200000
	STEAM_GUARD_VALIDATE_PHONE_NUMBER_FAIL
	STEAM_GUARD_NO_PHONE_ATTACHED
	STEAM_GUARD_CHECK_SMS_CODE_FAIL
	STEAM_GUARD_RESEND_SMS_CODE_FAIL
	STEAM_GUARD_EMAIL_CONFIRMATION_FAIL
	STEAM_GUARD_ADD_PHONE_FAIL
)

type GuardCheckResponse struct {
	Success bool `json:"success"`
}

func ValidatePhoneNumber(session SteamCommunitySession, phoneNumber string) *status.Exception {
	headers := getDefaultMobileHeader()

	query := map[string][]string{
		"phoneNumber": {phoneNumber},
		"sessionID":   {session.SessionId},
	}

	_, _, _, responseData, _, requestError := utils.HttpWebRequest("POST", STEAM_PHONE_VALIDATION_WEBAPI, headers, query, session.Cookies, nil, false, false)
	if requestError != nil {
		return status.NewError(STEAM_REQUEST_ERROR, fmt.Sprintf("Validate phone number Error %s", requestError.Error()))
	}

	responseDataStr := string(responseData)
	if responseDataStr == "" {
		return status.NewError(STEAM_REQUEST_ERROR, "Validate phone number error")
	}

	var response GuardCheckResponse
	er := json.Unmarshal(responseData, &response)
	if er != nil {
		return status.NewError(STEAM_REQUEST_INCOMP, fmt.Sprintf("Validate phone number error %s", er.Error()))
	}

	if !response.Success {
		return status.NewError(STEAM_GUARD_VALIDATE_PHONE_NUMBER_FAIL, "Validate phone number failed")
	}

	return nil
}

func AddPhoneNumber(session SteamCommunitySession, phoneNumber string) *status.Exception {
	headers := getDefaultMobileHeader()

	query := map[string][]string{
		"op":          {"get_phone_number"},
		"input":       {phoneNumber},
		"sessionID":   {session.SessionId},
		"confirmed":   {"1"},
		"checkfortos": {"1"},
		"bisediting":  {"0"},
		"token":       {"0"},
	}

	_, _, _, responseData, _, requestError := utils.HttpWebRequest("POST", STEAM_PHONE_ADD_WEBAPI, headers, query, session.Cookies, nil, false, false)
	if requestError != nil {
		return status.NewError(STEAM_REQUEST_ERROR, fmt.Sprintf("Add phone number error %s", requestError.Error()))
	}

	responseDataStr := string(responseData)
	if responseDataStr == "" {
		return status.NewError(STEAM_REQUEST_ERROR, "Add phone number error")
	}

	var response GuardCheckResponse
	er := json.Unmarshal(responseData, &response)
	if er != nil {
		return status.NewError(STEAM_REQUEST_INCOMP, fmt.Sprintf("Add phone number error %s", er.Error()))
	}

	if !response.Success {
		return status.NewError(STEAM_GUARD_ADD_PHONE_FAIL, "Add phone number failed")
	}

	return nil
}

func CheckEmailConfirmation(session SteamCommunitySession, repeat bool) *status.Exception {
	headers := getDefaultMobileHeader()

	op := "email_verification"
	if repeat {
		op = "retry_email_verification"
	}
	query := map[string][]string{
		"op":          {op},
		"input":       {},
		"sessionID":   {session.SessionId},
		"confirmed":   {"1"},
		"checkfortos": {"1"},
		"bisediting":  {"0"},
		"token":       {"0"},
	}

	_, _, _, responseData, _, requestError := utils.HttpWebRequest("POST", STEAM_PHONE_ADD_WEBAPI, headers, query, session.Cookies, nil, false, false)
	if requestError != nil {
		return status.NewError(STEAM_REQUEST_ERROR, fmt.Sprintf("Check email confirmation error %s", requestError.Error()))
	}

	responseDataStr := string(responseData)
	if responseDataStr == "" {
		return status.NewError(STEAM_REQUEST_ERROR, "Check email confirmation error")
	}

	var response GuardCheckResponse
	er := json.Unmarshal(responseData, &response)
	if er != nil {
		return status.NewError(STEAM_REQUEST_INCOMP, fmt.Sprintf("Check email confirmation error %s", er.Error()))
	}

	if !response.Success {
		return status.NewError(STEAM_GUARD_EMAIL_CONFIRMATION_FAIL, "Check email confirmation failed")
	}

	return nil
}

func CheckSMSCode(session SteamCommunitySession, smsCode string) *status.Exception {
	headers := getDefaultMobileHeader()

	query := map[string][]string{
		"op":          {"get_sms_code"},
		"input":       {smsCode},
		"sessionID":   {session.SessionId},
		"confirmed":   {"1"},
		"checkfortos": {"1"},
		"bisediting":  {"0"},
		"token":       {"0"},
	}

	_, _, _, responseData, _, requestError := utils.HttpWebRequest("POST", STEAM_PHONE_ADD_WEBAPI, headers, query, session.Cookies, nil, false, false)
	if requestError != nil {
		return status.NewError(STEAM_REQUEST_ERROR, fmt.Sprintf("Check sms code Error %s", requestError.Error()))
	}

	responseDataStr := string(responseData)
	if responseDataStr == "" {
		return status.NewError(STEAM_REQUEST_ERROR, "Check sms code Error")
	}

	var response GuardCheckResponse
	er := json.Unmarshal(responseData, &response)
	if er != nil {
		return status.NewError(STEAM_REQUEST_INCOMP, fmt.Sprintf("Check sms code error %s", er.Error()))
	}

	if !response.Success {
		return status.NewError(STEAM_GUARD_CHECK_SMS_CODE_FAIL, "Check sms code failed")
	}

	return nil
}

func ResendSMSCode(session SteamCommunitySession) *status.Exception {
	headers := getDefaultMobileHeader()

	query := map[string][]string{
		"op":          {"resend_sms"},
		"input":       {},
		"sessionID":   {session.SessionId},
		"confirmed":   {"0"},
		"checkfortos": {"1"},
		"bisediting":  {"0"},
		"token":       {"0"},
	}
	_, _, _, responseData, _, requestError := utils.HttpWebRequest("POST", STEAM_PHONE_ADD_WEBAPI, headers, query, session.Cookies, nil, false, false)
	if requestError != nil {
		return status.NewError(STEAM_REQUEST_ERROR, fmt.Sprintf("Resend sms code error %s", requestError.Error()))
	}

	responseDataStr := string(responseData)
	if responseDataStr == "" {
		return status.NewError(STEAM_REQUEST_ERROR, "Resend sms code error")
	}

	var response GuardCheckResponse
	er := json.Unmarshal(responseData, &response)
	if er != nil {
		return status.NewError(STEAM_REQUEST_INCOMP, fmt.Sprintf("Resend sms code error %s", er.Error()))
	}

	if !response.Success {
		return status.NewError(STEAM_GUARD_RESEND_SMS_CODE_FAIL, "Resend sms code failed")
	}

	return nil
}

//deprecated
//func CheckSMSCode(session SteamCommunitySession, smsCode string) *status.Exception {
//	headers := getDefaultMobileHeader()
//	if session.Cookies == nil {
//		session.Cookies = getDefaultMobileCooKies()
//	}
//
//	query := map[string][]string{
//		"op":          {"check_sms_code"},
//		"arg":         {smsCode},
//		"checkfortos": {"0"},
//		"skipvoip":    {"1"},
//		"sessionid":   {session.SessionId},
//	}
//
//	_, _, _, responseData, _, requestError := utils.HttpWebRequest("POST", STEAM_PHONE_GUARD_WEBAPI, headers, query, session.Cookies, nil, false, false)
//	if requestError != nil {
//		return status.NewError(STEAM_REQUEST_ERROR, fmt.Sprintf("Check sms code Error %s", requestError.Error()))
//	}
//
//	responseDataStr := string(responseData)
//	if responseDataStr == "" {
//		return status.NewError(STEAM_REQUEST_ERROR, fmt.Sprintf("Check sms code Error %s", requestError.Error()))
//	}
//
//	var response GuardCheckResponse
//	er := json.Unmarshal(responseData, &response)
//	if er != nil {
//		return status.NewError(STEAM_REQUEST_ERROR, fmt.Sprintf("Check sms code Error %s", er.Error()))
//	}
//
//	if !response.Success {
//		return status.NewError(STEAM_GUARD_INVALID_SMS_CODE, "Check sms code failed")
//	}
//
//	return nil
//}

//func HasPhoneAttached(session SteamCommunitySession) *status.Exception {
//	headers := getDefaultMobileHeader()
//	if session.Cookies == nil {
//		session.Cookies = getDefaultMobileCooKies()
//	}
//
//	query := map[string][]string{
//		"op":        {"has_phone"},
//		"arg":       {"null"},
//		"sessionid": {session.SessionId},
//	}
//
//	_, _, _, responseData, _, requestError := utils.HttpWebRequest("POST", STEAM_PHONE_GUARD_WEBAPI, headers, query, session.Cookies, nil, false, false)
//	if requestError != nil {
//		return status.NewError(STEAM_REQUEST_ERROR, fmt.Sprintf("Has phone attached Error %s", requestError.Error()))
//	}
//
//	responseDataStr := string(responseData)
//	if responseDataStr == "" {
//		return status.NewError(STEAM_REQUEST_ERROR, fmt.Sprintf("Has phone attached Error %s", requestError.Error()))
//	}
//
//	var response GuardCheckResponse
//	er := json.Unmarshal(responseData, &response)
//	if er != nil {
//		return status.NewError(STEAM_REQUEST_INCOMP, fmt.Sprintf("Has phone attached Error %s", er.Error()))
//	}
//	if !response.Success {
//		return status.NewError(STEAM_GUARD_NO_PHONE_ATTACHED, "No phone attached")
//	}
//	return nil
//}

//func CheckEmailConfirmation(session SteamCommunitySession) *status.Exception {
//	headers := getDefaultMobileHeader()
//	if session.Cookies == nil {
//		session.Cookies = getDefaultMobileCooKies()
//	}
//
//	query := map[string][]string{
//		"op":        {"email_confirmation"},
//		"arg":       {"null"},
//		"sessionid": {session.SessionId},
//	}
//
//	_, _, _, responseData, _, requestError := utils.HttpWebRequest("POST", STEAM_PHONE_GUARD_WEBAPI, headers, query, session.Cookies, nil, true, false)
//	if requestError != nil {
//		return status.NewError(STEAM_REQUEST_ERROR, fmt.Sprintf("Check email confirmation Error %s", requestError.Error()))
//	}
//
//	responseDataStr := string(responseData)
//	if responseDataStr == "" {
//		return status.NewError(STEAM_REQUEST_ERROR, fmt.Sprintf("Check email confirmation Error %s", requestError.Error()))
//	}
//
//	var response GuardCheckResponse
//	er := json.Unmarshal(responseData, &response)
//	if er != nil {
//		return status.NewError(STEAM_REQUEST_INCOMP, fmt.Sprintf("Check email confirmation Error %s", er.Error()))
//	}
//	if !response.Success {
//		return status.NewError(STEAM_GUARD_INVALID_EMAIL_CONFIRMATION, "Check email confirmation failed")
//	}
//	return nil
//}

//func AddPhoneNumber(session SteamCommunitySession, phoneNum string) *status.Exception {
//	headers := getDefaultMobileHeader()
//	if session.Cookies == nil {
//		session.Cookies = getDefaultMobileCooKies()
//	}
//
//	query := map[string][]string{
//		"op":        {"add_phone_number"},
//		"arg":       {phoneNum},
//		"sessionid": {session.SessionId},
//	}
//
//	_, _, _, responseData, _, requestError := utils.HttpWebRequest("POST", STEAM_PHONE_GUARD_WEBAPI, headers, query, session.Cookies, nil, false, false)
//	if requestError != nil {
//		return status.NewError(STEAM_REQUEST_ERROR, fmt.Sprintf("Add phone number Error %s", requestError.Error()))
//	}
//
//	responseDataStr := string(responseData)
//	if responseDataStr == "" {
//		return status.NewError(STEAM_REQUEST_ERROR, fmt.Sprintf("Add phone number Error %s", requestError.Error()))
//	}
//
//	var response GuardCheckResponse
//	er := json.Unmarshal(responseData, &response)
//	if er != nil {
//		return status.NewError(STEAM_REQUEST_INCOMP, fmt.Sprintf("Add phone number Error %s", er.Error()))
//	}
//	if !response.Success {
//		return status.NewError(STEAM_GUARD_ADD_PHONE_FAIL, "Add phone number failed")
//	}
//	return nil
//}
