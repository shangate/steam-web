package api

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/golang/protobuf/proto"
	steam_proto "github.com/shangate/steam-web/protobuf/generated"
	"github.com/shangate/steam-web/status"
	"github.com/shangate/steam-web/utils"
	"math/big"
	"net/http"
	"strconv"
	"time"
)

const STEAM_GET_PASSWORD_RSAPUBLICKEY_WEBAPI_V1 = STEAM_API_WEB_BASE + "/IAuthenticationService/GetPasswordRSAPublicKey/v1"
const STEAM_BEGIN_AUTHSESSION_VIA_CREDENTIALS_WEBAPI_V1 = STEAM_API_WEB_BASE + "/IAuthenticationService/BeginAuthSessionViaCredentials/v1"
const STEAM_UPDATE_AUTHSESSION_WITH_STEAM_GUARD_CODE_WEBAPI_V1 = STEAM_API_WEB_BASE + "/IAuthenticationService/UpdateAuthSessionWithSteamGuardCode/v1"
const STEAM_POLL_AUTHSESSION_STATUS_WEBAPI_V1 = STEAM_API_WEB_BASE + "/IAuthenticationService/PollAuthSessionStatus/v1"

const (
	STEAM_AUTH_REQUEST_ERROR = iota + 100000
	ENCRYPT_RSA_ERROR
	GET_RSA_PUBLIC_KEY_ERROR
	BEGIN_AUTH_SESSION_VIA_CREDENTIALS_ERROR
	AUTH_INVALID_CREDENTIALS_ERROR
	UPDATE_AUTH_SESSION_WITH_STEAM_GUARD_CODE_ERROR
	POLL_AUTH_SESSION_ERROR
	CONFIRM_AUTH_SESSION_FAIL
	REQUEST_LOGIN_FROM_MOBILE_ERROR
	STEAM_COMMUNITY_DO_LOGIN_ERROR
	STEAM_COMMUNITY_FINALIZE_LOGIN_ERROR
	STEAM_COMMUNITY_FINALIZE_LOGIN_FAIL
)

func encryptWithRSA(exponent string, modulus string, password string) (string, *status.Exception) {
	rsaPublicKey := &rsa.PublicKey{
		N: new(big.Int),
		E: 0,
	}
	rsaPublicKey.N.SetString(modulus, 16)
	exponentInt64, _ := strconv.ParseInt(exponent, 16, 64)
	rsaPublicKey.E = int(exponentInt64)

	passwordBytes := []byte(password)
	encryptedPasswordBytes, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPublicKey, passwordBytes)
	if err != nil {
		return "", status.NewError(ENCRYPT_RSA_ERROR, fmt.Sprintf("Encrypt pkcs1v15 error %s", err.Error()))
	}

	return base64.StdEncoding.EncodeToString(encryptedPasswordBytes), nil
}
func getRsaPublicKey(username string) (publicMod string, publicExp string, timestamp uint64, err *status.Exception) {
	rsaRequest := &steam_proto.CAuthentication_GetPasswordRSAPublicKey_Request{
		AccountName: &username,
	}
	requestData, e := proto.Marshal(rsaRequest)
	if e != nil {
		return publicMod, publicExp, timestamp, status.NewError(STEAM_REQUEST_INCOMP, fmt.Sprintf("Data incompatible error %s", e.Error()))
	}

	headers := getDefaultMobileHeader()
	query := map[string][]string{
		"input_protobuf_encoded": {base64.StdEncoding.EncodeToString(requestData)},
	}

	_, _, _, responseData, _, httpError := utils.HttpWebRequest("GET", STEAM_GET_PASSWORD_RSAPUBLICKEY_WEBAPI_V1, headers, query, nil, nil, false, false)
	if httpError != nil {
		return publicMod, publicExp, timestamp, status.NewError(GET_RSA_PUBLIC_KEY_ERROR, fmt.Sprintf("request rsa public key error %s", httpError.Error()))
	}

	var responseProto steam_proto.CAuthentication_GetPasswordRSAPublicKey_Response
	e = proto.Unmarshal(responseData, &responseProto)
	if e != nil {
		return publicMod, publicExp, timestamp, status.NewError(STEAM_REQUEST_INCOMP, fmt.Sprintf("Data incompatible error %s", e.Error()))
	}

	return *responseProto.PublickeyMod, *responseProto.PublickeyExp, *responseProto.Timestamp, err
}

type EncryptedPasswordData struct {
	Username        string
	Password        string
	EncryptPassword string
	Timestamp       uint64
}

func EncryptPasswordWithRSA(username, password string) (data EncryptedPasswordData, err *status.Exception) {
	publicKeyMod, publicKeyExp, timestamp, err := getRsaPublicKey(username)
	if err != nil {
		return data, err
	}

	encryptedPassword, e := encryptWithRSA(publicKeyExp, publicKeyMod, password)
	if e != nil {
		return data, e
	}

	return EncryptedPasswordData{
		Username:        username,
		Password:        password,
		EncryptPassword: encryptedPassword,
		Timestamp:       timestamp,
	}, nil
}

type BeginLoginRequest struct {
	SteamId   uint64
	ClientId  uint64
	Username  string
	Password  string
	EmailCode string
	TwoFactor string
}

type BeginLoginResponse struct {
	Success            bool
	LoginComplete      bool
	SteamId            uint64
	ClientId           uint64
	RequestId          []byte
	EmailCodeNeeded    bool
	EmailConfirmation  bool
	TwoFactorNeeded    bool
	DeviceConfirmation bool
	WeakToken          string
}

func LoginFromMobile(request BeginLoginRequest) (response BeginLoginResponse, err *status.Exception) {
	encryptedData, err := EncryptPasswordWithRSA(request.Username, request.Password)
	if err != nil {
		return response, err
	}

	deviceName := "Galaxy S22"
	deviceType := steam_proto.EAuthTokenPlatformType_k_EAuthTokenPlatformType_MobileApp
	osType := int32(-500)
	gamingDeviceType := uint32(528)
	persistence := steam_proto.ESessionPersistence_k_ESessionPersistence_Persistent
	webSiteId := "Mobile"
	guardData := ""
	authRequest := &steam_proto.CAuthentication_BeginAuthSessionViaCredentials_Request{
		AccountName:         &request.Username,
		EncryptedPassword:   &encryptedData.EncryptPassword,
		EncryptionTimestamp: &encryptedData.Timestamp,
		DeviceDetails: &steam_proto.CAuthentication_DeviceDetails{
			DeviceFriendlyName: &deviceName,
			PlatformType:       &deviceType,
			OsType:             &osType,
			GamingDeviceType:   &gamingDeviceType,
		},
		WebsiteId:    &webSiteId,
		Persistence:  &persistence,
		PlatformType: &deviceType,
		GuardData:    &guardData,
	}
	authRequestData, e := proto.Marshal(authRequest)
	if e != nil {
		return response, status.NewError(STEAM_REQUEST_INCOMP, fmt.Sprintf("Data incompatible error %s", e.Error()))
	}

	headers := getDefaultMobileHeader()
	query := map[string][]string{
		"input_protobuf_encoded": {base64.StdEncoding.EncodeToString(authRequestData)},
	}
	_, _, _, authResponseData, _, httpError := utils.HttpWebRequest("POST", STEAM_BEGIN_AUTHSESSION_VIA_CREDENTIALS_WEBAPI_V1, headers, query, nil, nil, false, false)
	if httpError != nil {
		return response, status.NewError(BEGIN_AUTH_SESSION_VIA_CREDENTIALS_ERROR, fmt.Sprintf("begin auth error %s", httpError.Error()))
	}
	var authResponseProto steam_proto.CAuthentication_BeginAuthSessionViaCredentials_Response
	e = proto.Unmarshal(authResponseData, &authResponseProto)
	if e != nil {
		return response, status.NewError(STEAM_REQUEST_INCOMP, fmt.Sprintf("Data incompatible error %s", e.Error()))
	}

	emailCodeNeeded := false
	twoFactorNeeded := false
	emailConfirmation := false
	deviceConfirmation := false
	for _, allowedConfirmation := range authResponseProto.AllowedConfirmations {
		if *allowedConfirmation.ConfirmationType == steam_proto.EAuthSessionGuardType_k_EAuthSessionGuardType_EmailCode {
			emailCodeNeeded = true
		}
		if *allowedConfirmation.ConfirmationType == steam_proto.EAuthSessionGuardType_k_EAuthSessionGuardType_DeviceCode {
			twoFactorNeeded = true
		}
		if *allowedConfirmation.ConfirmationType == steam_proto.EAuthSessionGuardType_k_EAuthSessionGuardType_EmailConfirmation {
			emailConfirmation = true
		}
		if *allowedConfirmation.ConfirmationType == steam_proto.EAuthSessionGuardType_k_EAuthSessionGuardType_DeviceConfirmation {
			deviceConfirmation = true
		}
	}

	response = BeginLoginResponse{
		Success:            true,
		LoginComplete:      false,
		EmailCodeNeeded:    emailCodeNeeded,
		TwoFactorNeeded:    twoFactorNeeded,
		EmailConfirmation:  emailConfirmation,
		DeviceConfirmation: deviceConfirmation,
	}
	if authResponseProto.RequestId != nil {
		response.RequestId = authResponseProto.RequestId
	}
	if authResponseProto.Steamid != nil {
		response.SteamId = *authResponseProto.Steamid
	}
	if authResponseProto.ClientId != nil {
		response.ClientId = *authResponseProto.ClientId
	}
	if authResponseProto.WeakToken != nil {
		response.WeakToken = *authResponseProto.WeakToken
	}
	return response, err
}

type ConfirmLoginRequest struct {
	SessionId        string
	SteamId          uint64
	ClientId         uint64
	RequestId        []byte
	EmailCode        string
	EmailCodeNeeded  bool
	TwoFactor        string
	DeviceCodeNeeded bool
}

type ConfirmLoginResponse struct {
	Success      bool
	SessionId    string
	SteamId      uint64
	ClientId     uint64
	AccessToken  string
	RefreshToken string
}

func ConfirmLogin(request ConfirmLoginRequest) (response ConfirmLoginResponse, err *status.Exception) {
	updateAuthRequest := &steam_proto.CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request{
		ClientId: &request.ClientId,
		Steamid:  &request.SteamId,
	}
	if request.EmailCodeNeeded {
		codeType := steam_proto.EAuthSessionGuardType_k_EAuthSessionGuardType_EmailCode
		updateAuthRequest.Code = &request.EmailCode
		updateAuthRequest.CodeType = &codeType
	}
	if request.DeviceCodeNeeded {
		codeType := steam_proto.EAuthSessionGuardType_k_EAuthSessionGuardType_DeviceCode
		updateAuthRequest.Code = &request.TwoFactor
		updateAuthRequest.CodeType = &codeType
	}

	updateAuthRequestData, e := proto.Marshal(updateAuthRequest)
	if e != nil {
		return response, status.NewError(STEAM_REQUEST_INCOMP, fmt.Sprintf("Data incompatible error %s", e.Error()))
	}

	headers := getDefaultMobileHeader()
	query := map[string][]string{
		"input_protobuf_encoded": {base64.StdEncoding.EncodeToString(updateAuthRequestData)},
	}
	_, _, _, updateAuthResponseData, _, httpError := utils.HttpWebRequest("POST", STEAM_UPDATE_AUTHSESSION_WITH_STEAM_GUARD_CODE_WEBAPI_V1, headers, query, nil, nil, false, false)
	if httpError != nil {
		return response, status.NewError(UPDATE_AUTH_SESSION_WITH_STEAM_GUARD_CODE_ERROR, fmt.Sprintf("update auth session error %s", httpError.Error()))
	}

	var updateAuthResponseProto steam_proto.CAuthentication_UpdateAuthSessionWithSteamGuardCode_Response
	e = proto.Unmarshal(updateAuthResponseData, &updateAuthResponseProto)
	if e != nil {
		return response, status.NewError(STEAM_REQUEST_INCOMP, fmt.Sprintf("Data incompatible error %s", e.Error()))
	}

	pollAuthRequest := &steam_proto.CAuthentication_PollAuthSessionStatus_Request{
		ClientId:  &request.ClientId,
		RequestId: request.RequestId,
	}
	pollAuthRequestData, e := proto.Marshal(pollAuthRequest)
	if e != nil {
		return response, status.NewError(STEAM_REQUEST_INCOMP, fmt.Sprintf("Data incompatible error %s", e.Error()))
	}

	query = map[string][]string{
		"input_protobuf_encoded": {base64.StdEncoding.EncodeToString(pollAuthRequestData)},
	}
	_, _, _, pollAuthResponseData, _, httpError := utils.HttpWebRequest("POST", STEAM_POLL_AUTHSESSION_STATUS_WEBAPI_V1, headers, query, nil, nil, false, false)
	if httpError != nil {
		return response, status.NewError(POLL_AUTH_SESSION_ERROR, fmt.Sprintf("update auth session error %s", httpError.Error()))
	}

	var pollAuthResponseProto steam_proto.CAuthentication_PollAuthSessionStatus_Response
	e = proto.Unmarshal(pollAuthResponseData, &pollAuthResponseProto)
	if e != nil {
		return response, status.NewError(STEAM_REQUEST_INCOMP, fmt.Sprintf("Data incompatible error %s", e.Error()))
	}

	response = ConfirmLoginResponse{
		Success: true,
		SteamId: request.SteamId,
	}
	if pollAuthResponseProto.AccessToken != nil {
		response.AccessToken = *pollAuthResponseProto.AccessToken
	}
	if pollAuthResponseProto.RefreshToken != nil {
		response.RefreshToken = *pollAuthResponseProto.RefreshToken
	}

	if pollAuthResponseProto.NewClientId != nil {
		response.ClientId = *pollAuthResponseProto.NewClientId
	} else {
		response.ClientId = request.ClientId
	}

	if pollAuthResponseProto.RefreshToken == nil || pollAuthResponseProto.AccessToken == nil {
		return response, status.NewError(CONFIRM_AUTH_SESSION_FAIL, "Refresh token or access token is null")
	}

	return response, nil
}

const (
	STEAM_COMMUNITY_LOGIN_URL            = STEAM_COMMUNITY_WEB_BASE + "/login?oauth_client_id=DE45CD61&oauth_scope=read_profile%20write_profile%20read_client%20write_client"
	STEAM_COMMUNITY_MOBILE_REQUEST_REFER = STEAM_COMMUNITY_LOGIN_URL + "/mobilelogin?oauth_client_id=DE45CD61&oauth_scope=read_profile%20write_profile%20read_client%20write_client"

	STEAM_COMMUNITY_LOGIN_GET_RSAKEY = STEAM_COMMUNITY_WEB_BASE + "/login/getrsakey"
	STEAM_COMMUNITY_DO_LOGIN         = STEAM_COMMUNITY_WEB_BASE + "/login/dologin"
)

type SteamCommunitySession struct {
	SessionId        string `json:"sessionid"`
	SteamId          string `json:"steamid"`
	WebCookie        string `json:"webcookie"`
	WgToken          string `json:"wgtoken"`
	WgTokenSecure    string `json:"wgtoken_secure"`
	SteamLogin       string
	SteamLoginSecure string
	Cookies          []*http.Cookie
}

func getSteamAuthCookies(session SteamCommunitySession) []*http.Cookie {
	defaultCookies := getDefaultMobileCooKies()
	authSteamCookies := []*http.Cookie{
		{
			Name:   "steamid",
			Value:  session.SteamId,
			Path:   "/",
			Domain: ".steamcommunity.com",
		},
		{
			Name:   "steamLoginSecure",
			Value:  session.SteamLoginSecure,
			Path:   "/",
			Domain: ".steamcommunity.com",
		},
		{
			Name:   "sessionid",
			Value:  session.SessionId,
			Path:   "/",
			Domain: ".steamcommunity.com",
		},
		{
			Name:   "dob",
			Value:  "",
			Path:   "/",
			Domain: ".steamcommunity.com",
		},
	}
	return append(authSteamCookies, defaultCookies...)
}

type LoginCommunityRequest struct {
	SessionId     string
	SteamId       string
	Username      string
	Password      string
	EmailCode     string
	TwoFactorCode string
	CaptchaGid    string
	CaptchaText   string
}

type transferParameters struct {
	Auth             string `json:"Auth"`
	RememberLogin    bool   `json:"remember_login"`
	SteamID          string `json:"steamid"`
	SteamLoginSecure string `json:"token_secure"`
	Webcookie        string `json:"webcookie"`
}

type LoginCommunityResponse struct {
	SessionId         string             `json:"sessionId"`
	Success           bool               `json:"success"`
	LoginComplete     bool               `json:"login_complete"`
	TransferParams    transferParameters `json:"transfer_parameters"`
	CaptchaNeeded     bool               `json:"captcha_needed"`
	EmailSteamId      string             `json:"emailsteamid"`
	EmailAuthNeeded   bool               `json:"emailauth_needed"`
	RequiresTwoFactor bool               `json:"requires_twofactor"`
	Message           string             `json:"message"`
	Session           SteamCommunitySession
}

type RsaKeyResponse struct {
	Success      bool   `json:"success"`
	PublickeyMod string `json:"publickey_mod"`
	PublickeyExp string `json:"publickey_exp"`
	Timestamp    string `json:"timestamp"`
	TokenGid     string `json:"token_gid"`
}

func requestLoginFromMobile() (sessionId string, err *status.Exception) {
	headers := getDefaultMobileHeader()
	cookies := getDefaultMobileCooKies()
	_, _, _, _, respCookies, requestError := utils.HttpWebRequest("GET", STEAM_COMMUNITY_LOGIN_URL, headers, nil, cookies, nil, false, false)

	if requestError != nil {
		return sessionId, status.NewError(REQUEST_LOGIN_FROM_MOBILE_ERROR, fmt.Sprintf("Request login by mobile Error %s", requestError.Error()))
	}
	for _, cookie := range respCookies {
		if cookie.Name == "sessionid" {
			sessionId = cookie.Value
		}
	}
	return sessionId, nil
}

func LoginCommunityFromMobile(request LoginCommunityRequest) (result LoginCommunityResponse, err *status.Exception) {
	if request.SessionId == "" {
		request.SessionId, err = requestLoginFromMobile()
		if err != nil {
			return result, err
		}
	}

	headers := getDefaultMobileHeader()
	cookies := getDefaultMobileCooKies()
	query := map[string][]string{
		"donotcache": {strconv.FormatInt(time.Now().Unix(), 10)},
		"username":   {request.Username},
	}

	_, _, _, response, _, requestError := utils.HttpWebRequest("POST", STEAM_COMMUNITY_LOGIN_GET_RSAKEY, headers, query, cookies, nil, false, false)
	if requestError != nil {
		return result, status.NewError(GET_RSA_PUBLIC_KEY_ERROR, fmt.Sprintf("Get rsa key Error %s", requestError.Error()))
	}

	var rsaKeyResponse RsaKeyResponse
	e := json.Unmarshal(response, &rsaKeyResponse)
	if e != nil {
		return result, status.NewError(STEAM_REQUEST_INCOMP, fmt.Sprintf("Data incompatible error %s", e.Error()))
	}

	time.Sleep(time.Second)

	encryptedPassword, err := encryptWithRSA(rsaKeyResponse.PublickeyExp, rsaKeyResponse.PublickeyMod, request.Password)
	if err != nil {
		return result, err
	}

	if request.CaptchaGid == "" {
		request.CaptchaGid = "-1"
	}
	query = map[string][]string{
		"donotcache":        {strconv.FormatInt(time.Now().Unix(), 10)},
		"username":          {request.Username},
		"password":          {encryptedPassword},
		"twofactorcode":     {request.TwoFactorCode},
		"emailauth":         {request.EmailCode},
		"loginfriendlyname": {"Xiaomi 13"},
		"captchagid":        {request.CaptchaGid},
		"captcha_text":      {request.CaptchaText},
		"emailsteamid":      {request.SteamId},
		"rsatimestamp":      {rsaKeyResponse.Timestamp},
		"remember_login":    {"true"},
		"oauth_client_id":   {"DE45CD61"},
		"oauth_scope":       {"read_profile write_profile read_client write_client"},
	}

	_, _, _, response, cookies, requestError = utils.HttpWebRequest("POST", STEAM_COMMUNITY_DO_LOGIN, headers, query, cookies, nil, false, false)
	if requestError != nil {
		return result, status.NewError(STEAM_COMMUNITY_DO_LOGIN_ERROR, fmt.Sprintf("Do login Error %s", requestError.Error()))
	}

	var loginResponse LoginCommunityResponse
	e = json.Unmarshal(response, &loginResponse)
	if e != nil {
		return result, status.NewError(STEAM_REQUEST_INCOMP, fmt.Sprintf("Data incompatible error %s", e.Error()))
	}

	loginResponse.SessionId = request.SessionId
	if loginResponse.LoginComplete && loginResponse.Success {
		steamId := loginResponse.TransferParams.SteamID
		steamLogin := steamId + "%7C%7C" + loginResponse.TransferParams.SteamLoginSecure
		webCookie := loginResponse.TransferParams.Webcookie
		session := SteamCommunitySession{
			SessionId:        request.SessionId,
			SteamId:          loginResponse.TransferParams.SteamID,
			SteamLogin:       steamLogin,
			SteamLoginSecure: steamLogin,
			WebCookie:        webCookie,
		}
		loginResponse.Session = session
	}
	return loginResponse, nil
}

type FinalizeLoginCommunityRequest struct {
	SessionId    string
	RefreshToken string
}

type FinalizeLoginCommunityResponse struct {
	SessionId string
	Cookies   []*http.Cookie
}

const (
	STEAM_LOGIN_FINALIZE_LOGIN = STEAM_LOGIN_WEB_BASE + "/jwt/finalizelogin"
)

type transferInfo struct {
	Url    string `json:"url"`
	Params struct {
		Nonce string `json:"nonce"`
		Auth  string `json:"auth"`
	} `json:"params"`
}

type finalizeLoginResponse struct {
	Success       bool           `json:"success"`
	Message       string         `json:"message"`
	SteamID       string         `json:"steamID"`
	Redir         string         `json:"redir"`
	TransferInfo  []transferInfo `json:"transfer_info"`
	PrimaryDomain string         `json:"primary_domain"`
}

func FinalizeLoginCommunityFromMobile(request FinalizeLoginCommunityRequest) (response FinalizeLoginCommunityResponse, err *status.Exception) {
	if request.SessionId == "" {
		sessionId, err := requestLoginFromMobile()
		if err != nil {
			return response, err
		}
		request.SessionId = sessionId
	}

	headers := getDefaultMobileHeader()
	cookies := getDefaultMobileCooKies()
	query := map[string][]string{
		"nonce":     {request.RefreshToken},
		"sessionid": {request.SessionId},
		"redir":     {"https://steamcommunity.com/login/home/?goto="},
	}
	_, _, _, responseData, responseCookies, requestError := utils.HttpWebRequest("POST", STEAM_LOGIN_FINALIZE_LOGIN, headers, query, cookies, nil, false, false)
	if requestError != nil {
		return response, status.NewError(STEAM_COMMUNITY_FINALIZE_LOGIN_ERROR, fmt.Sprintf("Do login Error %s", requestError.Error()))
	}
	finalizeResponse := finalizeLoginResponse{Success: true}
	e := json.Unmarshal(responseData, &finalizeResponse)
	if e != nil {
		return response, status.NewError(STEAM_REQUEST_INCOMP, fmt.Sprintf("Data incompatible error %s", e.Error()))
	}
	if !finalizeResponse.Success {
		return response, status.NewError(STEAM_COMMUNITY_FINALIZE_LOGIN_FAIL, finalizeResponse.Message)
	}

	cookiesMap := make(map[string]*http.Cookie)
	for _, responseCookie := range responseCookies {
		cookiesMap[responseCookie.Name+responseCookie.Domain] = responseCookie
	}
	for _, token := range finalizeResponse.TransferInfo {
		query = map[string][]string{
			"nonce":   {token.Params.Nonce},
			"auth":    {token.Params.Auth},
			"steamID": {finalizeResponse.SteamID},
		}
		_, _, _, _, subResponseCookies, requestError := utils.HttpWebRequest("POST", token.Url, headers, query, responseCookies, nil, false, false)
		if requestError != nil {
			return response, status.NewError(STEAM_COMMUNITY_FINALIZE_LOGIN_ERROR, fmt.Sprintf("Do login Error %s", requestError.Error()))
		}
		for _, subCookie := range subResponseCookies {
			if _, ok := cookiesMap[subCookie.Name+subCookie.Domain]; !ok {
				cookiesMap[subCookie.Name+subCookie.Domain] = subCookie
				responseCookies = append(responseCookies, subCookie)
			}
		}
	}

	if _, ok := cookiesMap["sessionid"+".steamcommunity.com"]; !ok {
		cookie := &http.Cookie{
			Name:   "sessionid",
			Value:  request.SessionId,
			Path:   "/",
			Domain: ".steamcommunity.com",
		}
		cookiesMap["sessionid"+".steamcommunity.com"] = cookie
		responseCookies = append(responseCookies, cookie)
	}

	return FinalizeLoginCommunityResponse{
		SessionId: request.SessionId,
		Cookies:   responseCookies,
	}, nil
}
