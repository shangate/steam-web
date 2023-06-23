package api

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/shangate/steam-web/status"
	"github.com/shangate/steam-web/utils"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	STEAM_TWOFACTOR_REQUEST_ERROR = iota + 500000
	STEAM_INVALID_SMS_CODE
	STEAM_UNABLE_TO_GENERATE_CORRECT_CODE
)

var (
	TWO_FACTOR_BASE       = STEAM_API_WEB_BASE + "/ITwoFactorService/%s/v0001"
	TWO_FACTOR_TIME_QUERY = strings.ReplaceAll(TWO_FACTOR_BASE, "%s", "QueryTime")
)

const (
	STEAM_ADD_AUTHENTICATOR_WEBAPI_V1      = STEAM_API_WEB_BASE + "/ITwoFactorService/AddAuthenticator/v0001"
	STEAM_FINALIZE_AUTHENTICATOR_WEBAPI_V1 = STEAM_API_WEB_BASE + "/ITwoFactorService/FinalizeAddAuthenticator/v0001"
	STEAM_REMOVE_AUTHENTICATOR_WEBAPI_V1   = STEAM_API_WEB_BASE + "/ITwoFactorService/RemoveAuthenticator/v0001"

	STEAM_QUERY_TIME_WEBAPI_V1 = "https://api.steampowered.com/ITwoFactorService/QueryTime/v0001?steamid=0"
)

var (
	chars    = "23456789BCDFGHJKMNPQRTVWXY"
	charsLen = uint32(len(chars))
)

func GetTwoFactor(sharedSecret string) string {
	currentSteamTime := GetSteamTime()

	data, err := base64.StdEncoding.DecodeString(sharedSecret)
	if err != nil {
		fmt.Printf("[TwoFactor] Error while decoding shared secret: %v", err.Error())
		return ""
	}

	ful := make([]byte, 8)
	binary.BigEndian.PutUint32(ful[4:], uint32(currentSteamTime/30))

	hmac := hmac.New(sha1.New, data)
	hmac.Write(ful)

	sum := hmac.Sum(nil)
	start := sum[19] & 0x0F
	slice := binary.BigEndian.Uint32(sum[start:start+4]) & 0x7FFFFFFF

	buf := make([]byte, 5)
	for i := 0; i < 5; i++ {
		buf[i] = chars[slice%charsLen]
		slice /= charsLen
	}

	return string(buf)
}

type Authenticator struct {
	SharedSecret   string `json:"shared_secret"`
	SerialNumber   string `json:"serial_number"`
	RevocationCode string `json:"revocation_code"`
	Uri            string `json:"uri"`
	ServerTime     string `json:"server_time"`
	AccountName    string `json:"account_name"`
	TokenGid       string `json:"token_gid"`
	IdentitySecret string `json:"identity_secret"`
	Secret1        string `json:"secret_1"`
	Status         int    `json:"status"`
	DeviceId       string `json:"device_id"`
	SteamId        string `json:"steam_id"`
	FullyEnrolled  bool   `json:"fully_enrolled"`
}

type authenticatorResponse struct {
	Auth Authenticator `json:"response"`
}

type AddAuthenticatorRequest struct {
	DeviceId    string
	SteamId     uint64
	AccessToken string
}

func AddAuthenticator(request AddAuthenticatorRequest) (auth Authenticator, err *status.Exception) {
	headers := getDefaultMobileHeader()

	query := map[string][]string{
		"access_token":       {request.AccessToken},
		"steamid":            {strconv.FormatUint(request.SteamId, 10)},
		"device_identifier":  {request.DeviceId},
		"sms_phone_id":       {"1"},
		"authenticator_type": {"1"},
	}

	_, _, _, response, _, e := utils.HttpWebRequest("POST", STEAM_ADD_AUTHENTICATOR_WEBAPI_V1, headers, query, nil, nil, false, false)
	if e != nil {
		return auth, status.NewError(STEAM_REQUEST_ERROR, fmt.Sprintf("Add authenticator Error %s", e.Error()))
	}

	responseStr := string(response)
	if responseStr == "" {
		return auth, status.NewError(STEAM_REQUEST_ERROR, "Add authenticator Error")
	}

	var authResponse authenticatorResponse
	er := json.Unmarshal(response, &authResponse)
	if er != nil {
		return auth, status.NewError(STEAM_REQUEST_ERROR, fmt.Sprintf("Add authenticator Error %s", er.Error()))
	}

	if authResponse.Auth.Status != 1 {
		return auth, status.NewError(STEAM_REQUEST_FAIL, fmt.Sprintf("Add authenticator Failed %d", auth.Status))
	}

	if authResponse.Auth.SteamId == "" {
		authResponse.Auth.SteamId = strconv.FormatUint(request.SteamId, 10)
	}
	if authResponse.Auth.DeviceId == "" {
		authResponse.Auth.DeviceId = request.DeviceId
	}
	return authResponse.Auth, nil
}

type FinalizeAuthenticatorRequest struct {
	SteamId     uint64
	SmsCode     string
	PhoneNum    string
	GuardCode   string
	AccessToken string
}

type finalizeAuthenticatorResponse struct {
	Response struct {
		Status     int    `json:"status"`
		ServerTime string `json:"server_time"`
		WantMore   bool   `json:"want_more"`
		Success    bool   `json:"success"`
	} `json:"response"`
}

func FinalizeAuthenticator(request FinalizeAuthenticatorRequest) (ok bool, err *status.Exception) {
	headers := getDefaultMobileHeader()

	query := map[string][]string{
		"access_token":    {request.AccessToken},
		"steamid":         {strconv.FormatUint(request.SteamId, 10)},
		"activation_code": {request.SmsCode},
	}

	query["authenticator_code"] = []string{request.GuardCode}
	query["authenticator_time"] = []string{strconv.FormatInt(GetSteamTime(), 10)}

	_, _, _, responseData, _, e := utils.HttpWebRequest("POST", STEAM_FINALIZE_AUTHENTICATOR_WEBAPI_V1, headers, query, nil, nil, false, false)
	if e != nil {
		return false, status.NewError(STEAM_REQUEST_ERROR, fmt.Sprintf("Finalize authenticator Error %s", e.Error()))
	}

	responseDataStr := string(responseData)
	if responseDataStr == "" {
		return false, status.NewError(STEAM_REQUEST_ERROR, "Finalize authenticator Error")
	}

	var finalizeAuthResponse finalizeAuthenticatorResponse
	er := json.Unmarshal(responseData, &finalizeAuthResponse)
	if er != nil {
		return false, status.NewError(STEAM_REQUEST_ERROR, fmt.Sprintf("Finalize authenticator Error %s", er.Error()))
	}

	if finalizeAuthResponse.Response.Status == 89 {
		return false, status.NewError(STEAM_INVALID_SMS_CODE, "Finalize authenticator Error invalid sms code")
	}

	if finalizeAuthResponse.Response.Status == 88 {
		return false, status.NewError(STEAM_INVALID_SMS_CODE, "Finalize authenticator Error unable to generate correct code")
	}

	if !finalizeAuthResponse.Response.Success {
		return false, status.NewError(STEAM_REQUEST_FAIL, "Finalize authenticator Request failed")
	}

	return true, nil
}

type RemoveAuthenticatorRequest struct {
	RevocationCode string
	Scheme         int
	SteamId        uint64
	AccessToken    string
}

type removeAuthenticatorResponse struct {
	Response struct {
		Success bool `json:"success"`
	} `json:"response"`
}

func RemoveAuthenticator(request RemoveAuthenticatorRequest) (ok bool, err *status.Exception) {
	headers := getDefaultMobileHeader()

	query := map[string][]string{
		"access_token":      {request.AccessToken},
		"steamid":           {strconv.FormatUint(request.SteamId, 10)},
		"steamguard_scheme": {strconv.Itoa(request.Scheme)},
		"revocation_code":   {request.RevocationCode},
	}

	_, _, _, response, _, requestError := utils.HttpWebRequest("POST", STEAM_REMOVE_AUTHENTICATOR_WEBAPI_V1, headers, query, nil, nil, false, false)
	if requestError != nil {
		return ok, status.NewError(STEAM_REQUEST_ERROR, fmt.Sprintf("Remove authenticator Error %s", requestError.Error()))
	}

	responseDataStr := string(response)
	if responseDataStr == "" {
		return false, status.NewError(STEAM_REQUEST_ERROR, "Remove authenticator Error")
	}

	var removeAuthResponse removeAuthenticatorResponse
	er := json.Unmarshal(response, &removeAuthResponse)
	if er != nil {
		return false, status.NewError(STEAM_REQUEST_ERROR, fmt.Sprintf("Remove authenticator Error %s", er.Error()))
	}

	return removeAuthResponse.Response.Success, nil
}

var (
	aligned              = false
	timeDifference int64 = 0
)

type TimeQuery struct {
	Response struct {
		ServerTime                        string `json:"server_time"`
		SkewToleranceSeconds              string `json:"skew_tolerance_seconds"`
		LargeTimeJink                     string `json:"large_time_jink"`
		ProbeFrequencySeconds             int    `json:"probe_frequency_seconds"`
		AdjustedTimeProbeFrequencySeconds int    `json:"adjusted_time_probe_frequency_seconds"`
		HintProbeFrequencySeconds         int    `json:"hint_probe_frequency_seconds"`
		SyncTimeout                       int    `json:"sync_timeout"`
		TryAgainSeconds                   int    `json:"try_again_seconds"`
		MaxAttempts                       int    `json:"max_attempts"`
	} `json:"response"`
}

func GetSteamTime() int64 {
	if !aligned {
		alignSteamTime()
	}
	return time.Now().Unix() + timeDifference
}

func GetCurrentSteamChunk() int64 {
	steamTime := GetSteamTime()
	currentSteamChunk := steamTime / 30
	secondsUntilChange := steamTime - (currentSteamChunk * 30)

	return 30 - secondsUntilChange
}

func alignSteamTime() {
	for i := 0; i < 3; i++ {
		currentTime := time.Now().Unix()
		resp, err := http.Post(STEAM_QUERY_TIME_WEBAPI_V1, "", nil)
		if err != nil {
			fmt.Printf("[TimeAlligner] Error while sending request to Steam API Time: %v", err.Error())
			time.Sleep(time.Second * 3)
			continue
		}
		bodyBytes, err2 := ioutil.ReadAll(resp.Body)
		if err2 != nil {
			fmt.Printf("[TimeAlligner] Error while parsing response from Steam API Time: %v", err2.Error())
			time.Sleep(time.Second * 3)
			continue
		}
		var timeQuery TimeQuery
		json.Unmarshal(bodyBytes, &timeQuery)
		steamServerTimeToInt, _ := strconv.Atoi(timeQuery.Response.ServerTime)

		timeDifference = int64(steamServerTimeToInt) - currentTime
		aligned = true
		return
	}
}
