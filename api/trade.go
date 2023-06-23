package api

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"steam-web/status"
	"steam-web/utils"
	"strconv"
)

const (
	STEAM_CONFIRM_FROM_MOBILE_WEBAPI           = STEAM_COMMUNITY_WEB_BASE + "/mobileconf/ajaxop"
	STEAM_GET_CONFIRMATIONS_FROM_MOBILE_WEBAPI = STEAM_COMMUNITY_WEB_BASE + "/mobileconf/getlist"
)

const (
	STEAM_TRADE_REQUEST_ERROR = iota + 400000
	CONFIRM_FROM_MOBILE_ERROR
	GET_CONFIRMATIONS_FROM_MOBILE_ERROR
)

func getConfirmationHash(serverTime int64, tag string, identitySecret string) string {
	identitySecretDecoded, _ := base64.StdEncoding.DecodeString(identitySecret)
	secret := []byte(identitySecretDecoded)
	buffer := make([]byte, 4+4+len(tag))
	binary.BigEndian.PutUint32(buffer[4:], uint32(serverTime))
	copy(buffer[8:], []byte(tag))
	confirmation := hmac.New(sha1.New, secret)
	confirmation.Write(buffer)
	return base64.StdEncoding.EncodeToString(confirmation.Sum(nil))
}

func ConfirmByTradeOfferIdFromMobile(session SteamCommunitySession, auth Authenticator, tradeOfferId int64) (bool, *status.Exception) {
	confirmations, err := GetMobileConfirmations(session, auth)
	if err != nil {
		return false, err
	}
	for _, confirmation := range confirmations {
		if confirmation.CreatorId == strconv.FormatInt(tradeOfferId, 10) {
			return ConfirmFromMobile(session, auth, confirmation)
		}
	}
	return false, nil
}

type MobileConfirmation struct {
	Id        string `json:"id"`
	Type      int    `json:"type"`
	CreatorId string `json:"creator_id"`
	Nonce     string `json:"nonce"`
}

type MobileConfirmationsResponse struct {
	Success bool                 `json:"success"`
	Conf    []MobileConfirmation `json:"conf"`
}

//deprecated
//func parseMobileConfirmationsResponse(response string) []MobileConfirmation {
//	doc, _ := goquery.NewDocumentFromReader(strings.NewReader(response))
//	rawConfirmations := doc.Find("#mobileconf_list > .mobileconf_list_entry")
//	if rawConfirmations.Length() == 0 {
//		return nil
//	}
//	confirmations := make([]MobileConfirmation, 0, rawConfirmations.Length())
//	rawConfirmations.Each(func(i int, s *goquery.Selection) {
//		confirmationId, _ := strconv.Atoi(s.AttrOr("data-confid", ""))
//		confirmationKey, _ := strconv.Atoi(s.AttrOr("data-key", ""))
//		tradeOfferId, _ := strconv.Atoi(s.AttrOr("data-creator", ""))
//		confirmation := MobileConfirmation{
//			ConfirmationId:  int64(confirmationId),
//			ConfirmationKey: int64(confirmationKey),
//			TradeOfferId:    int64(tradeOfferId),
//		}
//		confirmations = append(confirmations, confirmation)
//	})
//	return confirmations
//}

type ConfirmResponse struct {
	Success bool `json:"success"`
}

func ConfirmFromMobile(session SteamCommunitySession, auth Authenticator, confirmation MobileConfirmation) (bool, *status.Exception) {
	serverTime := GetSteamTime()
	confirmationHash := getConfirmationHash(serverTime, "allow", auth.IdentitySecret)

	query := map[string][]string{
		"op":  {"allow"},
		"p":   {auth.DeviceId},
		"a":   {auth.SteamId},
		"k":   {confirmationHash},
		"t":   {strconv.FormatInt(serverTime, 10)},
		"m":   {"android"},
		"tag": {"allow"},
		"cid": {confirmation.Id},
		"ck":  {confirmation.Nonce},
	}

	cookies := []*http.Cookie{
		{
			Name:  "mobileClient",
			Value: "android",
		},
		{
			Name:  "mobileClientVersion",
			Value: "0 (2.1.3)",
		},
	}
	if session.Cookies != nil {
		cookies = append(cookies, session.Cookies...)
	}

	var response ConfirmResponse
	_, _, _, responseData, _, requestError := utils.HttpWebRequest("GET", STEAM_CONFIRM_FROM_MOBILE_WEBAPI, nil, query, cookies, nil, true, false)
	if requestError != nil {
		return false, status.NewError(CONFIRM_FROM_MOBILE_ERROR, fmt.Sprintf("Confirm from mobile Error %s", requestError.Error()))
	}
	e := json.Unmarshal(responseData, &response)
	if e != nil {
		return false, status.NewError(STEAM_REQUEST_INCOMP, fmt.Sprintf("Confirm from mobile Error %s", e.Error()))
	}

	return response.Success, nil
}

func GetMobileConfirmations(session SteamCommunitySession, auth Authenticator) ([]MobileConfirmation, *status.Exception) {
	serverTime := GetSteamTime()
	confirmationHash := getConfirmationHash(serverTime, "conf", auth.IdentitySecret)
	query := map[string][]string{
		"p":   {auth.DeviceId},
		"a":   {auth.SteamId},
		"k":   {confirmationHash},
		"t":   {strconv.FormatInt(serverTime, 10)},
		"m":   {"android"},
		"tag": {"conf"},
	}

	cookies := []*http.Cookie{
		{
			Name:  "mobileClient",
			Value: "android",
		},
		{
			Name:  "mobileClientVersion",
			Value: "2.1.3",
		},
		{
			Name:  "steamid",
			Value: auth.SteamId,
		},
		{
			Name:  "Steam_Language",
			Value: "english",
		},
	}
	if session.Cookies != nil {
		cookies = append(cookies, session.Cookies...)
	}

	_, _, _, responseData, _, requestError := utils.HttpWebRequest("GET", STEAM_GET_CONFIRMATIONS_FROM_MOBILE_WEBAPI, nil, query, cookies, nil, false, false)
	if requestError != nil {
		return nil, status.NewError(GET_CONFIRMATIONS_FROM_MOBILE_ERROR, fmt.Sprintf("Get mobile confirmations Error %s", requestError.Error()))
	}

	var mobileConfirmations MobileConfirmationsResponse
	e := json.Unmarshal(responseData, &mobileConfirmations)
	if e != nil {
		return nil, status.NewError(STEAM_REQUEST_INCOMP, fmt.Sprintf("Data incompatible error %s", e.Error()))
	}

	return mobileConfirmations.Conf, nil
}
