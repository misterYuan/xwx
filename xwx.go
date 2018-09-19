package xwx

import (
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"sort"
)

// 用户参数配置
type info struct {
	appID     string
	appSecret string
}

func NewInfo(appID, appSecret string) *info {
	return &info{appID: appID, appSecret: appSecret}
}

// 获取token(发信息的)->生产环境建议将token存入缓存中
type getATRes struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	Errcode     int    `json:"errcode"`
	Errmsg      string `json:"errmsg"`
}

func GetAccessToken(o *info) (*getATRes, error) {
	res, err := http.Get(fmt.Sprintf("https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=%s&secret=%s", o.appID, o.appSecret))
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		return nil, errors.New("请求失败:" + fmt.Sprintf("%d", res.StatusCode))
	}
	bs, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	atres := new(getATRes)
	return atres, json.Unmarshal(bs, atres)
}

// 获取token(获取用户信息的)
type getInfoATRes struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	// RefreshToken string `json:"refresh_token"`
	Openid  string `json:"openid"`
	Scope   string `json:"scope"`
	Errcode int    `json:"errcode"`
	Errmsg  string `json:"errmsg"`
}

func GetInfoAccessToken(o *info, code string) (*getInfoATRes, error) {
	url := fmt.Sprintf(
		"https://api.weixin.qq.com/sns/oauth2/access_token?appid=%s&secret=%s&code=%s&grant_type=authorization_code",
		o.appID, o.appSecret, code,
	)
	res, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, errors.New("请求失败:" + fmt.Sprintf("%d", res.StatusCode))
	}
	bs, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	ires := new(getInfoATRes)
	return ires, json.Unmarshal(bs, ires)
}

// 使用token 获取用户信息
type profileRes struct {
	Openid     string   `json:"openid"`
	Nickname   string   `json:"nickname"`
	Sex        int      `json:"sex"`
	Province   string   `json:"province"`
	City       string   `json:"city"`
	Country    string   `json:"country"`
	HeadImgUrl string   `json:"headimgurl"`
	Privilege  []string `json:"privilege"`
	Unionid    string   `json:"unionid"`
}

func GetProfile(accessToken string, openID string) (*profileRes, error) {
	url := fmt.Sprintf("https://api.weixin.qq.com/sns/userinfo?access_token=%s&openid=%s&lang=zh_CN", accessToken, openID)
	res, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, errors.New("请求失败:" + fmt.Sprintf("%d", res.StatusCode))
	}
	bs, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	pres := new(profileRes)
	return pres, json.Unmarshal(bs, pres)
}

func SignVerify(token, signature, timestamp, nonce string) bool {
	strs := sort.StringSlice{token, timestamp, nonce}
	sort.Strings(strs)
	str := ""
	for _, signature := range strs {
		str += signature
	}
	h := sha1.New()
	h.Write([]byte(str))
	return fmt.Sprintf("%x", h.Sum(nil)) == signature
}
