package xwx

import (
	"crypto/sha1"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"sort"
	"strconv"
	"time"
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
type Profile struct {
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

func GetProfile(accessToken string, openID string) (*Profile, error) {
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
	pres := new(Profile)
	return pres, json.Unmarshal(bs, pres)
}

// 签名验证(确定是否为微信服务器发过来的消息)
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

/*
微信消息处理
*/
//消息类型
const (
	MT_EVENT = iota + 1
	MT_TEXT
	MT_IMAGE
	MT_VOICE
	MT_VIDEO
	MT_SHORTVIDEO
	MT_LOCATION
	MT_LINK
)

type MT struct {
	XML     xml.Name `xml:"xml"`
	MsgType string   `xml:"MsgType"`
}

func getMT(data []byte) int {
	v := new(MT)
	if err := xml.Unmarshal(data, v); err != nil {
		log.Panicln(err)
	}
	switch v.MsgType {
	case "event":
		return MT_EVENT
	case "text":
		return MT_TEXT
	case "image":
		return MT_IMAGE
	case "voice":
		return MT_VOICE
	case "video":
		return MT_VIDEO
	case "shortvideo":
		return MT_SHORTVIDEO
	case "location":
		return MT_LOCATION
	case "link":
		return MT_LINK
	}
	panic("不能识别的微信事件推送")
}

const (
	E_SUBSCRIBE   = iota + 1 //关注
	E_UNSUBSCRIBE            //取消关注
	E_SCAN                   //用户已关注时的事件推送
	E_LOCATION               //上报地理位置事件
	E_CLICK                  //自定义菜单事件
	E_VIEW                   //点击菜单跳转链接时的事件推送
)

type ET struct {
	XML    xml.Name `xml:"xml"`
	Eevent string   `xml:"Event"`
}

func getET(data []byte) int {
	v := new(ET)
	if err := xml.Unmarshal(data, v); err != nil {
		log.Panicln(err)
	}
	switch v.Eevent {
	case "subscribe":
		return E_SUBSCRIBE
	case "unsubscribe":
		return E_UNSUBSCRIBE
	case "SCAN":
		return E_SCAN
	case "LOCATION":
		return E_LOCATION
	case "CLICK":
		return E_CLICK
	case "VIEW":
		return E_VIEW
	}
	panic("不能识别的事件类型")
}

type GetMsgBaser interface {
	getMsgBase() *msgBase
}

type msgBase struct {
	XML          xml.Name `xml:"xml"`
	ToUserName   string   `xml:"ToUserName"`
	FromUserName string   `xml:"FromUserName"`
	CreateTime   string   `xml:"CreateTime"`
	MT
}

func (m msgBase) getMsgBase() *msgBase {
	return &m
}

type eventBase struct {
	msgBase
	Event string `xml:"Event" text:"事件类型"`
}

// 1. 用户未关注时，进行关注后的事件推送,2. 用户已关注时的事件推送
type SubEvent struct {
	eventBase
	EventKey string `xml:"EventKey" text:"事件KEY值，qrscene_为前缀，后面为二维码的参数值"`
	Ticket   string `xml:"Ticket" text:"二维码的ticket，可用来换取二维码图片"`
}

func getSubEvent(data []byte) *SubEvent {
	v := new(SubEvent)
	if err := xml.Unmarshal(data, v); err != nil {
		log.Panicln(err)
	}
	return v
}

// 取消关注事件
type UnSubEvent struct {
	eventBase
}

func getUnSubEvent(data []byte) *UnSubEvent {
	v := new(UnSubEvent)
	if err := xml.Unmarshal(data, v); err != nil {
		log.Panicln(err)
	}
	return v
}

type TextMsg struct {
	msgBase
	Content string `xml:"Content"`
	MsgId   string `xml:"MsgId"`
}

func getTextMsg(data []byte) *TextMsg {
	v := new(TextMsg)
	if err := xml.Unmarshal(data, v); err != nil {
		log.Panicln(err)
	}
	return v
}

/*
解析微信消息类型和消息体
返回消息类型和消息体
*/
func GetMsg(rc io.ReadCloser) (interface{}, int, int) {
	data, err := ioutil.ReadAll(rc)
	if err != nil {
		panic(err.Error())
	}
	defer rc.Close()
	switch getMT(data) {
	case MT_TEXT:
		return getTextMsg(data), MT_TEXT, 0
	case MT_EVENT:
		switch getET(data) {
		case E_SUBSCRIBE:
			return getSubEvent(data), MT_EVENT, E_SUBSCRIBE
		case E_UNSUBSCRIBE:
			return getUnSubEvent(data), MT_EVENT, E_UNSUBSCRIBE
		default:
			log.Println("待开发的事件类型")
			return nil, 0, 0
		}
	default:
		log.Println("待开发的消息类型")
		return nil, 0, 0
	}
}

/*响应消息数据格式*/
type CDATA struct {
	Text string `xml:",innerxml"`
}

func newCDATA(v string) CDATA {
	return CDATA{"<![CDATA[" + v + "]]>"}
}

type replyBase struct {
	XMLName      xml.Name `xml:"xml"`
	ToUserName   CDATA
	FromUserName CDATA
	CreateTime   CDATA
	MsgType      CDATA
}

/*响应消息*文本格式*/
type textReply struct {
	replyBase
	Content CDATA
}

func GetTextReply(mber GetMsgBaser, text string) *textReply {
	mb := mber.getMsgBase()
	tr := new(textReply)
	tr.ToUserName = newCDATA(mb.FromUserName)
	tr.FromUserName = newCDATA(mb.ToUserName)
	tr.CreateTime = newCDATA(strconv.FormatInt(time.Now().Unix(), 10))
	tr.MsgType = newCDATA("text")
	tr.Content = newCDATA(text)
	return tr
}
