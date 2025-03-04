package gsharp

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"net/http"
	"regexp"
)

const SpanCTX = "span-ctx"

var (
	GetTrackIdErr = errors.New("获取 track id 错误！")
)

// CallbackSuccess 返回成功响应
func CallbackSuccess(context *gin.Context, data any) {
	context.JSON(http.StatusOK, &Callback{Status: CodeSuccess, Message: CodeSuccess.Message(), Data: data})
}

// CallbackError 返回错误响应
func CallbackError(context *gin.Context, status StatusCode) {
	trackId, _ := getTrackIdFromContext(context)
	r := &TrackedErrorResult{
		Callback: Callback{Status: status, Message: status.Message(), Data: nil},
		TrackId:  trackId,
	}
	context.JSON(http.StatusOK, r)
}

func getTrackIdFromContext(context *gin.Context) (trackId string, err error) {
	spanContextInterface, _ := context.Get(SpanCTX)
	match := regexp.MustCompile(`([0-9a-fA-F]{16})`).FindStringSubmatch(fmt.Sprintf("%v", spanContextInterface))
	if len(match) > 0 {
		return match[1], nil
	}
	return "", GetTrackIdErr
}

type Callback struct {
	// 状态码
	Status StatusCode `json:"status" swaggerType:"integer"`
	// 数据
	Data any `json:"data" swaggerType:"object"`
	// 消息
	Message any `json:"message" swaggerType:"string"`
}

// TrackedErrorResult 带错误ID的错误结构
type TrackedErrorResult struct {
	Callback
	TrackId string `json:"track_id"`
}

type Method string

const (
	Get    Method = "GET"
	Post   Method = "POST"
	Put    Method = "PUT"
	Patch  Method = "PATCH" // RFC 5789
	Delete Method = "DELETE"
)

type StatusCode int64

const (
	// CodeSuccess 成功（默认返回状态码）
	CodeSuccess StatusCode = 200
	// CodeSeverError 全局未知异常
	CodeSeverError StatusCode = 500
	// CodeBadRequest 请求失败（一般前端处理，不常用）
	CodeBadRequest StatusCode = 400
	// CodeDataNotFount 请求资源不存在（静态资源不存在，不常用）
	CodeDataNotFount StatusCode = 404
	// CodeLoginExpire 登录认证异常
	CodeLoginExpire StatusCode = 401
)

// 通用业务
const (
	/*
	   1001-1010 通用操作相关
	*/
	// CodeOperationFail 操作失败
	CodeOperationFail StatusCode = 1001 + iota
	// CodeSelectOperationFail 查询操作失败
	CodeSelectOperationFail
	// CodeUpdateOperationFail 更新操作失败
	CodeUpdateOperationFail
	// CodeDeleteOperationFail 删除操作失败
	CodeDeleteOperationFail
	// CodeInsertOperationFail 新增操作失败
	CodeInsertOperationFail
	// CodeInvalidParam 参数错误
	CodeInvalidParam

	/*
	   1011-1050 例如登录注册相关
	*/
	CodeNoLogin StatusCode = 1011 + iota
	CodeErrorAuthCheckTokenFail
	CodeUserNameOrPasswordFail
)

// StatusCodeMap
// -----------go_api 业务相关（2xxx）------------
var StatusCodeMap = map[StatusCode]string{
	CodeSuccess:                 "success",
	CodeSeverError:              "服务器繁忙请重试",
	CodeBadRequest:              "请求失败",
	CodeDataNotFount:            "未找到资源",
	CodeLoginExpire:             "请登录后重试",
	CodeOperationFail:           "操作失败",
	CodeSelectOperationFail:     "查询操作失败！",
	CodeUpdateOperationFail:     "更新操作失败！",
	CodeDeleteOperationFail:     "删除操作失败！",
	CodeInsertOperationFail:     "新增操作失败！",
	CodeInvalidParam:            "请求参数错误",
	CodeNoLogin:                 "未登陆",
	CodeErrorAuthCheckTokenFail: "token 错误",
	CodeUserNameOrPasswordFail:  "用户名或密码错误",
}

func (status StatusCode) Message() string {
	msg, ok := StatusCodeMap[status]
	if !ok {
		msg = StatusCodeMap[CodeSeverError]
	}
	return msg
}
