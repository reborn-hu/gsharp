package gsharp

import (
	"embed"
	"fmt"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"net/http"
	"os"
	"strings"
	"sync"
	"text/template"
)

type groupOptions struct {
	Url            string `json:"url"`
	Location       string `json:"location"`
	Name           string `json:"name"`
	SwaggerVersion string `json:"swaggerVersion"`
}

type knife4jRoot struct {
	RelativePath  string
	ServicesPath  string
	Groups        []groupOptions
	DocPath       string
	DocJson       []byte
	DocJsonPath   string
	DocTemplate   *template.Template
	AppjsPath     string
	AppjsTemplate *template.Template
}

var (
	//go:embed front
	front      embed.FS
	knife4Once sync.Once
	k4jRoot    knife4jRoot // Knife4j配置文件
)

func (build *HostBuilder) UseKnife4j(relativePath string) *HostBuilder {
	knife4Once.Do(func() {
		docJson, err := os.ReadFile("./settings/docs/swagger.json")
		if err != nil {
			zap.L().Error("no swagger.json found in ./docs")
		}
		k4jRoot.DocJson = docJson
		k4jRoot.RelativePath = relativePath
		k4jRoot.DocPath = fmt.Sprint(relativePath, "/index")
		k4jRoot.DocJsonPath = fmt.Sprint(relativePath, "/json")
		k4jRoot.ServicesPath = fmt.Sprint(relativePath, "/front/service")
		k4jRoot.AppjsPath = fmt.Sprint(relativePath, "/front/webjars/js/app.42aa019b.js")
		k4jRoot.Groups = make([]groupOptions, 1)
		k4jRoot.Groups[0] = groupOptions{
			Url:            "/json",
			Location:       "/",
			Name:           "Api Doc",
			SwaggerVersion: "2.0",
		}
		docTemplate, err := template.New("doc.html").Delims("{[(", ")]}").ParseFS(front, "front/doc.html")
		if err != nil {
			zap.L().Error(err.Error())
		}
		appjsTemplate, err := template.New("app.42aa019b.js").Delims("{[(", ")]}").ParseFS(front, "front/webjars/js/app.42aa019b.js")
		if err != nil {
			zap.L().Error(err.Error())
		}
		k4jRoot.DocTemplate = docTemplate
		k4jRoot.AppjsTemplate = appjsTemplate
	})
	return build
}

func AddKnife4j() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if ctx.Request.Method != http.MethodGet {
			ctx.AbortWithStatus(http.StatusMethodNotAllowed)
			return
		}
		switch ctx.Request.RequestURI {
		case k4jRoot.DocPath:
			if err := k4jRoot.DocTemplate.Execute(ctx.Writer, k4jRoot); err != nil {
				zap.L().Error(err.Error())
			}
		case k4jRoot.AppjsPath:
			if err := k4jRoot.AppjsTemplate.Execute(ctx.Writer, k4jRoot); err != nil {
				zap.L().Error(err.Error())
			}
		case k4jRoot.ServicesPath:
			ctx.JSON(http.StatusOK, k4jRoot.Groups)
		case k4jRoot.DocJsonPath:
			ctx.Data(http.StatusOK, "application/json; charset=utf-8", k4jRoot.DocJson)
		default:
			ctx.FileFromFS(strings.TrimPrefix(ctx.Request.RequestURI, k4jRoot.RelativePath), http.FS(front))
		}
	}
}
