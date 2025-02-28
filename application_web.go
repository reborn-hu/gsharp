package gsharp

import (
	"context"
	"fmt"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"gopkg.in/tylerb/graceful.v1"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

type WebHostBuilder struct {
	*HostBuilder
	*gin.Engine
}

var (
	webHostOnce sync.Once
	webHost     *WebHostBuilder
)

// WebBuild 创建Web应用
func (build *HostBuilder) WebBuild() *WebHostBuilder {
	webHostOnce.Do(func() {
		webHost = &WebHostBuilder{
			HostBuilder: build,
		}

		// 根据环境载入gin启动模式
		switch build.Environment {
		case Local:
			gin.SetMode(gin.DebugMode)
		case Dev:
			gin.SetMode(gin.DebugMode)
		case Test:
			gin.SetMode(gin.TestMode)
		case Gray:
			gin.SetMode(gin.ReleaseMode)
		case Uat:
			gin.SetMode(gin.ReleaseMode)
		case Prod:
			gin.SetMode(gin.ReleaseMode)
		default:
			gin.SetMode(gin.ReleaseMode)
		}

		webHost.Engine = gin.New()

		// 设置统一请求日志处理
		webHost.Use(GinLogger(), GinRecovery(true))

		// 设置授信代理
		if err := webHost.SetTrustedProxies([]string{"0.0.0.0"}); err != nil {
			zap.L().Error(err.Error())
		}

		// 非法访问拦截
		webHost.NoRoute(func(context *gin.Context) {
			context.JSON(http.StatusNotFound, gin.H{"message": "错误的访问地址!"})
		})

		// 跨域检查
		origins := cors.DefaultConfig()
		origins.AllowCredentials = true
		origins.AllowMethods = []string{"OPTIONS", "GET", "POST", "DELETE", "PATCH", "PUT"}
		if len(Configuration.Gin.Cors.Headers) != 0 {
			origins.AllowHeaders = Configuration.Gin.Cors.Headers
			origins.ExposeHeaders = Configuration.Gin.Cors.Headers
		}
		if len(Configuration.Gin.Cors.Origins) != 0 {
			origins.AllowOrigins = Configuration.Gin.Cors.Origins
		}
		webHost.Use(cors.New(origins))

		// 开启文档
		if Configuration.Doc {
			build.UseKnife4j("/doc")
			webHost.GET("/doc/*any", AddKnife4j())
		}
	})
	return webHost
}

type RouterOptions struct {
	Method           Method
	Handler          gin.HandlerFunc
	Authorize        bool
	AuthorizeHandler gin.HandlerFunc
}

// UseRouter 添加路由
func (host *WebHostBuilder) UseRouter(relativePath string, router map[string]RouterOptions) *WebHostBuilder {
	api := host.Group(relativePath)
	{
		for item, val := range router {
			switch val.Method {
			case Get:
				if val.Authorize {
					api.GET(item, val.AuthorizeHandler, val.Handler)
				} else {
					api.GET(item, val.Handler)
				}
			case Post:
				if val.Authorize {
					api.POST(item, val.AuthorizeHandler, val.Handler)
				} else {
					api.POST(item, val.Handler)
				}
			case Put:
				if val.Authorize {
					api.PUT(item, val.AuthorizeHandler, val.Handler)
				} else {
					api.PUT(item, val.Handler)
				}
			case Patch:
				if val.Authorize {
					api.PATCH(item, val.AuthorizeHandler, val.Handler)
				} else {
					api.PATCH(item, val.Handler)
				}
			case Delete:
				if val.Authorize {
					api.DELETE(item, val.AuthorizeHandler, val.Handler)
				} else {
					api.DELETE(item, val.Handler)
				}
			}
		}
	}
	return host
}

// UseStatic 添加静态文件支持
func (host *WebHostBuilder) UseStatic(router string, path string) *WebHostBuilder {
	host.Static(router, path)
	return host
}

// Run 启动应用
func (host *WebHostBuilder) Run() {
	port := Configuration.Gin.Port
	if port <= 80 || port >= 65535 {
		port = 9527
	}
	ip := Configuration.Gin.Address
	if ip == "0.0.0.0" || len(strings.Split(ip, ".")) != 4 {
		ip = "localhost"
	}
	if host.Environment != Local {
		if conn, err := net.Dial("udp", "192.168.1.100:50000"); err == nil {
			ip = strings.Split(conn.LocalAddr().(*net.UDPAddr).String(), ":")[0]
			if len(strings.Split(ip, ".")) != 4 {
				ip = "localhost"
			}
		}
	}
	zap.L().Info(fmt.Sprintf("Doc访问地址: http://%v:%v/doc/index", ip, port))

	// 使用 graceful 管理 Gin 服务从而优雅的停止
	var serv = &graceful.Server{
		Timeout: 10 * time.Second,
		Server: &http.Server{
			Addr:    fmt.Sprintf("%v:%d", ip, port),
			Handler: host.Engine,
		},
	}

	// 开启一个goroutine启动服务 启动 HttpServer
	go func() {
		if err := serv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			zap.L().Fatal(fmt.Sprintf("监听错误: %s\n", err))
		}
	}()

	// 等待中断信号
	quit := make(chan os.Signal)

	// kill 默认会发送 syscall.SIGTERM 信号
	// kill -2 发送 syscall.SIGINT 信号，我们常用的Ctrl+C就是触发系统SIGINT信号
	// kill -9 发送 syscall.SIGKILL 信号，但是不能被捕获，所以不需要添加它
	// signal.Notify把收到的 syscall.SIGINT或syscall.SIGTERM 信号转发给quit
	// 此处不会阻塞
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// 阻塞在此，当接收到上述两种信号时才会往下执行
	<-quit
	zap.L().Info("正在停止服务器...")

	// 创建一个3秒的超时上下文
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// 关闭 HttpServer 3秒内优雅关闭服务（将未处理完的请求处理完再关闭服务），超过5秒就超时退出
	if err := serv.Shutdown(ctx); err != nil {
	}
	zap.L().Info("服务器已关闭！")
}
