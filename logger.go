package gsharp

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

var logOnce sync.Once

func (build *HostBuilder) UseLogger() *HostBuilder {
	logOnce.Do(func() {
		// 日志基础配置
		encoderConfig := zap.NewProductionEncoderConfig()
		encoderConfig.EncodeName = zapcore.FullNameEncoder
		encoderConfig.EncodeCaller = zapcore.ShortCallerEncoder
		encoderConfig.EncodeDuration = zapcore.SecondsDurationEncoder
		encoderConfig.EncodeTime = func(time time.Time, encoder zapcore.PrimitiveArrayEncoder) {
			encoder.AppendString(time.Format("2006-06-02 15:04:05.000"))
		}
		encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder

		// 日志输出配置
		var core zapcore.Core
		if Configuration.Logger.WriteFile {
			encoder := zapcore.NewConsoleEncoder(encoderConfig)
			core = zapcore.NewTee(
				zapcore.NewCore(encoder, getWriteSyncer(Configuration.Logger, "./logs/debug.log"), zap.LevelEnablerFunc(func(lev zapcore.Level) bool {
					return lev == zap.DebugLevel
				})),
				zapcore.NewCore(encoder, getWriteSyncer(Configuration.Logger, "./logs/info.log"), zap.LevelEnablerFunc(func(lev zapcore.Level) bool {
					return lev == zap.InfoLevel
				})),
				zapcore.NewCore(encoder, getWriteSyncer(Configuration.Logger, "./logs/warn.log"), zap.LevelEnablerFunc(func(lev zapcore.Level) bool {
					return lev == zap.WarnLevel
				})),
				zapcore.NewCore(encoder, getWriteSyncer(Configuration.Logger, "./logs/error.log"), zap.LevelEnablerFunc(func(lev zapcore.Level) bool {
					return lev >= zap.ErrorLevel
				})),
			)
		} else {
			encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
			core = zapcore.NewTee(zapcore.NewCore(zapcore.NewConsoleEncoder(encoderConfig), zapcore.Lock(os.Stdout), Configuration.Logger.Level.ToZapLevel()))
		}

		// 创建日志实例
		if build.Environment == Local || build.Environment == Dev {
			zap.ReplaceGlobals(zap.New(core, zap.AddCaller(), zap.Development()))
		} else {
			zap.ReplaceGlobals(zap.New(core, zap.AddCaller()))
		}

		fmt.Printf("  _____\n |  __ \\ \n | |__) |_   _  _ __  ___  _   _   ___ \n |  ___/| | | || '__|/ __|| | | | / _ \\\n | |    | |_| || |   \\__ \\| |_| ||  __/\n |_|     \\____||_|   |___/ \\____| \\___|\t")
		fmt.Printf("框架版本: %v \n", build.FrameworkVersion)
		zap.L().Info(fmt.Sprintf("应用名称:[%v]", build.ApplicationName))
		zap.L().Info(fmt.Sprintf("应用版本:[%v]", Configuration.Version))
		zap.L().Info(fmt.Sprintf("运行环境:[%v]", build.Environment))
		zap.L().Info("正在启动...")
	})
	return build
}

func getWriteSyncer(options Logger, filename string) zapcore.WriteSyncer {
	return zapcore.NewMultiWriteSyncer(zapcore.AddSync(&lumberjack.Logger{
		Filename:   filename,          // 日志文件路径
		MaxSize:    options.MaxSize,   // 每个日志文件保存的大小 单位:M
		MaxAge:     options.MaxAge,    // 文件最多保存多少天
		MaxBackups: options.MaxBackup, // 日志文件最多保存多少个备份F
		Compress:   false,             // 是否压缩
	}), zapcore.Lock(os.Stdout))
}

// GinLogger 接收gin框架默认的日志
func GinLogger() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Next()
		zap.L().Info("",
			zap.Int("status", ctx.Writer.Status()),
			zap.String("method", ctx.Request.Method),
			zap.String("path", ctx.Request.URL.Path),
			zap.String("query", ctx.Request.URL.RawQuery),
			zap.String("user-agent", ctx.Request.UserAgent()),
			zap.Duration("time", time.Since(time.Now())),
		)
	}
}

// GinRecovery recover掉项目可能出现的panic，并使用zap记录相关日志
func GinRecovery(stack bool) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		defer func() {
			// 获取异常
			if err := recover(); err != nil {
				// 检查是否有断开的连接，因为这并不是一个真正需要进行紧急堆栈跟踪的条件。
				var brokenPipe bool
				if ne, ok := err.(*net.OpError); ok {
					if se, ok := ne.Err.(*os.SyscallError); ok {
						if strings.Contains(strings.ToLower(se.Error()), "broken pipe") || strings.Contains(strings.ToLower(se.Error()), "connection reset by peer") {
							brokenPipe = true
						}
					}
				}
				httpRequest, _ := httputil.DumpRequest(ctx.Request, false)
				if brokenPipe {
					zap.L().Error(ctx.Request.URL.Path,
						zap.String("request", string(httpRequest)),
						zap.Any("error", err),
					)
					// 如果连接已断开，则无法向其写入状态。nolint:err-check
					_ = ctx.Error(err.(error))
					ctx.Abort()
					return
				}

				if stack {
					zap.L().Error("[Recovery from panic]",
						zap.String("request", string(httpRequest)),
						zap.String("stack", string(debug.Stack())),
						zap.Any("error", err),
					)
				} else {
					zap.L().Error("[Recovery from panic]",
						zap.String("request", string(httpRequest)),
						zap.Any("error", err),
					)
				}
				ctx.AbortWithStatus(http.StatusInternalServerError)
			}
		}()
		ctx.Next()
	}
}
