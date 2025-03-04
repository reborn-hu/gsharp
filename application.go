package gsharp

import (
	"os"
	"sync"
)

const version = "v0.0.0-20240126113001-5yuf8427"

type Env string

const (
	Local Env = "Local"
	Dev   Env = "Dev"
	Test  Env = "Test"
	Uat   Env = "Uat"
	Gray  Env = "Gray"
	Prod  Env = "Prod"
)

// HostOptions
//
// @Description:应用启动参数
type HostOptions struct {
	//  EnvironmentName
	//  @Description: 环境变量
	EnvironmentName string
}

// HostBuilder
//
// @Description: 应用启动构造器
type HostBuilder struct {
	//  Environment
	//  @Description:  环境变量
	Environment Env

	//  FrameworkVersion
	//  @Description:  框架版本
	FrameworkVersion string

	//  ApplicationName
	//  @Description: 应用名称
	ApplicationName string
}

var (
	hostOnce  sync.Once
	hostBuild *HostBuilder
)

// CreateHostBuilder
//
//	@Description: 创建应用构造器
//	@param options 应用启动参数
//	@return *HostBuilder
func CreateHostBuilder(options *HostOptions) *HostBuilder {
	hostOnce.Do(func() {
		hostBuild = &HostBuilder{
			Environment:      Env(os.Getenv(options.EnvironmentName)),
			FrameworkVersion: version,
		}
	})
	return hostBuild
}
