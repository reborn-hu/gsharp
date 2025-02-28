package gsharp

import (
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"go.uber.org/zap/zapcore"
	"sync"
	"time"
)

var (
	Configuration        *ConfigurationRoot // 配置文件根节点
	configurationManager *viper.Viper       // 日志管理器
	configurationOnce    sync.Once
)

func (build *HostBuilder) UseConfiguration(path string) *HostBuilder {
	configurationOnce.Do(func() {
		configurationManager = viper.New()
		configurationManager.SetConfigFile(path)
		if err := configurationManager.ReadInConfig(); err != nil {
			panic(errors.Errorf("配置文件读取失败！Error:%v", err))
		}
		if err := configurationManager.Unmarshal(&Configuration); err != nil {
			panic(errors.Errorf("转换配置对象错误！Error:%v", err))
		}
		build.ApplicationName = Configuration.AppName
	})
	return build
}

func GetSection(key string) (val string) {
	if configurationManager == nil {
		panic(errors.Errorf("请调用UseConfigurationBuilder()初始化配置组件！"))
	}
	return configurationManager.GetString(key)
}

type ConfigurationRoot struct {
	AppName     string      `json:"appName" yaml:"appName" mapstructure:"appName"`
	Version     string      `json:"version" yaml:"version" mapstructure:"version"`
	Doc         bool        `json:"doc" yaml:"doc" mapstructure:"doc"`
	Nacos       Nacos       `json:"nacos" yaml:"nacos" mapstructure:"nacos"`
	Jwt         Jwt         `json:"jwt"  yaml:"jwt" mapstructure:"jwt"`
	Gin         Gin         `json:"gin" yaml:"gin" mapstructure:"gin"`
	Logger      Logger      `json:"logger" yaml:"logger" mapstructure:"logger"`
	DataSource  DataSource  `json:"dataSource" yaml:"dataSource" mapstructure:"dataSource"`
	RedisSource RedisSource `json:"redisSource" yaml:"redisSource" mapstructure:"redisSource"`
}

// ============================================================================
// Nacos配置
// ============================================================================

type Nacos struct {
	Enable  bool                   `json:"enable" yaml:"enable"  mapstructure:"enable"`
	Scheme  string                 `json:"scheme" yaml:"scheme" mapstructure:"scheme"`
	Address string                 `json:"address" yaml:"address" mapstructure:"address"`
	Port    uint64                 `json:"port" yaml:"port"  mapstructure:"port"`
	Clients map[string]NacosClient `json:"clients" yaml:"clients" mapstructure:"clients"`
}

type NacosClient struct {
	Namespace   string   `json:"namespace" yaml:"namespace" mapstructure:"namespace"`
	DataId      string   `json:"dataId" yaml:"dataId" mapstructure:"dataId"`
	Group       string   `json:"group" yaml:"group" mapstructure:"group"`
	UserName    string   `json:"userName" yaml:"userName" mapstructure:"userName"`
	Password    string   `json:"password" yaml:"password" mapstructure:"password"`
	Timeout     uint64   `json:"timeout" yaml:"timeout" mapstructure:"timeout"`
	CacheEnable bool     `json:"cacheEnable" yaml:"cacheEnable" mapstructure:"cacheEnable"`
	LogLevel    LogLevel `json:"logLevel" yaml:"logLevel" mapstructure:"logLevel"`
}

// ============================================================================
// Gin配置
// ============================================================================

type Gin struct {
	Address string `json:"address" yaml:"address" mapstructure:"address"`
	Port    int32  `json:"port" yaml:"port" mapstructure:"port"`
	Cors    Cors   `json:"cors" yaml:"cors" mapstructure:"cors"`
}

type Cors struct {
	Origins []string `json:"origins" yaml:"origins" mapstructure:"origins"`
	Headers []string `json:"headers" yaml:"headers" mapstructure:"headers"`
}

type Jwt struct {
	Issuer         string        `json:"issuer" yaml:"issuer" mapstructure:"issuer"`
	Audience       []string      `json:"audience" yaml:"audience" mapstructure:"audience"`
	Secret         string        `json:"secret" yaml:"secret" mapstructure:"secret"`
	AccessExpires  time.Duration `json:"accessExpires" yaml:"accessExpires" mapstructure:"accessExpires"`
	RefreshExpires time.Duration `json:"refreshExpires" yaml:"refreshExpires" mapstructure:"refreshExpires"`
}

// ============================================================================
// 日志配置
// ============================================================================

type Logger struct {
	Level     LogLevel `json:"level" yaml:"level" mapstructure:"level"`
	MaxSize   int      `json:"maxSize" yaml:"maxSize" mapstructure:"maxSize"`
	MaxAge    int      `json:"maxAge" yaml:"maxAge" mapstructure:"maxAge"`
	MaxBackup int      `json:"maxBackup" yaml:"maxBackup" mapstructure:"maxBackup"`
	WriteFile bool     `json:"writeFile" yaml:"writeFile"  mapstructure:"writeFile"`
}

type LogLevel string

const (
	Debug LogLevel = "Debug"
	Info  LogLevel = "Info"
	Warn  LogLevel = "Warn"
	Error LogLevel = "Error"
)

func (enum LogLevel) ToString() string {
	switch enum {
	case Debug:
		return "Debug"
	case Warn:
		return "Warn"
	case Info:
		return "Info"
	case Error:
		return "Error"
	default:
		return "Info"
	}
}

func (enum LogLevel) ToZapLevel() zapcore.Level {
	switch enum {
	case Debug:
		return zapcore.DebugLevel
	case Warn:
		return zapcore.WarnLevel
	case Info:
		return zapcore.InfoLevel
	case Error:
		return zapcore.ErrorLevel
	default:
		return zapcore.InfoLevel
	}
}

// ============================================================================
// Redis配置
// ============================================================================

type RedisSource struct {
	Prefix             string                            `json:"prefix" yaml:"prefix" mapstructure:"prefix"`
	ConnectType        RedisConnectType                  `json:"connectType" yaml:"connectType" mapstructure:"connectType"`
	MasterName         string                            `json:"masterName" yaml:"masterName" mapstructure:"masterName"`
	ConnectionSettings map[string]RedisConnectionOptions `json:"connectionSettings" yaml:"connectionSettings" mapstructure:"connectionSettings"`
}
type RedisConnectionOptions struct {
	Protocol  string          `json:"protocol" yaml:"protocol" mapstructure:"protocol"`
	Password  string          `json:"password" yaml:"password" mapstructure:"password"`
	Database  int             `json:"database" yaml:"database" mapstructure:"database"`
	PoolSize  int             `json:"poolSize" yaml:"poolSize" mapstructure:"poolSize"`
	Endpoints []RedisEndpoint `json:"endpoints" yaml:"endpoints" mapstructure:"endpoints"`
}
type RedisEndpoint struct {
	Host string `json:"host" yaml:"host" mapstructure:"host"`
	Port int    `json:"port" yaml:"port" mapstructure:"port"`
}
type RedisConnectType string

const (
	Single   RedisConnectType = "Single"
	Cluster  RedisConnectType = "Cluster"
	Sentinel RedisConnectType = "Sentinel"
)

func (enum RedisConnectType) ToString() string {
	switch enum {
	case Single:
		return "Single"
	case Cluster:
		return "Cluster"
	case Sentinel:
		return "Sentinel"
	default:
		return "Single"
	}
}

// ============================================================================
// 数据库配置
// ============================================================================

type DataSource struct {
	DbType             DatabaseType      `json:"dbType" yaml:"dbType" mapstructure:"dbType"`
	CipherType         CipherType        `json:"cipherType" yaml:"cipherType" mapstructure:"cipherType"`
	ConnectionSettings map[string]string `json:"dataSource" yaml:"connectionSettings" mapstructure:"connectionSettings"`
	Pooling            Pooling           `json:"pooling" yaml:"pooling" mapstructure:"pooling"`
}
type Pooling struct {
	MaxIdle  string `json:"maxIdle" yaml:"maxIdle" mapstructure:"maxIdle"`
	MaxOpen  string `json:"maxOpen" yaml:"maxOpen" mapstructure:"maxOpen"`
	Lifetime string `json:"lifetime" yaml:"lifetime" mapstructure:"lifetime"`
}

type DatabaseType string

const (
	Sqlite     DatabaseType = "Sqlite"
	PostgreSQL DatabaseType = "PostgreSQL"
	MySql      DatabaseType = "MySql"
	SqlServer  DatabaseType = "SqlServer"
)

func (enum DatabaseType) ToString() string {
	switch enum {
	case Sqlite:
		return "Sqlite"
	case PostgreSQL:
		return "PostgreSQL"
	case MySql:
		return "MySql"
	case SqlServer:
		return "SqlServer"
	default:
		return "Sqlite"
	}
}

type CipherType string

const (
	Plaintext  CipherType = "Plaintext"
	Ciphertext CipherType = "Ciphertext"
)

func (enum CipherType) ToString() string {
	switch enum {
	case Plaintext:
		return "Plaintext"
	case Ciphertext:
		return "Ciphertext"
	default:
		return "Plaintext"
	}
}

type DbConnectType string

const (
	BaseWrite DbConnectType = "BaseWrite"
	BaseRead  DbConnectType = "BaseRead"
	BizWrite  DbConnectType = "BizWrite"
	BizRead   DbConnectType = "BizRead"
)

func (enum DbConnectType) ToString() string {
	switch enum {
	case BaseWrite:
		return "basewrite"
	case BaseRead:
		return "baseread"
	case BizWrite:
		return "bizwrite"
	case BizRead:
		return "bizread"
	default:
		return "basewrite"
	}
}
