package gsharp

import (
	"fmt"
	"github.com/glebarez/sqlite"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlserver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
	"strconv"
	"time"
)

// ============================================================================
// 基础字段
// ============================================================================

// PrimaryOptions 主键基础对象
type PrimaryOptions struct {
	Id  int64 `json:"id" gorm:"column:id;type:BIGINT;not null;primaryKey;autoIncrement:true;comment:自增列"`
	Uid int64 `json:"uid" gorm:"column:uid;type:BIGINT;not null;uniqueIndex;autoIncrement:false;comment:唯一主键"`
}

// OperateOptions 操作级基础对象
type OperateOptions struct {
	Enabled    bool     `json:"enabled" gorm:"column:enabled;default:1;comment:是否启用,1 启动（默认） 0 禁用"`
	Del        bool     `json:"del" gorm:"column:del;default:0;comment:是否删除,1 删除 0 未删除（默认）"`
	CreateUser string   `json:"createUser" gorm:"column:create_user;type:VARCHAR(20);size:20;default:'';comment:创建人Id"`
	CreateDate DataTime `json:"createDate" gorm:"column:create_date;type:datetime;default:'1970-01-01';comment:创建时间"`
	ModifyUser string   `json:"modifyUser" gorm:"column:modify_user;type:VARCHAR(20);size:20;default:'';comment:修改人Id"`
	ModifyDate DataTime `json:"modifyDate" gorm:"column:modify_date;type:datetime;default:'1970-01-01';comment:修改时间"`
}

func (options *PrimaryOptions) CreateId() {
	options.Uid = worker.NextId()
}

func (options *OperateOptions) CreateOperate(createUser string) {
	options.Del = false
	options.CreateUser = createUser
	options.CreateDate = DataTime(time.Now())
	options.ModifyDate = DataTime(time.Now())
}

func (options *OperateOptions) DisableOperate(modifyUser string) map[string]any {
	entityMap := make(map[string]any)
	entityMap["enabled"] = options.Enabled == false
	entityMap["modify_user"] = modifyUser
	entityMap["modify_date"] = time.Now()
	return entityMap
}

func (options *OperateOptions) DeleteOperate(modifyUser string) map[string]any {
	entityMap := make(map[string]any)
	entityMap["del"] = true
	entityMap["modify_user"] = modifyUser
	entityMap["modify_date"] = time.Now()
	return entityMap
}

// ============================================================================
// 分页支持
// ============================================================================

type PageList struct {
	Total int64 `json:"total"`
	Items any   `json:"items"`
}

func CreatePageList(total int64, items any) *PageList {
	return &PageList{
		Total: total,
		Items: items,
	}
}

func PaginateScope(page int, pageSize int) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		if page <= 0 {
			page = 1
		}
		switch {
		case pageSize > 100:
			pageSize = 100
		case pageSize <= 0:
			pageSize = 10
		}
		return db.Limit(pageSize).Offset((page - 1) * pageSize)
	}
}

// ============================================================================
// 数据库操作
// ============================================================================

var gormConfig *gorm.Config

type DbClient struct {
	*gorm.DB
}

func (build *HostBuilder) UseDatabaseBuilder() *HostBuilder {
	gormConfig = &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
		NamingStrategy: schema.NamingStrategy{
			SingularTable: true,
		},
		Logger: logger.Default.LogMode(logger.Info),
	}
	if build.Environment == Local || build.Environment == Dev {
		gormConfig.Logger = logger.Default.LogMode(logger.Info)
	} else {
		gormConfig.Logger = logger.Default
	}
	zap.L().Info("初始化数据库组件完毕！")
	return build
}

func GetDbClient(connectType DbConnectType) *DbClient {
	connectString := Configuration.DataSource.ConnectionSettings[connectType.ToString()]
	if len(connectString) > 0 {
		switch Configuration.DataSource.DbType {
		case MySql:
			return createMySql(connectString)
		case Sqlite:
			return createSqlite(connectString)
		case PostgreSQL:
			return createPostgreSQL(connectString)
		case SqlServer:
			return createSqlServer(connectString)
		default:
			panic(fmt.Sprintf("获取数据库客户端失败!"))
		}
	}
	panic(errors.Errorf("数据库配置错误！"))
}

func createMySql(connectString string) *DbClient {
	db, err := gorm.Open(mysql.Open(connectString), gormConfig)
	if err == nil {
		client := &DbClient{
			db,
		}
		return client.createPool()
	}
	panic(err)
}

func createSqlite(connectString string) *DbClient {
	db, err := gorm.Open(sqlite.Open(connectString), gormConfig)
	if err == nil {
		client := &DbClient{
			db,
		}
		return client.createPool()
	}
	panic(err)
}

func createPostgreSQL(connectString string) *DbClient {
	db, err := gorm.Open(postgres.Open(connectString), gormConfig)
	if err == nil {
		client := &DbClient{
			db,
		}
		return client.createPool()
	}
	panic(err)
}

func createSqlServer(connectString string) *DbClient {
	db, err := gorm.Open(sqlserver.Open(connectString), gormConfig)
	if err == nil {
		client := &DbClient{
			db,
		}
		return client.createPool()
	}
	panic(err)
}

func (db *DbClient) createPool() *DbClient {
	sqlDB, _ := db.DB.DB()
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(60 * time.Second)
	// 设置连接池中的最大空闲连接数
	if val, err := strconv.Atoi(Configuration.DataSource.Pooling.MaxIdle); err == nil {
		sqlDB.SetMaxIdleConns(val)
	}
	// 设置数据库的最大连接数
	if val, err := strconv.Atoi(Configuration.DataSource.Pooling.MaxOpen); err == nil {
		sqlDB.SetMaxOpenConns(val)
	}
	// 设置连接的最大生存时间
	if val, err := time.ParseDuration(Configuration.DataSource.Pooling.Lifetime); err == nil {
		sqlDB.SetConnMaxLifetime(val)
	}
	return db
}
