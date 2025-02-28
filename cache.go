package gsharp

import (
	"context"
	"fmt"
	"github.com/coocood/freecache"
	"github.com/go-redis/redis/v8"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"strconv"
	"sync"
	"time"
)

var (
	freeCache *LocalCache
	cacheMap  sync.Map
)

type LocalCache struct {
	*freecache.Cache
}
type redisOption struct {
	prefix     string
	section    string
	background context.Context
	client     *redis.Client
}
type IRedis interface {
	Set(key string, val any, expiration time.Duration) bool
	SetNX(key string, val any, expiration time.Duration) bool
	SetEX(key string, val any, expiration time.Duration) bool
	SetBit(key string, offset int64, val int) bool
	SetRange(key string, offset int64, val string) bool
	MSet(key string, val map[string]any, expiration time.Duration) bool
	MSetNX(key string, val map[string]any, expiration time.Duration) bool
	Get(key string) string
	GetEX(key string, expiration time.Duration) string
	GetBit(key string, offset int64) int64
	GetRange(key string, start, end int64) string
	GetSet(key string, val any) string
	Incr(key string) int64
	IncrBy(key string, val int64) int64
	IncrByFloat(key string, val float64) float64
	Decr(key string) int64
	DecrBy(key string, decrement int64) int64
	Append(key string, val string) int64
	StrLen(key string) int64
	HSet(key string, field string, val any, expiration time.Duration) bool
	HSetNX(key string, field string, val any, expiration time.Duration) bool
	HMSet(key string, val map[string]any, expiration time.Duration) bool
	HGet(key string, field string) string
	HMGet(key string, field ...string) []any
	HGetAll(key string) map[string]string
	HIncrBy(key string, field string, incr int64) int64
	HIncrByFloat(key string, field string, incr float64) float64
	HVals(key string) []string
	HKeys(key string) []string
	HLen(key string) int64
	HScan(key string, cursor uint64, match string, count int64) ([]string, uint64)
	HExists(key string, field string) bool
	HDel(key string, field ...string) bool
	BLPop(keys []string, timeout time.Duration) []string
	BRPop(keys []string, timeout time.Duration) []string
	BRPopLPush(source, destination string, timeout time.Duration) string
	LIndex(key string, index int64) string
	LInsertAfter(key string, pivot, val any) int64
	LInsertBefore(key string, pivot, val any) int64
	LLen(key string) int64
	LPop(key string) string
	LPush(key string, val []any) int64
	LPushX(key string, val []any) int64
	LRange(key string, start int64, stop int64) []string
	LRem(key string, count int64, val any) int64
	LSet(key string, index int64, value any) string
	LTrim(key string, start int64, stop int64) string
	RPop(key string) string
	RPopLPush(source, destination string) string
	RPush(key string, val []any) int64
	RPushX(key string, val []any) int64
	LPopCount(key string, count int) []string
	RPopCount(key string, count int) []string
	SAdd(key string, members []any) int64
	SCard(key string) int64
	SDiff(keys []string) []string
	SDiffStore(destination string, keys []string) int64
	SInter(keys []string) []string
	SInterStore(destination string, keys []string) int64
	SIsMember(key string, member any) bool
	SMembers(key string) []string
	SMembersMap(key string) map[string]struct{}
	SMove(source, destination string, member any) bool
	SPop(key string) string
	SPopN(key string, count int64) []string
	SRandMember(key string) string
	SRandMemberN(key string, count int64) []string
	SRem(key string, members []any) int64
	SUnion(keys []string) []string
	SUnionStore(destination string, keys []string) int64
	SScan(key string, cursor uint64, match string, count int64) ([]string, uint64)
	ZAdd(key string, members []*redis.Z) int64
	ZCard(key string) int64
}

func (build *HostBuilder) UseLocalCacheBuilder() *HostBuilder {
	freeCache = &LocalCache{
		freecache.NewCache(100 * 1024 * 1024),
	}
	return build
}

func (build *HostBuilder) UseRedisBuilder() *HostBuilder {
	zap.L().Info("=======================Redis预热开始=======================")
	for i, val := range Configuration.RedisSource.ConnectionSettings {
		switch Configuration.RedisSource.ConnectType {
		// 主从和单机连接
		case Single:
			createSingle(context.Background(), i, val)
		// 集群
		case Cluster:
			createCluster(context.Background(), i, val)
		// 哨兵
		case Sentinel:
			createSentinel(context.Background(), i, val)
		}
	}
	zap.L().Info("=======================Redis预热完毕=======================")
	return build
}

// =========================================================================================================================
// 创建Redis实例&切换Redis实例
// =========================================================================================================================

func GetLocalClient() (free *LocalCache) {
	if freeCache != nil {
		return freeCache
	}
	panic(errors.Errorf("未初始化本地缓存实例！"))
}

func GetRedisClient(ctx context.Context, section string) IRedis {
	opt := &redisOption{
		prefix:     Configuration.RedisSource.Prefix,
		section:    section,
		background: ctx,
	}
	val, ok := cacheMap.Load(section)
	if ok {
		opt.client = val.(*redis.Client)
	} else {
		connect := Configuration.RedisSource.ConnectionSettings[section]
		switch Configuration.RedisSource.ConnectType {
		// 主从和单机连接
		case Single:
			createSingle(ctx, section, connect)
		// 集群
		case Cluster:
			createCluster(ctx, section, connect)
		// 哨兵
		case Sentinel:
			createSentinel(ctx, section, connect)
		}
		val, ok := cacheMap.Load(section)
		if ok {
			opt.client = val.(*redis.Client)
		}
	}
	return opt
}

func createSingle(ctx context.Context, section string, config RedisConnectionOptions) {
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", config.Endpoints[0].Host, strconv.Itoa(config.Endpoints[0].Port)),
		DB:       config.Database,
		Password: config.Password,
		PoolSize: config.PoolSize,
	})
	if pong, err := client.Ping(ctx).Result(); err == nil {
		cacheMap.Store(section, client)
		zap.L().Info(fmt.Sprintf("Section：[%v], redis初始化成功！,状态：%v", section, zap.String("pong", pong)))
	} else {
		zap.L().Error(fmt.Sprintf("redis初始化失败！%v", err))
	}
}

func createCluster(ctx context.Context, section string, config RedisConnectionOptions) {
	var array []string
	for _, val := range config.Endpoints {
		array = append(array, fmt.Sprintf("%s:%s", val.Host, strconv.Itoa(val.Port)))
	}
	client := redis.NewClusterClient(&redis.ClusterOptions{
		Addrs: array,
	})
	if pong, err := client.Ping(ctx).Result(); err == nil {
		cacheMap.Store(section, client)
		zap.L().Info(fmt.Sprintf("Section：[%v], redis初始化成功！,状态：%v", section, zap.String("pong", pong)))
	} else {
		zap.L().Info("redis初始化失败！", zap.String("pong", pong))
	}
}

func createSentinel(ctx context.Context, section string, config RedisConnectionOptions) {
	var array []string
	for _, val := range config.Endpoints {
		array = append(array, fmt.Sprintf("%s:%s", val.Host, strconv.Itoa(val.Port)))
	}
	client := redis.NewFailoverClient(&redis.FailoverOptions{
		MasterName:    Configuration.RedisSource.MasterName,
		SentinelAddrs: array,
	})
	if pong, err := client.Ping(ctx).Result(); err == nil {
		cacheMap.Store(section, client)
		zap.L().Info(fmt.Sprintf("Section：[%v], redis初始化成功！,状态：%v", section, zap.String("pong", pong)))
	} else {
		zap.L().Info("redis初始化失败！", zap.String("pong", pong))
	}
}

// =========================================================================================================================
// String 操作
// =========================================================================================================================

func (ctx *redisOption) Set(key string, val any, expiration time.Duration) bool {
	redisKey := ctx.getRedisKey(key)
	redisTime := ctx.getRedisTimeout(expiration)
	if err := ctx.client.Set(ctx.background, redisKey, val, redisTime).Err(); err == nil {
		return true
	}
	return false
}

func (ctx *redisOption) SetNX(key string, val any, expiration time.Duration) bool {
	redisKey := ctx.getRedisKey(key)
	if err := ctx.client.SetNX(ctx.background, redisKey, val, expiration).Err(); err == nil {
		return true
	}
	return false
}

func (ctx *redisOption) SetEX(key string, val any, expiration time.Duration) bool {
	redisKey := ctx.getRedisKey(key)
	if err := ctx.client.SetEX(ctx.background, redisKey, val, expiration).Err(); err == nil {
		return true
	}
	return false
}

func (ctx *redisOption) SetBit(key string, offset int64, val int) bool {
	redisKey := ctx.getRedisKey(key)
	if err := ctx.client.SetBit(ctx.background, redisKey, offset, val).Err(); err == nil {
		return true
	}
	return false
}

func (ctx *redisOption) SetRange(key string, offset int64, val string) bool {
	redisKey := ctx.getRedisKey(key)
	if err := ctx.client.SetRange(ctx.background, redisKey, offset, val).Err(); err == nil {
		return true
	}
	return false
}

func (ctx *redisOption) MSet(key string, val map[string]any, expiration time.Duration) bool {
	redisKey := ctx.getRedisKey(key)
	redisTime := ctx.getRedisTimeout(expiration)
	if err := ctx.client.MSet(ctx.background, redisKey, val).Err(); err == nil {
		ctx.client.Expire(ctx.background, redisKey, redisTime)
		return true
	}
	return false
}

func (ctx *redisOption) MSetNX(key string, val map[string]any, expiration time.Duration) bool {
	redisKey := ctx.getRedisKey(key)
	redisTime := ctx.getRedisTimeout(expiration)
	if err := ctx.client.MSetNX(ctx.background, redisKey, val).Err(); err == nil {
		ctx.client.Expire(ctx.background, redisKey, redisTime)
		return true
	}
	return false
}

func (ctx *redisOption) Get(key string) string {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.Get(ctx.background, redisKey).Result(); err == nil {
		return result
	}
	return ""
}

func (ctx *redisOption) GetEX(key string, expiration time.Duration) string {
	redisKey := ctx.getRedisKey(key)
	redisTime := ctx.getRedisTimeout(expiration)
	if result, err := ctx.client.GetEx(ctx.background, redisKey, redisTime).Result(); err == nil {
		return result
	}
	return ""
}

func (ctx *redisOption) GetBit(key string, offset int64) int64 {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.GetBit(ctx.background, redisKey, offset).Result(); err == nil {
		return result
	}
	return 0
}

func (ctx *redisOption) GetRange(key string, start, end int64) string {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.GetRange(ctx.background, redisKey, start, end).Result(); err == nil {
		return result
	}
	return ""
}

func (ctx *redisOption) GetSet(key string, val any) string {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.GetSet(ctx.background, redisKey, val).Result(); err == nil {
		return result
	}
	return ""
}

func (ctx *redisOption) Incr(key string) int64 {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.Incr(ctx.background, redisKey).Result(); err == nil {
		return result
	}
	return 0
}

func (ctx *redisOption) IncrBy(key string, val int64) int64 {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.IncrBy(ctx.background, redisKey, val).Result(); err == nil {
		return result
	}
	return 0
}

func (ctx *redisOption) IncrByFloat(key string, val float64) float64 {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.IncrByFloat(ctx.background, redisKey, val).Result(); err == nil {
		return result
	}
	return 0
}

func (ctx *redisOption) Decr(key string) int64 {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.Decr(ctx.background, redisKey).Result(); err == nil {
		return result
	}
	return 0
}

func (ctx *redisOption) DecrBy(key string, decrement int64) int64 {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.DecrBy(ctx.background, redisKey, decrement).Result(); err == nil {
		return result
	}
	return 0
}

func (ctx *redisOption) Append(key string, val string) int64 {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.Append(ctx.background, redisKey, val).Result(); err == nil {
		return result
	}
	return 0
}

func (ctx *redisOption) StrLen(key string) int64 {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.StrLen(ctx.background, redisKey).Result(); err == nil {
		return result
	}
	return 0
}

// =========================================================================================================================
// Hash 操作
// =========================================================================================================================

func (ctx *redisOption) HSet(key string, field string, val any, expiration time.Duration) bool {
	redisKey := ctx.getRedisKey(key)
	redisTime := ctx.getRedisTimeout(expiration)
	if err := ctx.client.HSet(ctx.background, redisKey, map[string]any{field: val}).Err(); err == nil {
		ctx.client.Expire(ctx.background, redisKey, redisTime)
		return true
	}
	return false
}

func (ctx *redisOption) HSetNX(key string, field string, val any, expiration time.Duration) bool {
	redisKey := ctx.getRedisKey(key)
	redisTime := ctx.getRedisTimeout(expiration)
	if err := ctx.client.HSetNX(ctx.background, redisKey, field, val).Err(); err == nil {
		ctx.client.Expire(ctx.background, redisKey, redisTime)
		return true
	}
	return false
}

func (ctx *redisOption) HMSet(key string, val map[string]any, expiration time.Duration) bool {
	redisKey := ctx.getRedisKey(key)
	redisTime := ctx.getRedisTimeout(expiration)
	if err := ctx.client.HMSet(ctx.background, redisKey, val).Err(); err == nil {
		ctx.client.Expire(ctx.background, redisKey, redisTime)
		return true
	}
	return false
}

func (ctx *redisOption) HGet(key string, field string) string {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.HGet(ctx.background, redisKey, field).Result(); err == nil {
		return result
	}
	return ""
}

func (ctx *redisOption) HMGet(key string, field ...string) []any {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.HMGet(ctx.background, redisKey, field...).Result(); err == nil {
		return result
	}
	return nil
}

func (ctx *redisOption) HGetAll(key string) map[string]string {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.HGetAll(ctx.background, redisKey).Result(); err == nil {
		return result
	}
	return nil
}

func (ctx *redisOption) HIncrBy(key string, field string, incr int64) int64 {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.HIncrBy(ctx.background, redisKey, field, incr).Result(); err == nil {
		return result
	}
	return 0
}

func (ctx *redisOption) HIncrByFloat(key string, field string, incr float64) float64 {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.HIncrByFloat(ctx.background, redisKey, field, incr).Result(); err == nil {
		return result
	}
	return 0
}

func (ctx *redisOption) HVals(key string) []string {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.HVals(ctx.background, redisKey).Result(); err == nil {
		return result
	}
	return nil
}

func (ctx *redisOption) HKeys(key string) []string {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.HKeys(ctx.background, redisKey).Result(); err == nil {
		return result
	}
	return nil
}

func (ctx *redisOption) HLen(key string) int64 {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.HLen(ctx.background, redisKey).Result(); err == nil {
		return result
	}
	return 0
}

func (ctx *redisOption) HScan(key string, cursor uint64, match string, count int64) ([]string, uint64) {
	redisKey := ctx.getRedisKey(key)
	if keys, curs, err := ctx.client.HScan(ctx.background, redisKey, cursor, match, count).Result(); err == nil {
		return keys, curs
	}
	return nil, 0
}

func (ctx *redisOption) HExists(key string, field string) bool {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.HExists(ctx.background, redisKey, field).Result(); err == nil {
		return result
	}
	return false
}

func (ctx *redisOption) HDel(key string, field ...string) bool {
	redisKey := ctx.getRedisKey(key)
	if err := ctx.client.HDel(ctx.background, redisKey, field...).Err(); err == nil {
		return true
	}
	return false
}

// =========================================================================================================================
// List 操作
// =========================================================================================================================

func (ctx *redisOption) BLPop(keys []string, timeout time.Duration) []string {
	var redisKeys []string
	for i, key := range keys {
		redisKeys[i] = ctx.getRedisKey(key)
	}
	redisTime := ctx.getRedisTimeout(timeout)
	if result, err := ctx.client.BLPop(ctx.background, redisTime, redisKeys...).Result(); err == nil {
		return result
	}
	return nil
}

func (ctx *redisOption) BRPop(keys []string, timeout time.Duration) []string {
	var redisKeys []string
	for i, key := range keys {
		redisKeys[i] = ctx.getRedisKey(key)
	}
	redisTime := ctx.getRedisTimeout(timeout)

	if result, err := ctx.client.BRPop(ctx.background, redisTime, redisKeys...).Result(); err == nil {
		return result
	}
	return nil
}

func (ctx *redisOption) BRPopLPush(source, destination string, timeout time.Duration) string {
	sourceKey := ctx.getRedisKey(source)
	destinationKey := ctx.getRedisKey(destination)
	redisTime := ctx.getRedisTimeout(timeout)
	if result, err := ctx.client.BRPopLPush(ctx.background, sourceKey, destinationKey, redisTime).Result(); err == nil {
		return result
	}
	return ""
}

func (ctx *redisOption) LIndex(key string, index int64) string {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.LIndex(ctx.background, redisKey, index).Result(); err == nil {
		return result
	}
	return ""
}

func (ctx *redisOption) LInsertAfter(key string, pivot, val any) int64 {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.LInsertAfter(ctx.background, redisKey, pivot, val).Result(); err == nil {
		return result
	}
	return 0
}

func (ctx *redisOption) LInsertBefore(key string, pivot, val any) int64 {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.LInsertBefore(ctx.background, redisKey, pivot, val).Result(); err == nil {
		return result
	}
	return 0
}

func (ctx *redisOption) LLen(key string) int64 {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.LLen(ctx.background, redisKey).Result(); err == nil {
		return result
	}
	return 0
}

func (ctx *redisOption) LPop(key string) string {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.LPop(ctx.background, redisKey).Result(); err == nil {
		return result
	}
	return ""
}

func (ctx *redisOption) LPush(key string, val []any) int64 {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.LPush(ctx.background, redisKey, val...).Result(); err == nil {
		return result
	}
	return 0
}

func (ctx *redisOption) LPushX(key string, val []any) int64 {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.LPushX(ctx.background, redisKey, val...).Result(); err == nil {
		return result
	}
	return 0
}

func (ctx *redisOption) LRange(key string, start int64, stop int64) []string {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.LRange(ctx.background, redisKey, start, stop).Result(); err == nil {
		return result
	}
	return nil
}

func (ctx *redisOption) LRem(key string, count int64, val any) int64 {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.LRem(ctx.background, redisKey, count, val).Result(); err == nil {
		return result
	}
	return 0
}

func (ctx *redisOption) LSet(key string, index int64, value any) string {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.LSet(ctx.background, redisKey, index, value).Result(); err == nil {
		return result
	}
	return ""
}

func (ctx *redisOption) LTrim(key string, start int64, stop int64) string {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.LTrim(ctx.background, redisKey, start, stop).Result(); err == nil {
		return result
	}
	return ""
}

func (ctx *redisOption) RPop(key string) string {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.RPop(ctx.background, redisKey).Result(); err == nil {
		return result
	}
	return ""
}

func (ctx *redisOption) RPopLPush(source, destination string) string {
	sourceKey := ctx.getRedisKey(source)
	destinationKey := ctx.getRedisKey(destination)
	if result, err := ctx.client.RPopLPush(ctx.background, sourceKey, destinationKey).Result(); err == nil {
		return result
	}
	return ""
}

func (ctx *redisOption) RPush(key string, val []any) int64 {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.RPush(ctx.background, redisKey, val...).Result(); err == nil {
		return result
	}
	return 0
}

func (ctx *redisOption) RPushX(key string, val []any) int64 {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.RPushX(ctx.background, redisKey, val...).Result(); err == nil {
		return result
	}
	return 0
}

func (ctx *redisOption) LPopCount(key string, count int) []string {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.LPopCount(ctx.background, redisKey, count).Result(); err == nil {
		return result
	}
	return nil
}

func (ctx *redisOption) RPopCount(key string, count int) []string {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.RPopCount(ctx.background, redisKey, count).Result(); err == nil {
		return result
	}
	return nil
}

// =========================================================================================================================
// Set 操作
// =========================================================================================================================

func (ctx *redisOption) SAdd(key string, members []any) int64 {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.SAdd(ctx.background, redisKey, members).Result(); err == nil {
		return result
	}
	return 0
}

func (ctx *redisOption) SCard(key string) int64 {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.SCard(ctx.background, redisKey).Result(); err == nil {
		return result
	}
	return 0
}

func (ctx *redisOption) SDiff(keys []string) []string {
	var redisKeys []string
	for i, key := range keys {
		redisKeys[i] = ctx.getRedisKey(key)
	}
	if result, err := ctx.client.SDiff(ctx.background, redisKeys...).Result(); err == nil {
		return result
	}
	return nil
}

func (ctx *redisOption) SDiffStore(destination string, keys []string) int64 {
	var redisKeys []string
	for i, key := range keys {
		redisKeys[i] = ctx.getRedisKey(key)
	}
	destinationKey := ctx.getRedisKey(destination)
	if result, err := ctx.client.SDiffStore(ctx.background, destinationKey, redisKeys...).Result(); err == nil {
		return result
	}
	return 0
}

func (ctx *redisOption) SInter(keys []string) []string {
	var redisKeys []string
	for i, key := range keys {
		redisKeys[i] = ctx.getRedisKey(key)
	}
	if result, err := ctx.client.SInter(ctx.background, redisKeys...).Result(); err == nil {
		return result
	}
	return nil
}

func (ctx *redisOption) SInterStore(destination string, keys []string) int64 {
	var redisKeys []string
	for i, key := range keys {
		redisKeys[i] = ctx.getRedisKey(key)
	}
	destinationKey := ctx.getRedisKey(destination)
	if result, err := ctx.client.SInterStore(ctx.background, destinationKey, redisKeys...).Result(); err == nil {
		return result
	}
	return 0
}

func (ctx *redisOption) SIsMember(key string, member any) bool {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.SIsMember(ctx.background, redisKey, member).Result(); err == nil {
		return result
	}
	return false
}

func (ctx *redisOption) SMembers(key string) []string {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.SMembers(ctx.background, redisKey).Result(); err == nil {
		return result
	}
	return nil
}

func (ctx *redisOption) SMembersMap(key string) map[string]struct{} {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.SMembersMap(ctx.background, redisKey).Result(); err == nil {
		return result
	}
	return nil
}

func (ctx *redisOption) SMove(source, destination string, member any) bool {
	sourceKey := ctx.getRedisKey(source)
	destinationKey := ctx.getRedisKey(destination)
	if result, err := ctx.client.SMove(ctx.background, sourceKey, destinationKey, member).Result(); err == nil {
		return result
	}
	return false
}

func (ctx *redisOption) SPop(key string) string {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.SPop(ctx.background, redisKey).Result(); err == nil {
		return result
	}
	return ""
}

func (ctx *redisOption) SPopN(key string, count int64) []string {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.SPopN(ctx.background, redisKey, count).Result(); err == nil {
		return result
	}
	return nil
}

func (ctx *redisOption) SRandMember(key string) string {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.SRandMember(ctx.background, redisKey).Result(); err == nil {
		return result
	}
	return ""
}

func (ctx *redisOption) SRandMemberN(key string, count int64) []string {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.SRandMemberN(ctx.background, redisKey, count).Result(); err == nil {
		return result
	}
	return nil
}

func (ctx *redisOption) SRem(key string, members []any) int64 {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.SRem(ctx.background, redisKey, members...).Result(); err == nil {
		return result
	}
	return 0
}

func (ctx *redisOption) SUnion(keys []string) []string {
	var redisKeys []string
	for i, key := range keys {
		redisKeys[i] = ctx.getRedisKey(key)
	}
	if result, err := ctx.client.SUnion(ctx.background, redisKeys...).Result(); err == nil {
		return result
	}
	return nil
}

func (ctx *redisOption) SUnionStore(destination string, keys []string) int64 {
	var redisKeys []string
	for i, key := range keys {
		redisKeys[i] = ctx.getRedisKey(key)
	}
	destinationKey := ctx.getRedisKey(destination)
	if result, err := ctx.client.SUnionStore(ctx.background, destinationKey, redisKeys...).Result(); err == nil {
		return result
	}
	return 0
}

func (ctx *redisOption) SScan(key string, cursor uint64, match string, count int64) ([]string, uint64) {
	redisKey := ctx.getRedisKey(key)
	if result, curs, err := ctx.client.SScan(ctx.background, redisKey, cursor, match, count).Result(); err == nil {
		return result, curs
	}
	return nil, 0
}

// =========================================================================================================================
// Sorted Set 操作
// =========================================================================================================================

func (ctx *redisOption) ZAdd(key string, members []*redis.Z) int64 {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.ZAdd(ctx.background, redisKey, members...).Result(); err == nil {
		return result
	}
	return 0
}

func (ctx *redisOption) ZCard(key string) int64 {
	redisKey := ctx.getRedisKey(key)
	if result, err := ctx.client.ZCard(ctx.background, redisKey).Result(); err == nil {
		return result
	}
	return 0
}

// =========================================================================================================================
// 基础方法
// =========================================================================================================================

func (ctx *redisOption) getRedisKey(key string) string {
	if len(ctx.prefix) == 0 {
		return fmt.Sprintf("%v:%v", "default", key)
	} else {
		return fmt.Sprintf("%v:%v", ctx.prefix, key)
	}
}

func (ctx *redisOption) getRedisTimeout(expiration time.Duration) time.Duration {
	if expiration <= 0 {
		return -1
	} else {
		return expiration * time.Second
	}
}
