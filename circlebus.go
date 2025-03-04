package gsharp

import "sync"

type (
	ICircleBus interface {
		GetData() any
	}

	circleBusRoot struct {
		mu              sync.Mutex
		GetLocalData    func() any
		GetRedisData    func() any
		GetDatabaseData func() any
		SetLocalData    func(val any)
		SetRedisData    func(val any)
	}
)

func CreateCircleBus(getLocalFunc func() any, getRedisFunc func() any, getDbFunc func() any, setLocalFunc func(val any), setRedisFunc func(val any)) ICircleBus {
	bus := new(circleBusRoot)
	bus.GetLocalData = getLocalFunc
	bus.GetRedisData = getRedisFunc
	bus.GetDatabaseData = getDbFunc
	bus.SetLocalData = setLocalFunc
	bus.SetRedisData = setRedisFunc
	return bus
}

func (bus *circleBusRoot) GetData() any {
	bus.mu.Lock()
	defer bus.mu.Unlock()
	if bus.GetLocalData != nil {
		result := bus.GetLocalData()
		if result != nil {
			return result
		}
	}
	if bus.GetRedisData != nil {
		result := bus.GetRedisData()
		if result != nil && result != "" {
			if bus.SetLocalData != nil {
				bus.SetLocalData(result)
			}
			return result
		}
	}
	if bus.GetDatabaseData != nil {
		result := bus.GetDatabaseData()
		if result != nil {
			if bus.SetRedisData != nil {
				bus.SetRedisData(result)
			}
			if bus.SetLocalData != nil {
				bus.SetLocalData(result)
			}
		}
		return result
	}
	return nil
}
