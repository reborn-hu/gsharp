package gsharp

import (
	"fmt"
	"github.com/petersunbag/coven"
	"reflect"
	"sync"
)

var (
	covenMutex sync.Mutex
	covenMap   = make(map[string]*coven.Converter)
)

func Mapper(src, dst interface{}) (err error) {
	key := fmt.Sprintf("%v_%v", reflect.TypeOf(src).String(), reflect.TypeOf(dst).String())
	if _, ok := covenMap[key]; !ok {
		covenMutex.Lock()
		defer covenMutex.Unlock()
		if covenMap[key], err = coven.NewConverter(dst, src); err != nil {
			return
		}
	}
	if err = covenMap[key].Convert(dst, src); err != nil {
		return
	}
	return
}
