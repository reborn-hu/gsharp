package gsharp

import (
	"fmt"
	"sync"
	"time"
)

var worker *WorkerOptions

type WorkerOptions struct {
	mu        sync.Mutex
	timeStamp int64
	workerId  int64
	number    int64
}

const (
	workerBits  uint8 = 10                      //机器码位数
	numberBits  uint8 = 12                      //序列号位数
	workerMax   int64 = -1 ^ (-1 << workerBits) //机器码最大值（即1023）
	numberMax   int64 = -1 ^ (-1 << numberBits) //序列号最大值（即4095）
	timeShift         = workerBits + numberBits //时间戳偏移量
	workerShift       = numberBits              //机器码偏移量
	epoch       int64 = 1701446399000           //起始常量时间戳（毫秒）,此处选取的时间是2022-07-03 21:49:04
)

func (build *HostBuilder) UseWorkerBuilder(workerId int64) {
	if workerId < 0 || workerId > workerMax {
		panic("WorkerId超过了限制！")
	}
	worker = new(WorkerOptions)
	worker.number = 0
	worker.timeStamp = 0
	worker.workerId = workerId
}

func (w *WorkerOptions) NextId() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	//当前时间的毫秒时间戳
	now := time.Now().UnixNano() / 1e6
	//如果时间戳与当前时间相同，则增加序列号
	if w.timeStamp == now {
		w.number++
		//如果序列号超过了最大值，则更新时间戳
		if w.number > numberMax {
			for now <= w.timeStamp {
				now = time.Now().UnixNano() / 1e6
			}
		}
	} else { //如果时间戳与当前时间不同，则直接更新时间戳
		w.number = 0
		w.timeStamp = now
	}
	//ID由时间戳、机器编码、序列号组成
	ID := (now-epoch)<<timeShift | (w.workerId << workerShift) | (w.number)
	return ID
}

func (w *WorkerOptions) NextIdString() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	//当前时间的毫秒时间戳
	now := time.Now().UnixNano() / 1e6
	//如果时间戳与当前时间相同，则增加序列号
	if w.timeStamp == now {
		w.number++
		//如果序列号超过了最大值，则更新时间戳
		if w.number > numberMax {
			for now <= w.timeStamp {
				now = time.Now().UnixNano() / 1e6
			}
		}
	} else { //如果时间戳与当前时间不同，则直接更新时间戳
		w.number = 0
		w.timeStamp = now
	}
	//ID由时间戳、机器编码、序列号组成
	ID := (now-epoch)<<timeShift | (w.workerId << workerShift) | (w.number)
	return fmt.Sprint(ID)
}
