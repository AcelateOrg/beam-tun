package stack

import "sync"

// Size-classed buffer pools. Buffers exist only while datagrams are in flight,
// so memory follows real load; typical game/voice/DNS datagrams stay in the
// smallest class regardless of the tunnel MTU.
var bufferClasses = [...]int{2048, 16 << 10, 64 << 10}

var bufferPools [len(bufferClasses)]sync.Pool

func getBuffer(size int) *[]byte {
	for i, class := range bufferClasses {
		if size <= class {
			if v := bufferPools[i].Get(); v != nil {
				buf := v.(*[]byte)
				*buf = (*buf)[:size]
				return buf
			}
			buf := make([]byte, size, class)
			return &buf
		}
	}
	buf := make([]byte, size)
	return &buf
}

func putBuffer(buf *[]byte) {
	c := cap(*buf)
	for i, class := range bufferClasses {
		if c == class {
			bufferPools[i].Put(buf)
			return
		}
	}
}
