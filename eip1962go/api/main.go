package main

import (
	"C"

	eip "github.com/saitima/eip1962go/eip"
)
import (
	"unsafe"
)

//export run
func run(i *C.char, i_len uint32, o *C.char, o_len *uint32, e *C.char, e_len *uint32) C.int {
	buf := C.GoBytes(unsafe.Pointer(i), C.int(i_len))
	oBuff := C.GoBytes(unsafe.Pointer(o), C.int(768))
	eBuff := C.GoBytes(unsafe.Pointer(e), C.int(256))

	opType := int(buf[:1][0])
	res, err := new(eip.API).Run(opType, buf)
	if err != nil {
		err_desr := string(err.Error())
		*e_len = uint32(len(err_desr))
		copy(eBuff[0:], []byte(err_desr))
		return 0
	}

	o_bytes := res
	*o_len = uint32(len(o_bytes))
	copy(oBuff[0:], o_bytes)
	return 1
}

func main() {}
