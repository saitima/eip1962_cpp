package main

import (
	"C"

	eip "github.com/saitima/eip1962go/eip"
)
import (
	"unsafe"
)

//export c_run_operation
func c_run_operation(op C.char, i *C.char, i_len uint32, o *C.char, o_len *uint32, e *C.char, e_len *uint32) C.int {
	buf := C.GoBytes(unsafe.Pointer(i), C.int(i_len))
	oBuff := C.GoBytes(unsafe.Pointer(o), C.int(768))
	eBuff := C.GoBytes(unsafe.Pointer(e), C.int(256))

	opType := int(op)
	res, err := new(eip.API).Run(opType, buf)
	if err != nil {
		errDesc := []byte(err.Error())
		*e_len = uint32(len(errDesc))
		copy(eBuff[0:], errDesc)
		return 0
	}

	o_bytes := res
	*o_len = uint32(len(o_bytes))
	copy(oBuff[0:], o_bytes)
	return 1
}

func main() {}
