package main

import (
	"C"

	eip "github.com/saitima/eip1962"
)
import (
	"unsafe"
)

const (
	MAX_OUTPUT_LEN = 256 * 3 * 2
	MAX_ERR_LEN    = 256
)

// const NO_EXEC = true
const NO_EXEC = false

//export c_perform_operation
func c_perform_operation(op C.char, i *C.char, i_len uint32, o *C.char, o_len *uint32, e *C.char, e_len *uint32) C.int {
	buf := C.GoBytes(unsafe.Pointer(i), C.int(i_len))
	oBuff := C.GoBytes(unsafe.Pointer(o), C.int(MAX_OUTPUT_LEN))
	eBuff := C.GoBytes(unsafe.Pointer(e), C.int(MAX_ERR_LEN))

	opType := int(op)
	var res []byte
	var err error
	if NO_EXEC {
		res = []byte{0x00, 0x01, 0x00}
		err = nil
	} else {
		res, err = new(eip.API).Run(opType, buf)
	}
	// res, err := new(eip.API).Run(opType, buf)
	if err != nil {
		errDesc := []byte(err.Error())
		*e_len = uint32(len(errDesc))
		copy(eBuff[:], errDesc)
		return 1
	}

	o_bytes := res
	*o_len = uint32(len(o_bytes))
	copy(oBuff[:], o_bytes)
	return 0
}

func main() {}
