package main

import (
	"C"

	eip "github.com/saitima/eip1962go/eip"
)
import (
	"unsafe"
)

//export Run
func Run(i *C.char, i_len C.int) (C.int, *C.char) {
	buf := C.GoBytes(unsafe.Pointer(i), i_len)
	res, err := new(eip.API).Run(buf)
	if err != nil {
		return C.int(int(res[0])), C.CString(string(err.Error()))
	}
	return C.int(int(res[0])), C.CString("")
}

func main() {}
