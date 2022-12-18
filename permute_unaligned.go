//go:build i386 || amd64 || arm64 || ppc64le || s390x

package sphincs

import "unsafe"

// chachaPermute ...
func chachaPermute(x *[64]byte) {
	doRounds((*[16]uint32)(unsafe.Pointer(x)))
}
