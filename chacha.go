package sphincs

import (
	"encoding/binary"
	"strconv"
)

const (
	sigma        = "expand 32-byte k"
	chachaRounds = 12
)

// ctx is a ChaCha12 stream state.
type ctx struct {
	input [16]uint32
}

// chachaPrg fills r with a ChaCha12 keystream derived from the 32-byte key k.
func chachaPrg(r, k []byte) {
	var prgNonce [8]byte
	if len(k) != 32 {
		panic("sphincs: chacha key length must be 32: " + strconv.Itoa(len(k)))
	}
	keystreamBytes(r, prgNonce[:], k)
}

// ivSetup sets the 64-bit nonce.
func (x *ctx) ivSetup(iv []byte) {
	x.input[12] = 0
	x.input[13] = 0
	x.input[14] = binary.LittleEndian.Uint32(iv[0:])
	x.input[15] = binary.LittleEndian.Uint32(iv[4:])
}

// encryptBytes XORs m with the keystream into c.
func (x *ctx) encryptBytes(m, c []byte) {
	var output [64]byte
	cc, mm := c, m
	for len(mm) > 0 {
		salsa20WordToByte(&output, &x.input)
		x.input[12]++
		if x.input[12] == 0 {
			x.input[13]++ // stopping at 2^70 bytes per nonce is the caller's responsibility
		}
		n := min(len(mm), len(output))
		for i := range n {
			cc[i] = mm[i] ^ output[i]
		}
		cc = cc[n:]
		mm = mm[n:]
	}
}

// keystreamBytes fills stream with the keystream.
func (x *ctx) keystreamBytes(stream []byte) {
	clear(stream)
	x.encryptBytes(stream, stream)
}

// newCtx initializes a ChaCha12 state with a 32-byte key.
func newCtx(k []byte) *ctx {
	constants := []byte(sigma)
	x := &ctx{}
	x.input[4] = binary.LittleEndian.Uint32(k[0:])
	x.input[5] = binary.LittleEndian.Uint32(k[4:])
	x.input[6] = binary.LittleEndian.Uint32(k[8:])
	x.input[7] = binary.LittleEndian.Uint32(k[12:])
	x.input[8] = binary.LittleEndian.Uint32(k[16:])
	x.input[9] = binary.LittleEndian.Uint32(k[20:])
	x.input[10] = binary.LittleEndian.Uint32(k[24:])
	x.input[11] = binary.LittleEndian.Uint32(k[28:])
	x.input[0] = binary.LittleEndian.Uint32(constants[0:])
	x.input[1] = binary.LittleEndian.Uint32(constants[4:])
	x.input[2] = binary.LittleEndian.Uint32(constants[8:])
	x.input[3] = binary.LittleEndian.Uint32(constants[12:])
	return x
}

// keystreamBytes fills c with the keystream for nonce n and key k.
func keystreamBytes(c, n, k []byte) {
	ctx := newCtx(k)
	ctx.ivSetup(n)
	ctx.keystreamBytes(c)
}

// doRounds applies the 12-round permutation without a final feed-forward.
func doRounds(x *[16]uint32) {
	x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15 := x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9], x[10], x[11], x[12], x[13], x[14], x[15]
	for i := chachaRounds; i > 0; i -= 2 {
		var xx uint32
		x0 += x4
		xx = x12 ^ x0
		x12 = (xx << 16) | (xx >> 16)
		x8 += x12
		xx = x4 ^ x8
		x4 = (xx << 12) | (xx >> 20)
		x0 += x4
		xx = x12 ^ x0
		x12 = (xx << 8) | (xx >> 24)
		x8 += x12
		xx = x4 ^ x8
		x4 = (xx << 7) | (xx >> 25)
		x1 += x5
		xx = x13 ^ x1
		x13 = (xx << 16) | (xx >> 16)
		x9 += x13
		xx = x5 ^ x9
		x5 = (xx << 12) | (xx >> 20)
		x1 += x5
		xx = x13 ^ x1
		x13 = (xx << 8) | (xx >> 24)
		x9 += x13
		xx = x5 ^ x9
		x5 = (xx << 7) | (xx >> 25)
		x2 += x6
		xx = x14 ^ x2
		x14 = (xx << 16) | (xx >> 16)
		x10 += x14
		xx = x6 ^ x10
		x6 = (xx << 12) | (xx >> 20)
		x2 += x6
		xx = x14 ^ x2
		x14 = (xx << 8) | (xx >> 24)
		x10 += x14
		xx = x6 ^ x10
		x6 = (xx << 7) | (xx >> 25)
		x3 += x7
		xx = x15 ^ x3
		x15 = (xx << 16) | (xx >> 16)
		x11 += x15
		xx = x7 ^ x11
		x7 = (xx << 12) | (xx >> 20)
		x3 += x7
		xx = x15 ^ x3
		x15 = (xx << 8) | (xx >> 24)
		x11 += x15
		xx = x7 ^ x11
		x7 = (xx << 7) | (xx >> 25)
		x0 += x5
		xx = x15 ^ x0
		x15 = (xx << 16) | (xx >> 16)
		x10 += x15
		xx = x5 ^ x10
		x5 = (xx << 12) | (xx >> 20)
		x0 += x5
		xx = x15 ^ x0
		x15 = (xx << 8) | (xx >> 24)
		x10 += x15
		xx = x5 ^ x10
		x5 = (xx << 7) | (xx >> 25)
		x1 += x6
		xx = x12 ^ x1
		x12 = (xx << 16) | (xx >> 16)
		x11 += x12
		xx = x6 ^ x11
		x6 = (xx << 12) | (xx >> 20)
		x1 += x6
		xx = x12 ^ x1
		x12 = (xx << 8) | (xx >> 24)
		x11 += x12
		xx = x6 ^ x11
		x6 = (xx << 7) | (xx >> 25)
		x2 += x7
		xx = x13 ^ x2
		x13 = (xx << 16) | (xx >> 16)
		x8 += x13
		xx = x7 ^ x8
		x7 = (xx << 12) | (xx >> 20)
		x2 += x7
		xx = x13 ^ x2
		x13 = (xx << 8) | (xx >> 24)
		x8 += x13
		xx = x7 ^ x8
		x7 = (xx << 7) | (xx >> 25)
		x3 += x4
		xx = x14 ^ x3
		x14 = (xx << 16) | (xx >> 16)
		x9 += x14
		xx = x4 ^ x9
		x4 = (xx << 12) | (xx >> 20)
		x3 += x4
		xx = x14 ^ x3
		x14 = (xx << 8) | (xx >> 24)
		x9 += x14
		xx = x4 ^ x9
		x4 = (xx << 7) | (xx >> 25)
	}
	x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9], x[10], x[11], x[12], x[13], x[14], x[15] = x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15
}

// salsa20WordToByte writes one feed-forward ChaCha12 block to output.
func salsa20WordToByte(output *[64]byte, input *[16]uint32) {
	x := *input
	doRounds(&x)
	for i := range x {
		x[i] += input[i]
		binary.LittleEndian.PutUint32(output[4*i:], x[i])
	}
}
