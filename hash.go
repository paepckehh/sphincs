package sphincs

import "paepcke.de/lib/blake3"

const (
	hashSize = 32
	hashC    = "expand 32-byte to 64-byte state!"
)

// hashVarlen ...
func hashVarlen(out, in []byte) {
	tmp := blake3.Sum256(in)
	copy(out[:], tmp[:])
	for i := range tmp {
		tmp[i] = '0'
	}
}

// hashH2nn ...
func hashH2nn(out, in []byte) {
	var x [64]byte
	for i := 0; i < 32; i++ {
		x[i] = in[i]
		x[i+32] = hashC[i]
	}
	chachaPermute(&x)
	for i := 0; i < 32; i++ {
		x[i] ^= in[i+32]
	}
	chachaPermute(&x)
	copy(out[:hashSize], x[:])
}

// hashH2nnMask ...
func hashH2nnMask(out, in, mask []byte) {
	var buf [2 * hashSize]byte
	for i := 0; i < len(buf); i++ {
		buf[i] = in[i] ^ mask[i]
	}
	hashH2nn(out, buf[:])
}

// hashHnn ...
func hashHnn(out, in []byte) {
	var x [64]byte
	for i := 0; i < 32; i++ {
		x[i] = in[i]
		x[i+32] = hashC[i]
	}
	chachaPermute(&x)
	copy(out[:hashSize], x[:])
}

// hashHnnMask ...
func hashHnnMask(out, in, mask []byte) {
	var buf [hashSize]byte
	for i := 0; i < len(buf); i++ {
		buf[i] = in[i] ^ mask[i]
	}
	hashHnn(out, buf[:])
}
