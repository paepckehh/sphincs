package sphincs

import (
	"github.com/zeebo/blake3"
)

const (
	hashSize = 32
	hashC    = "expand 32-byte to 64-byte state!"
)

// hashVarlen writes a 32-byte BLAKE3 digest of in to out.
func hashVarlen(out, in []byte) {
	tmp := blake3.Sum256(in)
	copy(out, tmp[:])
	clear(tmp[:])
}

// hashH2nn hashes a 64-byte input to a 32-byte output with two permutations.
func hashH2nn(out, in []byte) {
	var x [64]byte
	for i := range 32 {
		x[i] = in[i]
		x[i+32] = hashC[i]
	}
	chachaPermute(&x)
	for i := range 32 {
		x[i] ^= in[i+32]
	}
	chachaPermute(&x)
	copy(out[:hashSize], x[:])
}

// hashH2nnMask applies a mask to a 64-byte input before hashH2nn.
func hashH2nnMask(out, in, mask []byte) {
	var buf [2 * hashSize]byte
	for i := range len(buf) {
		buf[i] = in[i] ^ mask[i]
	}
	hashH2nn(out, buf[:])
}

// hashHnn hashes a 32-byte input to a 32-byte output with one permutation.
func hashHnn(out, in []byte) {
	var x [64]byte
	for i := range 32 {
		x[i] = in[i]
		x[i+32] = hashC[i]
	}
	chachaPermute(&x)
	copy(out[:hashSize], x[:])
}

// hashHnnMask applies a mask to a 32-byte input before hashHnn.
func hashHnnMask(out, in, mask []byte) {
	var buf [hashSize]byte
	for i := range len(buf) {
		buf[i] = in[i] ^ mask[i]
	}
	hashHnn(out, buf[:])
}
