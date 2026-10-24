package sphincs

import "crypto/subtle"

const (
	horstSeedBytes = 32
	horstLogT      = 16
	horstT         = 1 << horstLogT
	horstK         = 32
	horstSkBytes   = 32
	horstSigBytes  = 64*hashSize + (((horstLogT-6)*hashSize)+horstSkBytes)*horstK
)

// horstExpandSeed expands a HORST seed into horstT secret keys.
func horstExpandSeed(outseeds []byte, inseed *[horstSeedBytes]byte) {
	chachaPrg(outseeds[0:horstT*horstSkBytes], inseed[:])
}

// horstSign writes a HORST few-time signature and its public key.
func horstSign(sig []byte, pk *[hashSize]byte, seed *[horstSeedBytes]byte, masks, mHash []byte) {
	var sk [horstT * horstSkBytes]byte
	sigpos := 0
	horstExpandSeed(sk[:], seed)
	var tree [(2*horstT - 1) * hashSize]byte
	for i := range horstT {
		hashHnn(tree[(horstT-1+i)*hashSize:], sk[i*horstSkBytes:])
	}
	var offsetIn, offsetOut uint64
	for i := range uint(horstLogT) {
		offsetIn = (1 << (horstLogT - i)) - 1
		offsetOut = (1 << (horstLogT - i - 1)) - 1
		for j := uint64(0); j < 1<<(horstLogT-i-1); j++ {
			hashH2nnMask(tree[(offsetOut+j)*hashSize:], tree[(offsetIn+2*j)*hashSize:], masks[2*i*hashSize:])
		}
	}
	copy(sig[0:64*hashSize], tree[63*hashSize:127*hashSize])
	sigpos += 64 * hashSize
	for i := range horstK {
		idx := uint(mHash[2*i]) + (uint(mHash[2*i+1]) << 8)
		copy(sig[sigpos:sigpos+horstSkBytes], sk[idx*horstSkBytes:(idx+1)*horstSkBytes])
		sigpos += horstSkBytes
		idx += horstT - 1
		for range horstLogT - 6 {
			switch {
			case idx&1 != 0:
				idx = idx + 1
			default:
				idx = idx - 1
			}
			copy(sig[sigpos:sigpos+hashSize], tree[idx*hashSize:(idx+1)*hashSize])
			sigpos += hashSize
			idx = (idx - 1) / 2
		}
	}
	copy(pk[0:hashSize], tree[0:hashSize])
}

// horstVerify recomputes the HORST public key from sig and mHash.
// On failure it clears pk and returns early.
func horstVerify(pk, sig, masks, mHash []byte) {
	var buffer [32 * hashSize]byte
	level10 := sig
	sig = sig[64*hashSize:]
	for i := range horstK {
		idx := uint(mHash[2*i]) + (uint(mHash[2*i+1]) << 8)
		switch {
		case idx&1 == 0:
			hashHnn(buffer[:], sig)
			copy(buffer[hashSize:hashSize*2], sig[horstSkBytes:horstSkBytes+hashSize])
		default:
			hashHnn(buffer[hashSize:], sig)
			copy(buffer[0:hashSize], sig[horstSkBytes:horstSkBytes+hashSize])
		}
		sig = sig[horstSkBytes+hashSize:]
		for j := 1; j < horstLogT-6; j++ {
			idx = idx >> 1
			switch {
			case idx&1 == 0:
				hashH2nnMask(buffer[:], buffer[:], masks[2*(j-1)*hashSize:])
				copy(buffer[hashSize:hashSize*2], sig[0:hashSize])
			default:
				hashH2nnMask(buffer[hashSize:], buffer[:], masks[2*(j-1)*hashSize:])
				copy(buffer[0:hashSize], sig[0:hashSize])
			}
			sig = sig[hashSize:]
		}
		idx = idx >> 1
		hashH2nnMask(buffer[:], buffer[:], masks[2*(horstLogT-7)*hashSize:])
		if subtle.ConstantTimeCompare(buffer[:hashSize], level10[idx*hashSize:(idx+1)*hashSize]) != 1 {
			clear(pk[:hashSize])
			return
		}
	}
	for j := range 32 {
		hashH2nnMask(buffer[j*hashSize:], level10[2*j*hashSize:], masks[2*(horstLogT-6)*hashSize:])
	}
	for j := range 16 {
		hashH2nnMask(buffer[j*hashSize:], buffer[2*j*hashSize:], masks[2*(horstLogT-5)*hashSize:])
	}
	for j := range 8 {
		hashH2nnMask(buffer[j*hashSize:], buffer[2*j*hashSize:], masks[2*(horstLogT-4)*hashSize:])
	}
	for j := range 4 {
		hashH2nnMask(buffer[j*hashSize:], buffer[2*j*hashSize:], masks[2*(horstLogT-3)*hashSize:])
	}
	for j := range 2 {
		hashH2nnMask(buffer[j*hashSize:], buffer[2*j*hashSize:], masks[2*(horstLogT-2)*hashSize:])
	}
	hashH2nnMask(pk, buffer[:], masks[2*(horstLogT-1)*hashSize:])
}
