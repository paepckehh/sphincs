package sphincs

const (
	horstSeedBytes = 32
	horstLogT      = 16
	horstT         = 1 << horstLogT
	horstK         = 32
	horstSkBytes   = 32
	horstSigBytes  = 64*hashSize + (((horstLogT-6)*hashSize)+horstSkBytes)*horstK
)

func horstExpandSeed(outseeds []byte, inseed *[horstSeedBytes]byte) {
	chachaPrg(outseeds[0:horstT*horstSkBytes], inseed[:])
}

func horstSign(sig []byte, pk *[hashSize]byte, seed *[horstSeedBytes]byte, masks, mHash []byte) {
	var sk [horstT * horstSkBytes]byte
	sigpos := 0
	horstExpandSeed(sk[:], seed)
	var tree [(2*horstT - 1) * hashSize]byte
	for i := 0; i < horstT; i++ {
		hashHnn(tree[(horstT-1+i)*hashSize:], sk[i*horstSkBytes:])
	}
	var offsetIn, offsetOut uint64
	for i := uint(0); i < horstLogT; i++ {
		offsetIn = (1 << (horstLogT - i)) - 1
		offsetOut = (1 << (horstLogT - i - 1)) - 1
		for j := uint64(0); j < 1<<(horstLogT-i-1); j++ {
			hashH2nnMask(tree[(offsetOut+j)*hashSize:], tree[(offsetIn+2*j)*hashSize:], masks[2*i*hashSize:])
		}
	}
	copy(sig[0:64*hashSize], tree[63*hashSize:127*hashSize])
	sigpos += 64 * hashSize
	for i := 0; i < horstK; i++ {
		idx := uint(mHash[2*i]) + (uint(mHash[2*i+1]) << 8)
		copy(sig[sigpos:sigpos+horstSkBytes], sk[idx*horstSkBytes:(idx+1)*horstSkBytes])
		sigpos += horstSkBytes
		idx += horstT - 1
		for j := 0; j < horstLogT-6; j++ {
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

func horstVerify(pk, sig, masks, mHash []byte) int {
	var buffer [32 * hashSize]byte
	level10 := sig
	sig = sig[64*hashSize:]
	for i := 0; i < horstK; i++ {
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
		for k := uint(0); k < hashSize; k++ {
			if level10[idx*hashSize+k] != buffer[k] {
				for i := range pk[:hashSize] {
					pk[i] = '0'
				}
				return -1
			}
		}
	}
	for j := 0; j < 32; j++ {
		hashH2nnMask(buffer[j*hashSize:], level10[2*j*hashSize:], masks[2*(horstLogT-6)*hashSize:])
	}
	for j := 0; j < 16; j++ {
		hashH2nnMask(buffer[j*hashSize:], buffer[2*j*hashSize:], masks[2*(horstLogT-5)*hashSize:])
	}
	for j := 0; j < 8; j++ {
		hashH2nnMask(buffer[j*hashSize:], buffer[2*j*hashSize:], masks[2*(horstLogT-4)*hashSize:])
	}
	for j := 0; j < 4; j++ {
		hashH2nnMask(buffer[j*hashSize:], buffer[2*j*hashSize:], masks[2*(horstLogT-3)*hashSize:])
	}
	for j := 0; j < 2; j++ {
		hashH2nnMask(buffer[j*hashSize:], buffer[2*j*hashSize:], masks[2*(horstLogT-2)*hashSize:])
	}
	hashH2nnMask(pk, buffer[:], masks[2*(horstLogT-1)*hashSize:])
	return 0
}
