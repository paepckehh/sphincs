package sphincs

const (
	wotsSeedBytes = 32
	wotsLogW      = 4
	wotsW         = 1 << wotsLogW
	wotsL1        = (256 + wotsLogW - 1) / wotsLogW
	wotsL         = 67
	wotsLogL      = 7
	wotsSigBytes  = wotsL * hashSize
)

func wotsExpandSeed(outseeds, inseed []byte) {
	chachaPrg(outseeds[0:wotsL*hashSize], inseed[0:wotsSeedBytes])
}

func genChain(out, seed, masks []byte, chainlen int) {
	copy(out[0:hashSize], seed[0:hashSize])
	for i := 0; i < chainlen && i < wotsW; i++ {
		mask := masks[i*hashSize:]
		hashHnnMask(out[:], out[:], mask)
	}
}

func wotsPkgen(pk, sk, masks []byte) {
	wotsExpandSeed(pk, sk)
	for i := 0; i < wotsL; i++ {
		genChain(pk[i*hashSize:], pk[i*hashSize:], masks, wotsW-1)
	}
}

func wotsSign(sig []byte, msg *[hashSize]byte, sk *[wotsSeedBytes]byte, masks []byte) {
	var basew [wotsL]int
	var c, i int
	switch wotsW {
	case 16:
		for i = 0; i < wotsL1; i += 2 {
			basew[i] = int(msg[i/2] & 0xf)
			basew[i+1] = int(msg[i/2] >> 4)
			c += wotsW - 1 - basew[i]
			c += wotsW - 1 - basew[i+1]
		}
		for ; i < wotsL; i++ {
			basew[i] = c & 0xf
			c >>= 4
		}
		wotsExpandSeed(sig, sk[:])
		for i = 0; i < wotsL; i++ {
			genChain(sig[i*hashSize:], sig[i*hashSize:], masks, basew[i])
		}
	case 4:
		for i = 0; i < wotsL1; i += 4 {
			basew[i] = int(msg[i/4] & 0x3)
			basew[i+1] = int((msg[i/4] >> 2) & 0x3)
			basew[i+2] = int((msg[i/4] >> 4) & 0x3)
			basew[i+3] = int((msg[i/4] >> 6) & 0x3)
			c += wotsW - 1 - basew[i]
			c += wotsW - 1 - basew[i+1]
			c += wotsW - 1 - basew[i+2]
			c += wotsW - 1 - basew[i+3]
		}
		for ; i < wotsL; i++ {
			basew[i] = c & 0xf
			c >>= 4
		}
		wotsExpandSeed(sig, sk[:])
		for i = 0; i < wotsL; i++ {
			genChain(sig[i*hashSize:], sig[i*hashSize:], masks, basew[i])
		}
	default:
		panic("sphincs: internal error: wotsSign: wotsW  != [4|16]")
	}
}

func wotsVerify(pk *[wotsL * hashSize]byte, sig []byte, msg *[hashSize]byte, masks []byte) {
	var basew [wotsL]int
	var c, i int
	switch wotsW {
	case 16:
		for i = 0; i < wotsL1; i += 2 {
			basew[i] = int(msg[i/2] & 0xf)
			basew[i+1] = int(msg[i/2] >> 4)
			c += wotsW - 1 - basew[i]
			c += wotsW - 1 - basew[i+1]
		}
		for ; i < wotsL; i++ {
			basew[i] = c & 0xf
			c >>= 4
		}
		for i = 0; i < wotsL; i++ {
			genChain(pk[i*hashSize:], sig[i*hashSize:], masks[basew[i]*hashSize:], wotsW-1-basew[i])
		}
	case 4:
		for i = 0; i < wotsL1; i += 4 {
			basew[i] = int(msg[i/4] & 0x3)
			basew[i+1] = int((msg[i/4] >> 2) & 0x3)
			basew[i+2] = int((msg[i/4] >> 4) & 0x3)
			basew[i+3] = int((msg[i/4] >> 6) & 0x3)
			c += wotsW - 1 - basew[i]
			c += wotsW - 1 - basew[i+1]
			c += wotsW - 1 - basew[i+2]
			c += wotsW - 1 - basew[i+3]
		}
		for ; i < wotsL; i++ {
			basew[i] = c & 0xf
			c >>= 4
		}
		for i = 0; i < wotsL; i++ {
			genChain(pk[i*hashSize:], sig[i*hashSize:], masks[basew[i]*hashSize:], wotsW-1-basew[i])
		}
	default:
		panic("sphincs: internal error: wotsVerify: wotsW != [4|16]")
	}
}
