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

// wotsExpandSeed expands a WOTS+ seed into wotsL chain seeds.
func wotsExpandSeed(outseeds, inseed []byte) {
	chachaPrg(outseeds[0:wotsL*hashSize], inseed[0:wotsSeedBytes])
}

// genChain applies chainlen masked permutation steps to seed.
func genChain(out, seed, masks []byte, chainlen int) {
	copy(out[0:hashSize], seed[0:hashSize])
	for i := range min(chainlen, wotsW) {
		hashHnnMask(out, out, masks[i*hashSize:])
	}
}

// wotsPkgen derives a WOTS+ public key from a seed.
func wotsPkgen(pk, sk, masks []byte) {
	wotsExpandSeed(pk, sk)
	for i := range wotsL {
		genChain(pk[i*hashSize:], pk[i*hashSize:], masks, wotsW-1)
	}
}

// wotsBaseW encodes a message digest as base-w digits followed by a checksum.
func wotsBaseW(msg *[hashSize]byte) [wotsL]int {
	var basew [wotsL]int
	var c, i int
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
	return basew
}

// wotsSign writes a WOTS+ signature for msg using sk.
func wotsSign(sig []byte, msg *[hashSize]byte, sk *[wotsSeedBytes]byte, masks []byte) {
	basew := wotsBaseW(msg)
	wotsExpandSeed(sig, sk[:])
	for i := range wotsL {
		genChain(sig[i*hashSize:], sig[i*hashSize:], masks, basew[i])
	}
}

// wotsVerify recomputes a WOTS+ public key from a signature.
func wotsVerify(pk *[wotsL * hashSize]byte, sig []byte, msg *[hashSize]byte, masks []byte) {
	basew := wotsBaseW(msg)
	for i := range wotsL {
		genChain(pk[i*hashSize:], sig[i*hashSize:], masks[basew[i]*hashSize:], wotsW-1-basew[i])
	}
}
