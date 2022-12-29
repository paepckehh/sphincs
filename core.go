package sphincs

import "encoding/binary"

const (
	// nMasks has to be the max of (2*(subtreeHeight+wotsLogL)) and (wotsW-1) and 2*horstLogT
	nMasks               = 2 * horstLogT
	nLevels              = totalTreeHeight / subtreeHeight
	subtreeHeight        = 5
	totalTreeHeight      = 60
	seedBytes            = 32
	skRandSeedBytes      = 32
	messageHashSeedBytes = 32
)

// leafaddr ...
type leafaddr struct {
	level   int
	subtree uint64
	subleaf int
}

// generateSeed ...
func generateSeed(seed, sk []byte, a *leafaddr) {
	var buffer [seedBytes + 8]byte
	copy(buffer[0:seedBytes], sk[0:seedBytes])
	t := uint64(a.level)
	t |= a.subtree << 4
	t |= uint64(a.subleaf) << 59
	binary.LittleEndian.PutUint64(buffer[seedBytes:], t)
	hashVarlen(seed, buffer[:])
}

// lTree ...
func lTree(leaf, wotsPk, masks []byte) {
	l := wotsL
	for i := 0; i < wotsLogL; i++ {
		for j := 0; j < l>>1; j++ {
			hashH2nnMask(wotsPk[j*hashSize:], wotsPk[j*2*hashSize:], masks[i*2*hashSize:])
		}
		switch {
		case l&1 != 0:
			copy(wotsPk[(l>>1)*hashSize:((l>>1)+1)*hashSize], wotsPk[(l-1)*hashSize:])
			l = (l >> 1) + 1
		default:
			l = l >> 1
		}
	}
	copy(leaf[:hashSize], wotsPk[:])
}

// genLeafWots ...
func genLeafWots(leaf, masks, sk []byte, a *leafaddr) {
	var seed [seedBytes]byte
	var pk [wotsL * hashSize]byte
	generateSeed(seed[:], sk, a)
	wotsPkgen(pk[:], seed[:], masks)
	lTree(leaf, pk[:], masks)
}

// treehash ...
func treehash(node []byte, height int, sk []byte, leaf *leafaddr, masks []byte) {
	a := *leaf
	stack := make([]byte, (height+1)*hashSize)
	stacklevels := make([]uint, height+1)
	var stackoffset, maskoffset uint
	lastnode := a.subleaf + (1 << uint(height))
	for ; a.subleaf < lastnode; a.subleaf++ {
		genLeafWots(stack[stackoffset*hashSize:], masks, sk, &a)
		stacklevels[stackoffset] = 0
		stackoffset++
		for stackoffset > 1 && stacklevels[stackoffset-1] == stacklevels[stackoffset-2] {
			maskoffset = 2 * (stacklevels[stackoffset-1] + wotsLogL) * hashSize
			hashH2nnMask(stack[(stackoffset-2)*hashSize:], stack[(stackoffset-2)*hashSize:], masks[maskoffset:])
			stacklevels[stackoffset-2]++
			stackoffset--
		}
	}
	copy(node[0:hashSize], stack[0:hashSize])
}

// validateAuthpath ...
func validateAuthpath(root, leaf *[hashSize]byte, leafidx uint, authpath, masks []byte, height uint) {
	var buffer [2 * hashSize]byte
	switch {
	case leafidx&1 != 0:
		copy(buffer[hashSize:hashSize*2], leaf[0:hashSize])
		copy(buffer[0:hashSize], authpath[0:hashSize])
	default:
		copy(buffer[0:hashSize], leaf[0:hashSize])
		copy(buffer[hashSize:hashSize*2], authpath[0:hashSize])
	}
	authpath = authpath[hashSize:]
	for i := uint(0); i < height-1; i++ {
		leafidx >>= 1
		switch {
		case leafidx&1 != 0:
			hashH2nnMask(buffer[hashSize:], buffer[:], masks[2*(wotsLogL+i)*hashSize:])
			copy(buffer[0:hashSize], authpath[0:hashSize])
		default:
			hashH2nnMask(buffer[:], buffer[:], masks[2*(wotsLogL+i)*hashSize:])
			copy(buffer[hashSize:hashSize*2], authpath[0:hashSize])
		}
		authpath = authpath[hashSize:]
	}
	hashH2nnMask(root[:], buffer[:], masks[2*(wotsLogL+height-1)*hashSize:])
}

// computeAuthpathWots ...
func computeAuthpathWots(root *[hashSize]byte, authpath []byte, a *leafaddr, sk, masks []byte, height uint) {
	ta := *a
	var tree [2 * (1 << subtreeHeight) * hashSize]byte
	var seed [(1 << subtreeHeight) * seedBytes]byte
	var pk [(1 << subtreeHeight) * wotsL * hashSize]byte
	for ta.subleaf = 0; ta.subleaf < 1<<subtreeHeight; ta.subleaf++ {
		generateSeed(seed[ta.subleaf*seedBytes:], sk, &ta)
	}
	for ta.subleaf = 0; ta.subleaf < 1<<subtreeHeight; ta.subleaf++ {
		wotsPkgen(pk[ta.subleaf*wotsL*hashSize:], seed[ta.subleaf*seedBytes:], masks)
	}
	for ta.subleaf = 0; ta.subleaf < 1<<subtreeHeight; ta.subleaf++ {
		lTree(tree[(1<<subtreeHeight)*hashSize+ta.subleaf*hashSize:], pk[ta.subleaf*wotsL*hashSize:], masks)
	}
	level := 0
	for i := 1 << subtreeHeight; i > 0; i >>= 1 {
		for j := 0; j < i; j += 2 {
			hashH2nnMask(tree[(i>>1)*hashSize+(j>>1)*hashSize:],
				tree[i*hashSize+j*hashSize:], masks[2*(wotsLogL+level)*hashSize:])
		}
		level++
	}
	idx := a.subleaf
	for i := uint(0); i < height; i++ {
		dst := authpath[i*hashSize : (i+1)*hashSize]
		src := tree[((1<<subtreeHeight)>>i)*hashSize+((idx>>i)^1)*hashSize:]
		copy(dst[:], src[:])
	}
	copy(root[:], tree[hashSize:])
}

// multiSliceAppend ...
func multiSliceAppend(in ...[]byte) []byte {
	var out []byte
	for _, t := range in {
		out = append(out, t...)
	}
	return out
}
