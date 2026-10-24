package sphincs

import "testing"

func testSeed(tag byte) [SeedTokenSize]byte {
	var seed [SeedTokenSize]byte
	for i := range seed {
		seed[i] = byte(i) ^ tag
	}
	return seed
}

func testMessage(tag byte) [MessageSize]byte {
	var msg [MessageSize]byte
	for i := range msg {
		msg[i] = byte(i*7) ^ tag
	}
	return msg
}

func TestSizes(t *testing.T) {
	if PublicKeySize != 1056 {
		t.Fatalf("PublicKeySize = %d, want 1056", PublicKeySize)
	}
	if PrivateKeySize != 1088 || SeedTokenSize != PrivateKeySize {
		t.Fatalf("PrivateKeySize = %d, SeedTokenSize = %d, want 1088", PrivateKeySize, SeedTokenSize)
	}
	if SignatureSize != 41000 {
		t.Fatalf("SignatureSize = %d, want 41000", SignatureSize)
	}
	if HashSize != 64 || MessageSize != 64 {
		t.Fatalf("HashSize = %d, MessageSize = %d, want 64", HashSize, MessageSize)
	}
}

func TestKeyDerivation(t *testing.T) {
	pk1, sk1 := GenerateKey(testSeed(1))
	pk2, sk2 := GenerateKey(testSeed(1))
	pk3, _ := GenerateKey(testSeed(2))

	if pk1 != pk2 || sk1 != sk2 {
		t.Fatal("key generation is not deterministic")
	}
	if pk1 == pk3 {
		t.Fatal("different seed tokens produced the same public key")
	}
	if pk1 == ([PublicKeySize]byte{}) || sk1 == ([PrivateKeySize]byte{}) {
		t.Fatal("key generation returned an all-zero key")
	}
}

func TestSignVerify(t *testing.T) {
	seed := testSeed(7)
	pk, sk := GenerateKey(seed)
	msg := testMessage(3)
	sig := Sign(sk, msg)

	if !Verify(pk, msg, sig) {
		t.Fatal("valid signature rejected")
	}

	t.Run("tampered message", func(t *testing.T) {
		bad := msg
		bad[0] ^= 1
		if Verify(pk, bad, sig) {
			t.Fatal("signature accepted for tampered message")
		}
	})

	t.Run("tampered signature", func(t *testing.T) {
		for _, off := range []int{0, messageHashSeedBytes, messageHashSeedBytes + leafIndexBytes, SignatureSize - 1} {
			bad := sig
			bad[off] ^= 1
			if Verify(pk, msg, bad) {
				t.Fatalf("tampered signature accepted at offset %d", off)
			}
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		otherPK, _ := GenerateKey(testSeed(8))
		if Verify(otherPK, msg, sig) {
			t.Fatal("signature accepted under a different public key")
		}
	})
}

func TestSignDeterministic(t *testing.T) {
	_, sk := GenerateKey(testSeed(11))
	msg := testMessage(5)
	before := sk

	sig1 := Sign(sk, msg)
	sig2 := Sign(sk, msg)

	if sig1 != sig2 {
		t.Fatal("signing is not deterministic")
	}
	if sk != before {
		t.Fatal("Sign modified the caller's private key")
	}
	if sig1 == Sign(sk, testMessage(6)) {
		t.Fatal("different messages produced identical signatures")
	}
}

func TestWotsBaseWChecksum(t *testing.T) {
	var zero [hashSize]byte
	basew := wotsBaseW(&zero)
	for i := 0; i < wotsL1; i++ {
		if basew[i] != 0 {
			t.Fatalf("zero digest digit %d = %d, want 0", i, basew[i])
		}
	}
	if want := [3]int{0, 12, 3}; basew[64] != want[0] || basew[65] != want[1] || basew[66] != want[2] {
		t.Fatalf("zero digest checksum = %v, want %v", basew[64:], want)
	}

	var max [hashSize]byte
	for i := range max {
		max[i] = 0xff
	}
	basew = wotsBaseW(&max)
	for i, d := range basew {
		want := 0xf
		if i >= wotsL1 {
			want = 0
		}
		if d != want {
			t.Fatalf("max digest digit %d = %d, want %d", i, d, want)
		}
	}
}
