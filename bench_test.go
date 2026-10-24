package sphincs

import "testing"

var (
	benchPK  [PublicKeySize]byte
	benchSK  [PrivateKeySize]byte
	benchSig [SignatureSize]byte
	benchOK  bool
)

func BenchmarkGenerateKey(b *testing.B) {
	seed := testSeed(21)
	for b.Loop() {
		benchPK, benchSK = GenerateKey(seed)
	}
}

func BenchmarkSign(b *testing.B) {
	_, sk := GenerateKey(testSeed(22))
	msg := testMessage(23)
	for b.Loop() {
		benchSig = Sign(sk, msg)
	}
}

func BenchmarkVerify(b *testing.B) {
	pk, sk := GenerateKey(testSeed(24))
	msg := testMessage(25)
	sig := Sign(sk, msg)
	for b.Loop() {
		benchOK = Verify(pk, msg, sig)
	}
}
