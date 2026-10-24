package sphincs_test

import (
	"fmt"

	"paepcke.de/sphincs"
)

func Example() {
	var seed [sphincs.SeedTokenSize]byte
	for i := range seed {
		seed[i] = byte(i*31 + 7)
	}
	pk, sk := sphincs.GenerateKey(seed)

	var msg [sphincs.MessageSize]byte
	copy(msg[:], "post-quantum")

	sig := sphincs.Sign(sk, msg)
	sig2 := sphincs.Sign(sk, msg)

	fmt.Println("public key :", sphincs.PublicKeySize, "bytes")
	fmt.Println("private key:", sphincs.PrivateKeySize, "bytes")
	fmt.Println("signature  :", sphincs.SignatureSize, "bytes")
	fmt.Printf("sig prefix : %x...\n", sig[:8])
	fmt.Println("deterministic:", sig == sig2)
	fmt.Println("valid      :", sphincs.Verify(pk, msg, sig))
	msg[0] ^= 1
	fmt.Println("tampered   :", sphincs.Verify(pk, msg, sig))
	// Output:
	// public key : 1056 bytes
	// private key: 1088 bytes
	// signature  : 41000 bytes
	// sig prefix : 8c902824a809170e...
	// deterministic: true
	// valid      : true
	// tampered   : false
}
