// Command demo runs a deterministic sphincs round-trip.
package main

import (
	"fmt"
	"time"

	"paepcke.de/sphincs"
)

func main() {
	var seed [sphincs.SeedTokenSize]byte
	for i := range seed {
		seed[i] = byte(i*31 + 7)
	}

	start := time.Now()
	pk, sk := sphincs.GenerateKey(seed)
	keygen := time.Since(start)

	var msg [sphincs.MessageSize]byte
	copy(msg[:], "post-quantum")

	start = time.Now()
	sig := sphincs.Sign(sk, msg)
	sign := time.Since(start)

	start = time.Now()
	ok := sphincs.Verify(pk, msg, sig)
	verify := time.Since(start)

	tampered := msg
	tampered[0] ^= 1

	fmt.Println("sphincs demo")
	fmt.Printf("public key     %d bytes\n", sphincs.PublicKeySize)
	fmt.Printf("private key    %d bytes\n", sphincs.PrivateKeySize)
	fmt.Printf("signature      %d bytes\n", sphincs.SignatureSize)
	fmt.Printf("signature hash %x...\n", sig[:8])
	fmt.Printf("deterministic  %v\n", sig == sphincs.Sign(sk, msg))
	fmt.Printf("verify         %v\n", ok)
	fmt.Printf("tampered       %v\n", sphincs.Verify(pk, tampered, sig))
	fmt.Printf("keygen         %s\n", keygen.Round(time.Microsecond))
	fmt.Printf("sign           %s\n", sign.Round(time.Microsecond))
	fmt.Printf("verify         %s\n", verify.Round(time.Microsecond))
}
