package nodeagent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// newECDSAKey generates the node's private key pair.
//
// It returns the PRIVATE key as PKCS#8 PEM (never transmitted, written to the
// state directory at mode 0600) and the PUBLIC key as PKIX PEM (transmitted to
// the controller to be signed).
//
// P-256 is used to match internal/pki. The choice is deliberate: the agent must
// not be able to generate a key the controller's authority would refuse to sign,
// and keeping one curve across the mesh means a key-type mismatch cannot arise
// between what a node generates and what the CA expects.
func newECDSAKey() (privatePEM, publicPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("nodeagent: generate node key: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("nodeagent: encode node private key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, nil, fmt.Errorf("nodeagent: encode node public key: %w", err)
	}
	privatePEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	publicPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	return privatePEM, publicPEM, nil
}
