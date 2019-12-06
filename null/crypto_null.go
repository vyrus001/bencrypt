package null

import (
	"github.com/awgh/bencrypt"
	"github.com/awgh/bencrypt/bc"
)

// NAME - human-readable name of this Crypto implementation
var NAME = "NULL"

// PubKey : Implements bc.PubKey interface
type PubKey struct {
	Pubkey []byte //len=32
}

func init() {
	bencrypt.KeypairTypes[NAME] = func() bc.KeyPair { return new(KeyPair) }
}

// ToB64 : Returns Public Key as a Base64 encoded string
func (e *PubKey) ToB64() string {
	return ""
}

// FromB64 : Does nothing
func (e *PubKey) FromB64(s string) error {
	return nil
}

// ToBytes : Returns Public Key as bytes
func (e *PubKey) ToBytes() []byte {
	return e.Pubkey
}

// FromBytes : Sets Public Key from bytes
func (e *PubKey) FromBytes(b []byte) error {
	return nil
}

// Clone : Returns a new PubKey of the same type as this one
func (e *PubKey) Clone() bc.PubKey {
	return new(PubKey)
}

// Nil : Returns the interface-to-nil-pointer type for this PubKey
func (e *PubKey) Nil() interface{} {
	return (*PubKey)(nil)
}

// KeyPair for ECC : Bencrypt Implementation of a Curve25519,AES-CBC-256,HMAC-SHA-256 system
type KeyPair struct {
	pubkey *PubKey
}

// GetName : Returns the common language name for this cryptosystem
func (e *KeyPair) GetName() string {
	return NAME
}

// GetPubKey : Returns the Public portion of this KeyPair
func (e *KeyPair) GetPubKey() bc.PubKey {
	return e.pubkey
}

// Precompute : This does nothing in NULL
func (e *KeyPair) Precompute() {
}

// GenerateKey : Generates a new keypair inside this KeyPair object
func (e *KeyPair) GenerateKey() {
	e.pubkey = new(PubKey)
	e.Precompute()
}

// ToB64 : Returns the private portion of this keypair as a Base64-encoded string
func (e *KeyPair) ToB64() string {
	return ""
}

// FromB64 : Does nothing
func (e *KeyPair) FromB64(s string) error {
	return nil
}

// EncryptMessage : Encrypts a message
func (e *KeyPair) EncryptMessage(clear []byte, pubkey bc.PubKey) ([]byte, error) {
	return clear, nil
}

// DecryptMessage : Decrypts a message
func (e *KeyPair) DecryptMessage(data []byte) (bool, []byte, error) {
	return true, data, nil
}

// ValidatePubKey : Returns true if and only if the argument is a valid PubKey to this KeyPair
func (e *KeyPair) ValidatePubKey(s string) bool {
	return true
}

// Clone : Returns a new node of the same type as this one
func (e *KeyPair) Clone() bc.KeyPair {
	return new(KeyPair)
}
