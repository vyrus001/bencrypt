package null

import (
	"bytes"
	"testing"

	"github.com/awgh/bencrypt/bc"
)

var (
	nullCrypt bc.KeyPair = new(KeyPair)
	key       string
)

func Test_B64PublicKey_ECC(t *testing.T) {
	pubkey := new(PubKey)
	if err := pubkey.FromB64(key); err != nil {
		t.Error(err.Error())
	}
	b64 := pubkey.ToB64()
	if key != b64 {
		t.Error("base64 public key conversion test failed")
	} else {
		t.Log("base64 public key conversion test passed")
	}
}

func Test_B64PrivateKey_ECC(t *testing.T) {
	err := nullCrypt.FromB64(key)
	if err != nil {
		t.Error(err.Error())
	}
	b64 := nullCrypt.ToB64()
	if key != b64 {
		t.Error("base64 private key conversion test failed")
	} else {
		t.Log("base64 private key conversion test passed")
	}
}

func Test_GenerateKeys_ECC(t *testing.T) {
	// save old key so other tests don't break
	oldkey := nullCrypt.ToB64()

	nullCrypt.GenerateKey()
	t.Log("b64 pubpriv: " + nullCrypt.ToB64())
	pubkey := nullCrypt.GetPubKey()
	b64 := pubkey.ToB64()
	t.Log(b64)

	// restore old key
	nullCrypt.FromB64(oldkey)
}

func Test_EncryptDecrypt_ECC(t *testing.T) {
	cleartext, err := bc.GenerateRandomBytes(151)
	if err != nil {
		t.Error(err.Error())
	}
	pubkey := new(PubKey)
	err = pubkey.FromB64(key)
	if err != nil {
		t.Error(err.Error())
	}
	ciphertext, err := nullCrypt.EncryptMessage(cleartext, pubkey)
	if err != nil {
		t.Error(err.Error())
	}
	tagOK, recovered, err := nullCrypt.DecryptMessage(ciphertext)
	if !tagOK || err != nil {
		t.Error(err.Error())
	}

	if bytes.Equal(cleartext, recovered[:len(cleartext)]) {
		t.Log("encrypt decrypt test passed")
	} else {
		t.Error("encrypt decrypt test failed")
	}
}
