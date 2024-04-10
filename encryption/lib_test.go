package encryption

import (
	"testing"
	"tools"
)

func Test1(t *testing.T) {
	privateKey, publicKey := GenerateKey(1000)

	{
		a1, err := PrivateKeyEncoding(privateKey)
		tools.Test(false, true, "#v", err, nil)
		a2, err := PrivateKeyDecoding(a1)
		tools.Test(false, true, "#v", err, nil)
		tools.Test(false, true, "#v", privateKey, a2)
	}
	{
		a1, err := PublicKeyEncoding(publicKey)
		tools.Test(false, true, "#v", err, nil)
		a2, err := PublicKeyDecoding(a1)
		tools.Test(false, true, "#v", err, nil)
		tools.Test(false, true, "#v", publicKey, a2)
	}

	address := CreateAddress(publicKey)

	StoreKey(privateKey, 10, "1234")

	key, err := GetKey(address, 10, "1234")
	tools.Test(false, true, "v", key, privateKey)
	tools.Test(false, true, "v", err, nil)

	err = ChangePassword(address, 1, 20, "1234", "12345")
	tools.Test(false, false, "v", err, nil)

	err = ChangePassword(address, 10, 20, "1234", "12345")
	tools.Test(false, true, "v", err, nil)

	key, err = GetKey(address, 10, "1234")
	tools.Test(false, false, "v", key, privateKey)
	tools.Test(false, false, "v", err, nil)

	key, err = GetKey(address, 10, "12345")
	tools.Test(false, false, "v", key, privateKey)
	tools.Test(false, false, "v", err, nil)

	key, err = GetKey(address, 20, "1234")
	tools.Test(false, false, "v", key, privateKey)
	tools.Test(false, false, "v", err, nil)

	key, err = GetKey(address, 20, "12345")
	tools.Test(false, true, "v", key, privateKey)
	tools.Test(false, true, "v", err, nil)

	password, err := GuessPassword(address, 20, []string{"1", "2", "3", "4", "5"})
	tools.Test(false, true, "v", password, "12345")
	tools.Test(false, true, "v", err, nil)

	text := []byte("hashem")

	ciphertext, err := Encrypt(publicKey, text)
	tools.Test(false, true, "v", err, nil)

	text1, err := Decrypt(privateKey, ciphertext)
	tools.Test(false, true, "v", text1, text)
	tools.Test(false, true, "v", err, nil)

	signature, err := CreateSignature(privateKey, text)
	tools.Test(false, false, "v", signature, nil)
	tools.Test(false, true, "v", err, nil)

	err = VerifiSignature(publicKey, text, signature)
	tools.Test(false, true, "v", err, nil)
}

func Test2(t *testing.T) {
	a0 := []byte("hashem")
	key := [32]byte{88}

	c := encrypt(key, a0)

	a1, err := decrypt(key, c)
	tools.Test(false, true, "v", a1, a0)
	tools.Test(false, true, "v", err, nil)

	a1, err = decrypt([32]byte{}, c)
	tools.Test(false, true, "v", a1, nil)
	tools.Test(false, false, "v", err, nil)

	a1, err = decrypt(key, a0)
	tools.Test(false, true, "v", a1, nil)
	tools.Test(false, false, "v", err, nil)
}
