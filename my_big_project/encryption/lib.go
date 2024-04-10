package encryption

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"determinants"
	"encoding/pem"
	"errors"
	"io"
	db "my_database"
	"tools"

	"github.com/samber/lo"
)

const (
	packageName = "encryption"
	dbName      = "keys"
)

var keys db.DB

type (
	Sha256    [32]byte
	Signature []byte
	Password  string
)

func GenerateKey(bits int) (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	tools.PanicIfErr(err)
	publicKey := &privateKey.PublicKey
	return privateKey, publicKey
}

func CreateAddress(publicKey *rsa.PublicKey) Sha256 {
	return sha256.Sum256(x509.MarshalPKCS1PublicKey(publicKey))
}

func Encrypt(publicKey *rsa.PublicKey, text []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, text, nil)
}

func Decrypt(privateKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, nil)
}

func CreateSignature(privateKey *rsa.PrivateKey, text []byte) (Signature, error) {
	hash := sha256.Sum256(text)
	return rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hash[:], nil)
}

func VerifiSignature(publicKey *rsa.PublicKey, text []byte, signature Signature) error {
	hash := sha256.Sum256(text)
	return rsa.VerifyPSS(publicKey, crypto.SHA256, hash[:], signature, nil)
}

func encrypt(key [32]byte, text []byte) []byte {
	c, err := aes.NewCipher(key[:])
	tools.PanicIfErr(err)

	gcm, err := cipher.NewGCM(c)
	tools.PanicIfErr(err)

	nonce := make([]byte, gcm.NonceSize())

	_, err = io.ReadFull(rand.Reader, nonce)
	tools.PanicIfErr(err)

	ciphertext := gcm.Seal(nonce, nonce, text, nil)

	return ciphertext
}

func decrypt(key [32]byte, ciphertext []byte) ([]byte, error) {
	c, err := aes.NewCipher(key[:])
	tools.PanicIfErr(err)

	gcm, err := cipher.NewGCM(c)
	tools.PanicIfErr(err)

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		panic("ciphertext size is less than nonceSize")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	text, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return text, nil
}

func VDF(rounds int, seed Sha256) Sha256 {
	for i := 0; i < rounds; i++ {
		seed = sha256.Sum256(seed[:])
	}
	return seed
}

func VDFVerifi(rounds int, seed, target Sha256) bool {
	return VDF(rounds, seed) == target
}

////////////////////////////////////////////user side

func GetKeyFromPassword(rounds int, password Password) [32]byte {
	return VDF(rounds, sha256.Sum256([]byte(password)))
}

func StoreKey(privateKey *rsa.PrivateKey, rounds int, password Password) {
	db.Open(&keys, determinants.DBPath(dbName))
	defer keys.Close()

	key2 := x509.MarshalPKCS1PrivateKey(privateKey)
	key3 := encrypt(GetKeyFromPassword(rounds, password), key2)
	address := CreateAddress(&privateKey.PublicKey)
	db.Update(keys, address[:], key3)
}

func GetKey(address Sha256, rounds int, password Password) (*rsa.PrivateKey, error) {
	db.Open(&keys, determinants.DBPath(dbName))
	defer keys.Close()

	key1, err := db.Get(keys, address[:])
	if err != nil {
		return nil, err
	}

	key3, err := decrypt(GetKeyFromPassword(rounds, password), key1)
	if err != nil {
		return nil, err
	}

	key4, err := x509.ParsePKCS1PrivateKey(key3)
	tools.PanicIfErr(err)

	return key4, nil
}

func ChangePassword(address Sha256, rounds, newRounds int, password, newPassword Password) error {
	key, err := GetKey(address, rounds, password)
	if err != nil {
		return err
	}

	StoreKey(key, newRounds, newPassword)
	return nil
}

func GuessPassword(address Sha256, rounds int, passwordProbabilities []string) (Password, error) {
	db.Open(&keys, determinants.DBPath(dbName))
	defer keys.Close()

	c, err := db.Get(keys, address[:])
	if err != nil {
		return "", err
	}

	passwordProbabilities = lo.Compact(passwordProbabilities)

	password := make([]rune, len(passwordProbabilities))
	index := 0
	var correctPassword Password

	var findCorrectPassword func(passwordProbabilities []string, password []rune)
	findCorrectPassword = func(passwordProbabilities []string, password []rune) {
		for _, v := range passwordProbabilities[index] {
			if correctPassword != "" {
				return
			}
			password[index] = v

			if index == len(password)-1 {
				if _, err := decrypt(GetKeyFromPassword(rounds, Password(password)), c); err == nil {
					correctPassword = Password(password)
				}
				continue
			}

			index++
			findCorrectPassword(passwordProbabilities, password)
		}
		index--
	}

	findCorrectPassword(passwordProbabilities, password)

	if correctPassword == "" {
		return "", tools.Errorf(packageName, 3, "the password probabilities is uncorrect or not enough or the encryption id is uncorrect or the encryption hash is uncorrect")
	}

	return correctPassword, nil
}

// //////////////////////////////////////////////////////////////////////////

func HashPair(h0, h1 Sha256) Sha256 {
	return sha256.Sum256(append(h0[:], h1[:]...))
}

// //////////////////////////////////////////////////////////////////////////

func PrivateKeyEncoding(privateKey *rsa.PrivateKey) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("private key cannot be nil")
	}

	pemBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	return pem.EncodeToMemory(pemBlock), nil
}

func PrivateKeyDecoding(pemData []byte) (*rsa.PrivateKey, error) {
	block, rest := pem.Decode(pemData)
	if rest != nil {
		// return nil, errors.New("extra data found in PEM block")
	}
	if block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("invalid PEM block type")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("error parsing private key: " + err.Error())
	}
	return privateKey, nil
}

func PublicKeyEncoding(publicKey *rsa.PublicKey) ([]byte, error) {
	if publicKey == nil {
		return nil, errors.New("public key cannot be nil")
	}

	pemBlock := &pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(publicKey)}
	return pem.EncodeToMemory(pemBlock), nil
}

func PublicKeyDecoding(pemData []byte) (*rsa.PublicKey, error) {
	block, rest := pem.Decode(pemData)
	if rest != nil {
		// return nil, errors.New("extra data found in PEM block")
	}
	if block.Type != "RSA PUBLIC KEY" {
		return nil, errors.New("invalid PEM block type")
	}

	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("error parsing public key: " + err.Error())
	}
	return publicKey, nil
}
