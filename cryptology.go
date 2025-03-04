package gsharp

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/sm4"
	"golang.org/x/crypto/pbkdf2"
	rand2 "math/rand"
	"sync"
	"time"
)

type ICryptology interface {
	// AddKey
	// @Description: 添加加密Key
	// @param key 加密用的Key
	// @return ICryptology
	AddKey(key string) ICryptology
	// AddIv
	// @Description: 添加加密向量
	// @param iv 向量值
	// @return ICryptology
	AddIv(iv string) ICryptology

	// Random
	// @Description: 随机码
	// @param length 位数
	// @return randByte 随机码字节码
	// @return randStr 随机数字符串
	Random(length int) (randByte []byte, randStr string)
	// RandomString
	//  @Description: 随机码字符串
	//  @param length 位数
	//  @return randStr 随机数字符串
	RandomString(length int) (randStr string)

	// GenRsaKey
	//  @Description: 获取公钥和私钥
	//  @return *RsaSecretString Rsa证书对象
	GenRsaKey() *RsaSecretString
	// RsaEncrypt
	//  @Description: Ras加密
	//  @param publicKey 公钥
	//  @param plainText 需加密字符串
	//  @return cipherText 加密后字符串
	//  @return err 异常
	RsaEncrypt(publicKey, plainText string) (cipherText string, err error)
	// RsaDecrypt
	//  @Description: Rsa解密
	//  @param privateKey 私钥
	//  @param cipherText 密文
	//  @return plainText 解密后的正文
	//  @return err 异常
	RsaDecrypt(privateKey, cipherText string) (plainText string, err error)
	// RsaSign
	//  @Description: Rsa加签
	//  @param privateKey 私钥
	//  @param plainText 需要加签的正文
	//  @return signature 签名
	//  @return err 异常
	RsaSign(privateKey, plainText string) (signature string, err error)
	// RsaVery
	//  @Description: Ras验签
	//  @param publicKey 公钥
	//  @param plainText 需要验签的正文
	//  @param signature 签名
	//  @return ok 签名是否正确
	//  @return err 异常
	RsaVery(publicKey, plainText, signature string) (ok bool, err error)

	// AesCTREncrypt
	//  @Description: CTR加密
	//  @param plainText 需要加密的文正
	//  @return cipherText 密文
	//  @return iv 向量
	AesCTREncrypt(plainText string) (cipherText string, iv string)
	// AesCTRDecrypt
	//  @Description: CTR解密
	//  @param cipherText 密文
	//  @return plainText 解密后的正文
	AesCTRDecrypt(cipherText string) (plainText string)

	// AesCBCEncrypt
	//  @Description: CBC加密
	//  @param plaintext 需要加密的文正
	//  @return ciphertext 密文
	//  @return iv 向量
	//  @return err 异常
	AesCBCEncrypt(plaintext string) (ciphertext string, iv string, err error)
	// AesCBCDecrypt
	//  @Description: CBC解密
	//  @param ciphertext 密文
	//  @return plaintext 解密后的正文
	//  @return err 异常
	AesCBCDecrypt(ciphertext string) (plaintext string, err error)

	// HmacSHA256Encrypt
	//  @Description: HmacSHA256加密
	//  @param plaintext 需要加密的文正
	//  @return ciphertext 密文
	HmacSHA256Encrypt(plaintext string) (ciphertext string)
	// HmacSHA512Encrypt
	//  @Description: HmacSHA256解密
	//  @param plaintext 密文
	//  @return ciphertext 解密后的正文
	HmacSHA512Encrypt(plaintext string) (ciphertext string)

	// SM4Encrypt
	//  @Description: SM4-CBC加密
	//  @param plaintext 需要加密的文正
	//  @return ciphertext 密文
	//  @return iv 向量
	//  @return err 异常
	SM4Encrypt(plaintext string) (ciphertext string, iv string, err error)
	// SM4Decrypt
	//  @Description: SM4-CBC解密
	//  @param ciphertext 密文
	//  @return plaintext 解密后的正文
	//  @return err 异常
	SM4Decrypt(ciphertext string) (plaintext string, err error)

	PBKDF2Encrypt(plaintext string) (ciphertext, salt string)
}

type cryptologyRoot struct {
	key  string
	iv   string
	seed []byte
	mu   sync.Mutex
}

func CreateCryptology() ICryptology {
	return &cryptologyRoot{
		seed: []byte("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"),
	}
}

func (cryptology *cryptologyRoot) AddKey(key string) ICryptology {
	cryptology.key = key
	return cryptology
}

func (cryptology *cryptologyRoot) AddIv(iv string) ICryptology {
	cryptology.iv = iv
	return cryptology
}

// =========================================================================================================================
// Rsa
// =========================================================================================================================

type RsaSecretKey struct {
	PrivateKey []byte
	PublicKey  []byte
}

type RsaSecretString struct {
	PrivateKey string
	PublicKey  string
}

// ToString Rsa秘钥转换字符串
func (secret *RsaSecretKey) ToString() *RsaSecretString {
	return &RsaSecretString{
		PrivateKey: string(secret.PrivateKey),
		PublicKey:  string(secret.PublicKey),
	}
}

// ToByte Rsa秘钥转换字节码
func (secret *RsaSecretString) ToByte() *RsaSecretKey {
	return &RsaSecretKey{
		PrivateKey: []byte(secret.PrivateKey),
		PublicKey:  []byte(secret.PublicKey),
	}
}

// GenRsaKey 获取秘钥
func (cryptology *cryptologyRoot) GenRsaKey() *RsaSecretString {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(errors.New(fmt.Sprintf("生成秘钥失败！%v", err)))
	}

	privateKeyStream := x509.MarshalPKCS1PrivateKey(privateKey)
	publicKeyStream, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		panic(errors.New(fmt.Sprintf("转换公钥失败！%v", err)))
	}

	rsaSecret := new(RsaSecretKey)
	rsaSecret.PrivateKey = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyStream,
	})
	rsaSecret.PublicKey = pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyStream,
	})

	return rsaSecret.ToString()
}

// RsaEncrypt Rsa加密
func (cryptology *cryptologyRoot) RsaEncrypt(publicKey, plainText string) (cipherText string, err error) {
	block, _ := pem.Decode([]byte(publicKey))
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", errors.New(fmt.Sprintf("解析公钥失败！\n %v", err))
	}

	res, err := rsa.EncryptPKCS1v15(rand.Reader, pub.(*rsa.PublicKey), []byte(plainText))
	if err != nil {
		return "", errors.New(fmt.Sprintf("加密失败！\n %v", err))
	}

	return base64.StdEncoding.EncodeToString(res), nil
}

// RsaDecrypt Rsa解密
func (cryptology *cryptologyRoot) RsaDecrypt(privateKey, cipherText string) (plainText string, err error) {
	block, _ := pem.Decode([]byte(privateKey))
	pri, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", errors.New(fmt.Sprintf("解析私钥失败！\n %v", err))
	}

	cip, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", errors.New(fmt.Sprintf("解密失败！\n %v", err))
	}

	res, err := rsa.DecryptPKCS1v15(rand.Reader, pri, cip)
	if err != nil {
		return "", errors.New(fmt.Sprintf("解密失败！\n %v", err))
	}

	return string(res), nil
}

// RsaSign Rsa签名
func (cryptology *cryptologyRoot) RsaSign(privateKey, plainText string) (signature string, err error) {
	// 解析私钥
	block, _ := pem.Decode([]byte(privateKey))
	private, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", nil
	}

	hash := sha256.New()
	hash.Write([]byte(plainText))

	sign, err := rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA256, hash.Sum(nil))
	if err != nil {
		return "", nil
	}
	return hex.EncodeToString(sign), nil
}

// RsaVery Rsa验证签名
func (cryptology *cryptologyRoot) RsaVery(publicKey, plainText, signature string) (ok bool, err error) {
	// 解析公钥
	block, _ := pem.Decode([]byte(publicKey))
	publicAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, err
	}

	sign, err := hex.DecodeString(signature)
	if err != nil {
		return false, err
	}

	hash := sha256.New()
	hash.Write([]byte(plainText))

	verifyErr := rsa.VerifyPKCS1v15(publicAny.(*rsa.PublicKey), crypto.SHA256, hash.Sum(nil), sign)
	return verifyErr == nil, err
}

// =========================================================================================================================
// Aes
// =========================================================================================================================

// AesCTREncrypt AesCTR加密
func (cryptology *cryptologyRoot) AesCTREncrypt(plainText string) (cipherText string, iv string) {
	block, err := aes.NewCipher([]byte(cryptology.key))
	if err != nil {
		panic(err)
	}
	ivb, _ := cryptology.Random(16)
	res := make([]byte, len(plainText))
	cipher.NewCTR(block, ivb).XORKeyStream(res, []byte(plainText))

	return base64.StdEncoding.EncodeToString(res), base64.StdEncoding.EncodeToString(ivb)
}

// AesCTRDecrypt AesCTR解密
func (cryptology *cryptologyRoot) AesCTRDecrypt(cipherText string) (plainText string) {
	block, err := aes.NewCipher([]byte(cryptology.key))
	if err != nil {
		panic(err)
	}
	iv, err := base64.StdEncoding.DecodeString(cryptology.iv)
	if err != nil {
		panic(err)
	}
	cipherByte, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		panic(err)
	}
	res := make([]byte, len(cipherText))
	cipher.NewCTR(block, iv).XORKeyStream(res, cipherByte)

	return string(bytes.Trim(res, "\x00"))
}

// AesCBCEncrypt AesCBC加密
func (cryptology *cryptologyRoot) AesCBCEncrypt(plaintext string) (ciphertext string, iv string, err error) {
	block, err := aes.NewCipher([]byte(cryptology.key))
	if err != nil {
		return "", "", err
	}
	// 初始化随机向量
	ivb, _ := cryptology.Random(16)
	paddedPlaintext := pkcs7Padding([]byte(plaintext), block.BlockSize())
	res := make([]byte, len(paddedPlaintext))
	cipher.NewCBCEncrypter(block, ivb).CryptBlocks(res, paddedPlaintext)

	return base64.StdEncoding.EncodeToString(res), base64.StdEncoding.EncodeToString(ivb), nil
}

// AesCBCDecrypt AesCBC解密
func (cryptology *cryptologyRoot) AesCBCDecrypt(ciphertext string) (plaintext string, err error) {
	block, err := aes.NewCipher([]byte(cryptology.key))
	if err != nil {
		return "", err
	}
	cipherByte, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	ivb, err := base64.StdEncoding.DecodeString(cryptology.iv)
	if err != nil {
		return "", err
	}

	decryptedData := make([]byte, len(cipherByte))
	cipher.NewCBCDecrypter(block, ivb).CryptBlocks(decryptedData, cipherByte)
	result := pkcs7UnPadding(decryptedData)
	return string(result), nil
}

// SM4Encrypt AesSM4加密
func (cryptology *cryptologyRoot) SM4Encrypt(plaintext string) (ciphertext string, iv string, err error) {
	block, err := sm4.NewCipher([]byte(cryptology.key))
	if err != nil {
		return "", "", err
	}
	ivb, _ := cryptology.Random(16)
	val := pkcs7Padding([]byte(plaintext), block.BlockSize())

	res := make([]byte, len(val))
	cipher.NewCBCEncrypter(block, ivb).CryptBlocks(res, val)

	return hex.EncodeToString(res), base64.StdEncoding.EncodeToString(ivb), nil
}

// SM4Decrypt AesSM4解密
func (cryptology *cryptologyRoot) SM4Decrypt(ciphertext string) (plaintext string, err error) {
	block, err := sm4.NewCipher([]byte(cryptology.key))
	if err != nil {
		panic(err)
	}

	iv, err := base64.StdEncoding.DecodeString(cryptology.iv)
	if err != nil {
		panic(err)
	}

	cipherByte, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	decryptedData := make([]byte, len(cipherByte))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(decryptedData, cipherByte)
	res := pkcs7UnPadding(decryptedData)

	return string(res), nil
}

// pkcs7Padding 使用PKCS7填充方式对数据进行填充
func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// pkcs7UnPadding 对使用PKCS7填充方式的数据进行去填充
func pkcs7UnPadding(data []byte) []byte {
	length := len(data)
	padding := int(data[length-1])
	return data[:(length - padding)]
}

// =========================================================================================================================
// HmacSHA512
// =========================================================================================================================

// HmacSHA256Encrypt HmacSHA256编码
func (cryptology *cryptologyRoot) HmacSHA256Encrypt(plaintext string) (ciphertext string) {
	m := hmac.New(sha256.New, []byte(cryptology.key))
	m.Write([]byte(plaintext))
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// HmacSHA512Encrypt HmacSHA512编码
func (cryptology *cryptologyRoot) HmacSHA512Encrypt(plaintext string) (ciphertext string) {
	m := hmac.New(sha512.New, []byte(cryptology.key))
	m.Write([]byte(plaintext))
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// =========================================================================================================================
// PBKDF2
// =========================================================================================================================

// PBKDF2Encrypt  PBKDF2编码
func (cryptology *cryptologyRoot) PBKDF2Encrypt(plaintext string) (ciphertext, salt string) {
	var iv []byte
	if len(cryptology.iv) <= 0 {
		res, _ := cryptology.Random(16)
		iv = res
	} else {
		iv = []byte(cryptology.iv)
	}
	cipherByte := pbkdf2.Key([]byte(plaintext), iv, 10000, sha512.Size, sha512.New)
	return hex.EncodeToString(cipherByte), string(iv)
}

// =========================================================================================================================
// 随机数
// =========================================================================================================================

// Random 获取传入位数的随机码
func (cryptology *cryptologyRoot) Random(length int) (seedByte []byte, seedText string) {
	cryptology.mu.Lock()
	defer cryptology.mu.Unlock()
	rand2.NewSource(time.Now().UnixNano())
	var res []byte
	for i := 0; i < length; i++ {
		res = append(res, cryptology.seed[rand2.Intn(len(cryptology.seed))])
	}
	return res, string(res)
}

// RandomString 获取传入位数的随机码字符串
func (cryptology *cryptologyRoot) RandomString(length int) (seedText string) {
	cryptology.mu.Lock()
	defer cryptology.mu.Unlock()
	rand2.NewSource(time.Now().UnixNano())
	var res []byte
	for i := 0; i < length; i++ {
		res = append(res, cryptology.seed[rand2.Intn(len(cryptology.seed))])
	}
	return string(res)
}
