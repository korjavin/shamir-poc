package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"strconv"
	"syscall/js"

	"golang.org/x/crypto/pbkdf2"
)

// Global variables to prevent garbage collection of function values
var (
	shamirSplitFunc   js.Func
	shamirCombineFunc js.Func
	deriveKeyFunc     js.Func
	encryptSecretFunc js.Func
	decryptSecretFunc js.Func
)

// InitCryptoFunctions initializes all cryptography functions
func InitCryptoFunctions() {
	shamirSplitFunc = js.FuncOf(shamirSplit)
	shamirCombineFunc = js.FuncOf(shamirCombine)
	deriveKeyFunc = js.FuncOf(deriveKey)
	encryptSecretFunc = js.FuncOf(encryptSecret)
	decryptSecretFunc = js.FuncOf(decryptSecret)

	// Register JavaScript functions
	js.Global().Get("goWasm").Set("shamirSplit", shamirSplitFunc)
	js.Global().Get("goWasm").Set("shamirCombine", shamirCombineFunc)
	js.Global().Get("goWasm").Set("deriveKey", deriveKeyFunc)
	js.Global().Get("goWasm").Set("encryptSecret", encryptSecretFunc)
	js.Global().Get("goWasm").Set("decryptSecret", decryptSecretFunc)
}

// shamirSplit splits a secret into n shares, requiring k shares to reconstruct
func shamirSplit(this js.Value, args []js.Value) interface{} {
	if len(args) < 3 {
		return js.Error{Value: js.ValueOf("Missing arguments: secret, n, k")}
	}

	secretStr := args[0].String()
	n := args[1].Int()
	k := args[2].Int()

	if n < k {
		return js.Error{Value: js.ValueOf("n must be greater than or equal to k")}
	}

	// Convert secret to a big.Int
	secretBytes := []byte(secretStr)
	secretHash := sha256.Sum256(secretBytes)
	secret := new(big.Int).SetBytes(secretHash[:])

	// Generate random coefficients for the polynomial
	coeffs := make([]*big.Int, k)
	coeffs[0] = secret // The constant term is the secret

	prime := new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil) // 2^256
	prime = prime.Sub(prime, big.NewInt(189))                      // 2^256 - 189 (a prime number)

	// Generate random coefficients
	for i := 1; i < k; i++ {
		coeff := new(big.Int)
		max := new(big.Int).Sub(prime, big.NewInt(1))
		coeff, err := rand.Int(rand.Reader, max)
		if err != nil {
			return js.Error{Value: js.ValueOf(err.Error())}
		}
		coeffs[i] = coeff
	}

	// Generate shares
	shares := make([]map[string]interface{}, n)

	for i := 1; i <= n; i++ {
		x := big.NewInt(int64(i))
		y := evaluatePolynomial(coeffs, x, prime)

		shares[i-1] = map[string]interface{}{
			"x": x.String(),
			"y": y.String(),
		}
	}

	return js.ValueOf(shares)
}

// shamirCombine combines k shares to reconstruct the secret
func shamirCombine(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return js.Error{Value: js.ValueOf("Missing argument: shares")}
	}

	shares := args[0]
	if shares.Length() < 2 {
		return js.Error{Value: js.ValueOf("At least 2 shares are required")}
	}

	// Parse shares
	xValues := make([]*big.Int, shares.Length())
	yValues := make([]*big.Int, shares.Length())

	for i := 0; i < shares.Length(); i++ {
		share := shares.Index(i)
		xStr := share.Get("x").String()
		yStr := share.Get("y").String()

		x, ok := new(big.Int).SetString(xStr, 10)
		if !ok {
			return js.Error{Value: js.ValueOf("Invalid x value: " + xStr)}
		}

		y, ok := new(big.Int).SetString(yStr, 10)
		if !ok {
			return js.Error{Value: js.ValueOf("Invalid y value: " + yStr)}
		}

		xValues[i] = x
		yValues[i] = y
	}

	// Reconstruct the secret using Lagrange interpolation
	prime := new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil) // 2^256
	prime = prime.Sub(prime, big.NewInt(189))                      // 2^256 - 189 (a prime number)

	secret := lagrangeInterpolation(xValues, yValues, big.NewInt(0), prime)

	// Convert the secret back to a string
	return secret.String()
}

// deriveKey derives a key from a set of answers and a salt
func deriveKey(this js.Value, args []js.Value) interface{} {
	if len(args) < 3 {
		return js.Error{Value: js.ValueOf("Missing arguments: answers, salt, threshold")}
	}

	answers := args[0]
	saltStr := args[1].String()
	threshold := args[2].Int()

	if answers.Length() < threshold {
		return js.Error{Value: js.ValueOf("Not enough answers provided")}
	}

	// Convert answers to strings
	answerStrs := make([]string, answers.Length())
	for i := 0; i < answers.Length(); i++ {
		answerStrs[i] = answers.Index(i).String()
	}

	// Use Shamir Secret Sharing to split and combine the answers
	// First, create shares from each answer
	shares := make([]map[string]interface{}, len(answerStrs))

	for i, answer := range answerStrs {
		// Hash the answer to create a consistent value
		answerHash := sha256.Sum256([]byte(answer))
		answerInt := new(big.Int).SetBytes(answerHash[:])

		// Create a share with x = i+1 and y = answer hash
		shares[i] = map[string]interface{}{
			"x": strconv.Itoa(i + 1),
			"y": answerInt.String(),
		}
	}

	// Convert shares to JS value
	jsShares := js.ValueOf(shares)

	// Combine the shares to get the secret
	secretVal := shamirCombine(this, []js.Value{jsShares})
	secretStr := secretVal.(string)
	secretInt, _ := new(big.Int).SetString(secretStr, 10)
	secretBytes := secretInt.Bytes()

	// Decode salt
	salt, err := base64.URLEncoding.DecodeString(saltStr)
	if err != nil {
		return js.Error{Value: js.ValueOf("Invalid salt: " + err.Error())}
	}

	// Derive key using PBKDF2
	key := pbkdf2.Key(secretBytes, salt, 10000, 32, sha256.New)

	// Return base64 encoded key
	return base64.StdEncoding.EncodeToString(key)
}

// encryptSecret encrypts a secret using AES-GCM
func encryptSecret(this js.Value, args []js.Value) interface{} {
	if len(args) < 3 {
		return js.Error{Value: js.ValueOf("Missing arguments: secret, key, aad")}
	}

	secretStr := args[0].String()
	keyStr := args[1].String()
	aadStr := args[2].String()

	// Decode key
	key, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		return js.Error{Value: js.ValueOf("Invalid key: " + err.Error())}
	}

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return js.Error{Value: js.ValueOf("Failed to create cipher: " + err.Error())}
	}

	// Create GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return js.Error{Value: js.ValueOf("Failed to create GCM: " + err.Error())}
	}

	// Create nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return js.Error{Value: js.ValueOf("Failed to create nonce: " + err.Error())}
	}

	// Encrypt
	ciphertext := gcm.Seal(nil, nonce, []byte(secretStr), []byte(aadStr))

	// Return result
	return js.ValueOf(map[string]interface{}{
		"ciphertext": base64.StdEncoding.EncodeToString(ciphertext),
		"nonce":      base64.StdEncoding.EncodeToString(nonce),
	})
}

// decryptSecret decrypts a secret using AES-GCM
func decryptSecret(this js.Value, args []js.Value) interface{} {
	if len(args) < 4 {
		return js.Error{Value: js.ValueOf("Missing arguments: ciphertext, key, nonce, aad")}
	}

	ciphertextStr := args[0].String()
	keyStr := args[1].String()
	nonceStr := args[2].String()
	aadStr := args[3].String()

	// Decode values
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextStr)
	if err != nil {
		return js.Error{Value: js.ValueOf("Invalid ciphertext: " + err.Error())}
	}

	key, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		return js.Error{Value: js.ValueOf("Invalid key: " + err.Error())}
	}

	nonce, err := base64.StdEncoding.DecodeString(nonceStr)
	if err != nil {
		return js.Error{Value: js.ValueOf("Invalid nonce: " + err.Error())}
	}

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return js.Error{Value: js.ValueOf("Failed to create cipher: " + err.Error())}
	}

	// Create GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return js.Error{Value: js.ValueOf("Failed to create GCM: " + err.Error())}
	}

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, []byte(aadStr))
	if err != nil {
		return js.Error{Value: js.ValueOf("Failed to decrypt: " + err.Error())}
	}

	// Return result
	return string(plaintext)
}

// evaluatePolynomial evaluates a polynomial at point x
func evaluatePolynomial(coeffs []*big.Int, x *big.Int, prime *big.Int) *big.Int {
	result := new(big.Int).Set(coeffs[0])
	power := new(big.Int).Set(x)

	for i := 1; i < len(coeffs); i++ {
		term := new(big.Int).Mul(coeffs[i], power)
		result = new(big.Int).Add(result, term)
		result = new(big.Int).Mod(result, prime)
		power = new(big.Int).Mul(power, x)
		power = new(big.Int).Mod(power, prime)
	}

	return result
}

// lagrangeInterpolation performs Lagrange interpolation to reconstruct the secret
func lagrangeInterpolation(xs []*big.Int, ys []*big.Int, x *big.Int, prime *big.Int) *big.Int {
	result := big.NewInt(0)

	for i := 0; i < len(xs); i++ {
		num := big.NewInt(1)
		den := big.NewInt(1)

		for j := 0; j < len(xs); j++ {
			if i == j {
				continue
			}

			num = new(big.Int).Mul(num, new(big.Int).Sub(x, xs[j]))
			num = new(big.Int).Mod(num, prime)

			den = new(big.Int).Mul(den, new(big.Int).Sub(xs[i], xs[j]))
			den = new(big.Int).Mod(den, prime)
		}

		denInv := new(big.Int).ModInverse(den, prime)
		if denInv == nil {
			panic("ModInverse does not exist")
		}

		term := new(big.Int).Mul(ys[i], num)
		term = new(big.Int).Mul(term, denInv)
		term = new(big.Int).Mod(term, prime)

		result = new(big.Int).Add(result, term)
		result = new(big.Int).Mod(result, prime)
	}

	return result
}
