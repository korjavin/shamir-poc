package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"syscall/js"

	"golang.org/x/crypto/pbkdf2"
)

// Global variables to prevent garbage collection of function values
var (
	shamirSplitFunc         js.Func
	shamirCombineFunc       js.Func
	deriveKeyFunc           js.Func
	encryptSecretFunc       js.Func
	decryptSecretFunc       js.Func
	generateRandomBytesFunc js.Func
)

// InitCryptoFunctions initializes all cryptography functions
func InitCryptoFunctions() {
	shamirSplitFunc = js.FuncOf(shamirSplit)
	shamirCombineFunc = js.FuncOf(shamirCombine)
	deriveKeyFunc = js.FuncOf(deriveKey)
	encryptSecretFunc = js.FuncOf(encryptSecret)
	decryptSecretFunc = js.FuncOf(decryptSecret)
	generateRandomBytesFunc = js.FuncOf(generateRandomBytes)

	// Register JavaScript functions
	js.Global().Get("goWasm").Set("shamirSplit", shamirSplitFunc)
	js.Global().Get("goWasm").Set("shamirCombine", shamirCombineFunc)
	js.Global().Get("goWasm").Set("deriveKey", deriveKeyFunc)
	js.Global().Get("goWasm").Set("encryptSecret", encryptSecretFunc)
	js.Global().Get("goWasm").Set("decryptSecret", decryptSecretFunc)
	js.Global().Get("goWasm").Set("generateRandomBytes", generateRandomBytesFunc)
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

// lagrangeInterpolation performs Lagrange interpolation to reconstruct a polynomial at point x
func lagrangeInterpolation(xValues []*big.Int, yValues []*big.Int, x *big.Int, prime *big.Int) *big.Int {
	result := big.NewInt(0)

	for i := 0; i < len(xValues); i++ {
		// Calculate the Lagrange basis polynomial for this point
		numerator := big.NewInt(1)
		denominator := big.NewInt(1)

		for j := 0; j < len(xValues); j++ {
			if i != j {
				// Calculate (x - x_j)
				temp := new(big.Int).Sub(x, xValues[j])
				// Ensure it's positive in the finite field
				temp.Mod(temp, prime)
				// Multiply the numerator by (x - x_j)
				numerator.Mul(numerator, temp)
				numerator.Mod(numerator, prime)

				// Calculate (x_i - x_j)
				temp = new(big.Int).Sub(xValues[i], xValues[j])
				// Ensure it's positive in the finite field
				temp.Mod(temp, prime)
				// Multiply the denominator by (x_i - x_j)
				denominator.Mul(denominator, temp)
				denominator.Mod(denominator, prime)
			}
		}

		// Calculate the modular multiplicative inverse of the denominator
		denominatorInverse := new(big.Int).ModInverse(denominator, prime)
		if denominatorInverse == nil {
			// If the inverse doesn't exist, skip this term
			continue
		}

		// Calculate the Lagrange basis polynomial value
		basis := new(big.Int).Mul(numerator, denominatorInverse)
		basis.Mod(basis, prime)

		// Multiply by the y-value and add to the result
		term := new(big.Int).Mul(basis, yValues[i])
		term.Mod(term, prime)
		result.Add(result, term)
		result.Mod(result, prime)
	}

	return result
}

// deriveKey derives a key from a set of answers and a salt using Shamir's Secret Sharing
func deriveKey(this js.Value, args []js.Value) interface{} {
	// Add debug logging
	js.Global().Get("console").Call("log", "WebAssembly: deriveKey function called")

	// Check arguments
	if len(args) < 3 {
		js.Global().Get("console").Call("error", "WebAssembly: Missing arguments: answers, salt, threshold")
		return js.Error{Value: js.ValueOf("Missing arguments: answers, salt, threshold")}
	}

	// Safely get arguments
	if args[0].Type() != js.TypeObject {
		js.Global().Get("console").Call("error", "WebAssembly: First argument (answers) must be an array")
		return js.Error{Value: js.ValueOf("First argument (answers) must be an array")}
	}
	answers := args[0]

	if args[1].Type() != js.TypeString {
		js.Global().Get("console").Call("error", "WebAssembly: Second argument (salt) must be a string")
		return js.Error{Value: js.ValueOf("Second argument (salt) must be a string")}
	}
	saltStr := args[1].String()

	if args[2].Type() != js.TypeNumber {
		js.Global().Get("console").Call("error", "WebAssembly: Third argument (threshold) must be a number")
		return js.Error{Value: js.ValueOf("Third argument (threshold) must be a number")}
	}
	threshold := args[2].Int()

	// Log argument values
	js.Global().Get("console").Call("log", "WebAssembly: Answers length:", answers.Length())
	js.Global().Get("console").Call("log", "WebAssembly: Salt length:", len(saltStr))
	js.Global().Get("console").Call("log", "WebAssembly: Threshold:", threshold)

	// Check if we have enough answers
	if answers.Length() < threshold {
		js.Global().Get("console").Call("error", "WebAssembly: Not enough answers provided")
		// Create a proper error object that JavaScript can handle
		errorObj := js.Global().Get("Error").New("Not enough answers provided. Need at least " + js.ValueOf(threshold).String() + " answers.")
		return js.Error{Value: errorObj}
	}

	// Create a prime number for finite field arithmetic
	prime := new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil) // 2^256
	prime = prime.Sub(prime, big.NewInt(189))                      // 2^256 - 189 (a prime number)

	// Generate shares from each answer
	xValues := make([]*big.Int, answers.Length())
	yValues := make([]*big.Int, answers.Length())

	js.Global().Get("console").Call("log", "WebAssembly: Processing answers...")

	for i := 0; i < answers.Length(); i++ {
		// Safely get the answer
		answerValue := answers.Index(i)
		if answerValue.Type() != js.TypeString {
			js.Global().Get("console").Call("error", "WebAssembly: Answer at index", i, "is not a string")
			return js.Error{Value: js.ValueOf("Answer at index " + js.ValueOf(i).String() + " is not a string")}
		}
		answer := answerValue.String()

		// Hash the answer to create a consistent y-value
		answerHash := sha256.Sum256([]byte(answer))
		yValue := new(big.Int).SetBytes(answerHash[:])
		yValue.Mod(yValue, prime) // Ensure it's within the field

		// Use position (i+1) as the x-value
		xValue := big.NewInt(int64(i + 1))

		xValues[i] = xValue
		yValues[i] = yValue

		js.Global().Get("console").Call("log", "WebAssembly: Processed answer", i+1)
	}

	// Use only the first 'threshold' number of shares for interpolation
	xSubset := xValues[:threshold]
	ySubset := yValues[:threshold]

	js.Global().Get("console").Call("log", "WebAssembly: Performing Lagrange interpolation...")

	// Use Lagrange interpolation to reconstruct the secret at x=0
	secretInt := lagrangeInterpolation(xSubset, ySubset, big.NewInt(0), prime)

	// Convert to bytes (ensure we have at least 32 bytes)
	secretBytes := secretInt.Bytes()
	if len(secretBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(secretBytes):], secretBytes)
		secretBytes = padded
	} else if len(secretBytes) > 32 {
		// If longer than 32 bytes, take the first 32
		secretBytes = secretBytes[:32]
	}

	js.Global().Get("console").Call("log", "WebAssembly: Decoding salt...")

	// Decode salt
	salt, err := base64.StdEncoding.DecodeString(saltStr)
	if err != nil {
		js.Global().Get("console").Call("error", "WebAssembly: Invalid salt:", err.Error())
		return js.Error{Value: js.ValueOf("Invalid salt: " + err.Error())}
	}

	js.Global().Get("console").Call("log", "WebAssembly: Deriving key using PBKDF2...")

	// Derive key using PBKDF2
	key := pbkdf2.Key(secretBytes, salt, 10000, 32, sha256.New)

	// Return base64 encoded key
	result := base64.StdEncoding.EncodeToString(key)
	js.Global().Get("console").Call("log", "WebAssembly: Key derived successfully")
	return result
}

// encryptSecret encrypts a secret using AES-GCM
func encryptSecret(this js.Value, args []js.Value) interface{} {
	// Add debug logging
	js.Global().Get("console").Call("log", "WebAssembly: encryptSecret function called")

	// Check arguments
	if len(args) < 3 {
		js.Global().Get("console").Call("error", "WebAssembly: Missing arguments: secret, key, aad")
		return js.Error{Value: js.ValueOf("Missing arguments: secret, key, aad")}
	}

	// Safely get arguments
	if args[0].Type() != js.TypeString {
		js.Global().Get("console").Call("error", "WebAssembly: First argument (secret) must be a string")
		return js.Error{Value: js.ValueOf("First argument (secret) must be a string")}
	}
	secretStr := args[0].String()

	if args[1].Type() != js.TypeString {
		js.Global().Get("console").Call("error", "WebAssembly: Second argument (key) must be a string")
		return js.Error{Value: js.ValueOf("Second argument (key) must be a string")}
	}
	keyStr := args[1].String()

	if args[2].Type() != js.TypeString {
		js.Global().Get("console").Call("error", "WebAssembly: Third argument (aad) must be a string")
		return js.Error{Value: js.ValueOf("Third argument (aad) must be a string")}
	}
	aadStr := args[2].String()

	// Log argument values
	js.Global().Get("console").Call("log", "WebAssembly: Secret length:", len(secretStr))
	js.Global().Get("console").Call("log", "WebAssembly: Key length:", len(keyStr))
	js.Global().Get("console").Call("log", "WebAssembly: AAD length:", len(aadStr))

	js.Global().Get("console").Call("log", "WebAssembly: Decoding key...")

	// Decode key
	key, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		js.Global().Get("console").Call("error", "WebAssembly: Invalid key:", err.Error())
		return js.Error{Value: js.ValueOf("Invalid key: " + err.Error())}
	}

	js.Global().Get("console").Call("log", "WebAssembly: Creating cipher...")

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		js.Global().Get("console").Call("error", "WebAssembly: Failed to create cipher:", err.Error())
		return js.Error{Value: js.ValueOf("Failed to create cipher: " + err.Error())}
	}

	js.Global().Get("console").Call("log", "WebAssembly: Creating GCM...")

	// Create GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		js.Global().Get("console").Call("error", "WebAssembly: Failed to create GCM:", err.Error())
		return js.Error{Value: js.ValueOf("Failed to create GCM: " + err.Error())}
	}

	js.Global().Get("console").Call("log", "WebAssembly: Creating nonce...")

	// Create nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		js.Global().Get("console").Call("error", "WebAssembly: Failed to create nonce:", err.Error())
		return js.Error{Value: js.ValueOf("Failed to create nonce: " + err.Error())}
	}

	js.Global().Get("console").Call("log", "WebAssembly: Encrypting...")

	// Encrypt
	ciphertext := gcm.Seal(nil, nonce, []byte(secretStr), []byte(aadStr))

	js.Global().Get("console").Call("log", "WebAssembly: Creating result object...")

	// Create a JavaScript object to return
	result := js.Global().Get("Object").New()
	result.Set("ciphertext", base64.StdEncoding.EncodeToString(ciphertext))
	result.Set("nonce", base64.StdEncoding.EncodeToString(nonce))

	js.Global().Get("console").Call("log", "WebAssembly: Encryption successful")

	// Return result
	return result
}

// decryptSecret decrypts a secret using AES-GCM
func decryptSecret(this js.Value, args []js.Value) interface{} {
	// Add debug logging
	js.Global().Get("console").Call("log", "WebAssembly: decryptSecret function called")

	// Check arguments
	if len(args) < 4 {
		js.Global().Get("console").Call("error", "WebAssembly: Missing arguments: ciphertext, key, nonce, aad")
		return js.Error{Value: js.ValueOf("Missing arguments: ciphertext, key, nonce, aad")}
	}

	// Safely get arguments
	if args[0].Type() != js.TypeString {
		js.Global().Get("console").Call("error", "WebAssembly: First argument (ciphertext) must be a string")
		return js.Error{Value: js.ValueOf("First argument (ciphertext) must be a string")}
	}
	ciphertextStr := args[0].String()

	if args[1].Type() != js.TypeString {
		js.Global().Get("console").Call("error", "WebAssembly: Second argument (key) must be a string")
		return js.Error{Value: js.ValueOf("Second argument (key) must be a string")}
	}
	keyStr := args[1].String()

	if args[2].Type() != js.TypeString {
		js.Global().Get("console").Call("error", "WebAssembly: Third argument (nonce) must be a string")
		return js.Error{Value: js.ValueOf("Third argument (nonce) must be a string")}
	}
	nonceStr := args[2].String()

	if args[3].Type() != js.TypeString {
		js.Global().Get("console").Call("error", "WebAssembly: Fourth argument (aad) must be a string")
		return js.Error{Value: js.ValueOf("Fourth argument (aad) must be a string")}
	}
	aadStr := args[3].String()

	// Log argument values
	js.Global().Get("console").Call("log", "WebAssembly: Ciphertext length:", len(ciphertextStr))
	js.Global().Get("console").Call("log", "WebAssembly: Key length:", len(keyStr))
	js.Global().Get("console").Call("log", "WebAssembly: Nonce length:", len(nonceStr))
	js.Global().Get("console").Call("log", "WebAssembly: AAD length:", len(aadStr))

	js.Global().Get("console").Call("log", "WebAssembly: Decoding values...")

	// Decode values
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextStr)
	if err != nil {
		js.Global().Get("console").Call("error", "WebAssembly: Invalid ciphertext:", err.Error())
		return js.Error{Value: js.ValueOf("Invalid ciphertext: " + err.Error())}
	}

	key, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		js.Global().Get("console").Call("error", "WebAssembly: Invalid key:", err.Error())
		return js.Error{Value: js.ValueOf("Invalid key: " + err.Error())}
	}

	nonce, err := base64.StdEncoding.DecodeString(nonceStr)
	if err != nil {
		js.Global().Get("console").Call("error", "WebAssembly: Invalid nonce:", err.Error())
		return js.Error{Value: js.ValueOf("Invalid nonce: " + err.Error())}
	}

	js.Global().Get("console").Call("log", "WebAssembly: Creating cipher...")

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		js.Global().Get("console").Call("error", "WebAssembly: Failed to create cipher:", err.Error())
		return js.Error{Value: js.ValueOf("Failed to create cipher: " + err.Error())}
	}

	js.Global().Get("console").Call("log", "WebAssembly: Creating GCM...")

	// Create GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		js.Global().Get("console").Call("error", "WebAssembly: Failed to create GCM:", err.Error())
		return js.Error{Value: js.ValueOf("Failed to create GCM: " + err.Error())}
	}

	js.Global().Get("console").Call("log", "WebAssembly: Decrypting...")

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, []byte(aadStr))
	if err != nil {
		js.Global().Get("console").Call("error", "WebAssembly: Failed to decrypt:", err.Error())
		return js.Error{Value: js.ValueOf("Failed to decrypt: " + err.Error())}
	}

	js.Global().Get("console").Call("log", "WebAssembly: Decryption successful")

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

// generateRandomBytes generates random bytes and returns them as a base64 string
func generateRandomBytes(this js.Value, args []js.Value) interface{} {
	// Add debug logging
	js.Global().Get("console").Call("log", "WebAssembly: generateRandomBytes function called")

	// Check arguments
	if len(args) < 1 {
		js.Global().Get("console").Call("error", "WebAssembly: Missing argument: length")
		return js.Error{Value: js.ValueOf("Missing argument: length")}
	}

	// Safely get arguments
	if args[0].Type() != js.TypeNumber {
		js.Global().Get("console").Call("error", "WebAssembly: First argument (length) must be a number")
		return js.Error{Value: js.ValueOf("First argument (length) must be a number")}
	}
	length := args[0].Int()

	// Log argument values
	js.Global().Get("console").Call("log", "WebAssembly: Requested length:", length)

	if length <= 0 {
		js.Global().Get("console").Call("error", "WebAssembly: Length must be positive")
		return js.Error{Value: js.ValueOf("Length must be positive")}
	}

	js.Global().Get("console").Call("log", "WebAssembly: Generating random bytes...")

	// Generate random bytes
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		js.Global().Get("console").Call("error", "WebAssembly: Failed to generate random bytes:", err.Error())
		return js.Error{Value: js.ValueOf("Failed to generate random bytes: " + err.Error())}
	}

	// Return base64 encoded bytes
	result := base64.StdEncoding.EncodeToString(bytes)
	js.Global().Get("console").Call("log", "WebAssembly: Random bytes generated successfully")
	return result
}
