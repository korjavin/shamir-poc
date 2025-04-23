# Shamir Schema Demo with Browser-Side Cryptography

A comprehensive, self-contained web application that demonstrates **Shamir Secret Sharing**. The goal is strictly educational: the app shows every request, response, and cryptographic value involved so developers can see exactly **how the Shamir Schema produces a stable output that can later feed a KDF to wrap a DEK (Data Encryption Key)**.

## Key Features

- **Browser-Side Cryptography**: All cryptographic operations are performed in the browser using WebAssembly (Go compiled to WASM)
- **Persistent Storage**: User registrations and encrypted secrets are stored in a data.json file
- **Interactive UI**: Edit secret attributes directly in the UI for educational purposes
- **Detailed Logging**: Every step of the process is logged for transparency and learning

The application supports the following flows:

1. **Register/Login with Passkeys**: Create and use WebAuthn credentials (implemented in `passkey.go`)
2. **New Secret Questions**: WebUI allows user to create an arbitrary number of Secret Questions with their Answers
3. **New Secret**: WebUI allows user to create a new secret with an associated ID and some generated salt
4. **Encrypt/Decrypt**: Use the Answers to Secret Questions, using Shamir schema, so a client need to know only a subset of the Answers    to derive an encryption key and encrypt/decrypt the secret. Answers never leave the browser, all the decryption happens in the browser. Only Secret Questions, Encrypted Secrets, their IDs,AAD, and salts are stored on the server. Secrets are encrypted using AES-GCM with a key derived from the Answers output.
5. **Key Derivation**: Use the PBKDF2-HMAC algorithm applied to Answers on Secret Questions to derive a key for encryption/decryption
6. **Encryption Algorithm**: Use AES-GCM for encryption/decryption of the secret
7. **Load Secrets**: Retrieve previously stored encrypted secrets from the server, and save them there after encryption 

---

## What We Are Demonstrating

| Topic | Why it matters |
|-------|----------------|
| **Shamir Secret Sharing** | A method for splitting a secret into parts, where only a subset of parts is needed to reconstruct the secret. |
| **Salt = domain separation** | The application chooses an arbitrary 32-byte salt (random). Different salts produce different outputs, allowing multiple independent keys from one credential. |
| **Transparent step-by-step UX** | Each stage (generated salt, JS request JSON, authenticator response, shamir schema output, etc.) is printed to the screen so learners can follow the flow. |
| **Interactive experimentation** | Users can edit AAD and other parameters to see how they affect encryption/decryption, providing hands-on learning about authenticated encryption. |

We deliberately focus on the core functionality of **"Answers (Shamir Schema) → deterministic secret → encryption/decryption"** while providing a user-friendly interface for experimentation.

---

## High-Level Flow

1. **Register**: User creates a passkey for the demo site.
2. **Login**: User authenticates with their passkey.
3. **New Secret Set**:
   1. Browser generates:
      * `secretID` – 16 random bytes (base64url-encoded).
      * `salt` – 32 random bytes (base64url-encoded).
      * `secret` – Let user to specify text
      * `aad` – Let user to specify text
      * `secretQuestions` – Let user to specify text for N secret questions (N chosen by user by using ADD/Del buttons)
      * `secretAnswers` – Let user to specify text every Question (never leave browser)
   2. Browser stores these values in memory and displays them in the UI.

4. **Key Derivation**:
   1. Browser uses secretAnswers to derive a key using PBKDF2-HMAC-SHA256.

5. **Encrypt Secret**:
   1. Browser uses AES-256-GCM and the derived key to encrypt the secret.
   2. Browser uses the AAD (Additional Authenticated Data) to prevent tampering.
   3. Browser sends the Secret Questions, encrypted secret, nonce (IV), AAD, salt, and secretID to the server.
   4. Server stores the encrypted data in the data.json file.
6. **Decrypt Secret**:
   1. Browser retrieves the encrypted data from the server.
   2. Browser colects secretAnswers from user presented Secret Questions.
   3. Browser uses secretAnswers to derive a key using PBKDF2-HMAC-SHA256.
   3. Browser decrypts the secret using the derived key, nonce, and AAD.
   4. The decrypted secret is displayed in the UI.

---

## Implementation Details

For all cryptographic operations on the browser side (key derivation, encryption, and decryption), we use [WebAssembly](https://webassembly.org/) compiled from Go code. This allows us to use Go's robust cryptographic libraries directly in the browser.

The server side is implemented in Go and focuses on storing and retrieving data. It doesn't perform any cryptographic operations, ensuring that sensitive operations remain client-side.

### Key Components:

- **WebAssembly Module**: Handles cryptographic operations (wasm/crypto.go)
- **Passkey Authentication**: Manages WebAuthn registration and login (passkey.go)
- **Secret Management**: Handles storage and retrieval of encrypted secrets (secret.go)
- **Persistence Layer**: Saves and loads data to/from data.json (persistence.go)
- **Interactive UI**: Allows users to view and edit secret attributes (static/app.js, static/index.html)

## Running the Demo

```bash
# Requires Go 1.22+
$ git clone https://github.com/korjavin/shamir-poc
$ cd shamir-poc
$ go build
$ ./shamir-poc

```



---

## Glossary

- **secretID**: Opaque 16-byte identifier for one logical "secret". Used as the primary key in storage.
- **salt**: 32-byte random value generated by the browser; unique per secret, guarantees domain separation.
- **secret**: Random text that will be encrypted and decrypted.
- **AAD**: Additional Authenticated Data used in AES-GCM to prevent tampering.
- **nonce**: Initialization Vector (IV) used in AES-GCM encryption.
- **KEK**: Key Encryption Key derived from the Secret Answers.
- **DEK**: Data Encryption Key, the secret being protected.
- **Secret Questions**: Questions that the user provides to derive the KEK.
- **Secret Answers**: Answers to the Secret Questions, used to derive the KEK. Never leaves the browser.

---

## Security Considerations

This demo is for educational purposes only and should not be used in production without additional security measures:

1. **Error Handling**: The demo includes basic error handling but may not cover all edge cases.
2. **Key Management**: In a production environment, consider additional key management strategies.
3. **Backup and Recovery**: Implement proper backup and recovery mechanisms for keys and data.
4. **Rate Limiting**: Add rate limiting to prevent brute force attacks.
5. **Audit Logging**: Implement comprehensive audit logging for security events.

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
