package main

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"sync"

	"github.com/go-webauthn/webauthn/webauthn"
)

// PersistentData represents the application data to be persisted
type PersistentData struct {
	Users map[string]PersistentUser `json:"users"`
}

// PersistentUser represents a user with credentials
type PersistentUser struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	DisplayName string                 `json:"displayName"`
	Credentials []PersistentCredential `json:"credentials"`
}

// PersistentCredential is a version of webauthn.Credential that can be serialized to JSON
type PersistentCredential struct {
	ID              string                    `json:"id"`
	PublicKey       string                    `json:"publicKey"`
	AttestationType string                    `json:"attestationType"`
	Flags           PersistentCredentialFlags `json:"flags"`
	Authenticator   PersistentAuthenticator   `json:"authenticator"`
}

// PersistentCredentialFlags is a version of webauthn.CredentialFlags that can be serialized to JSON
type PersistentCredentialFlags struct {
	UserPresent    bool `json:"userPresent"`
	UserVerified   bool `json:"userVerified"`
	BackupEligible bool `json:"backupEligible"`
	BackupState    bool `json:"backupState"`
}

// PersistentAuthenticator is a version of webauthn.Authenticator that can be serialized to JSON
type PersistentAuthenticator struct {
	AAGUID       string `json:"aaguid"`
	SignCount    uint32 `json:"signCount"`
	CloneWarning bool   `json:"cloneWarning"`
}

// PersistentSecret represents an encrypted secret with its ID, salt, and encrypted data
type PersistentSecret struct {
	ID         string `json:"id"`
	Salt       string `json:"salt"`
	Ciphertext string `json:"ciphertext"`
	Nonce      string `json:"nonce"`
	AAD        string `json:"aad"`
}

var (
	persistenceFile = "data.json"
	persistenceLock sync.Mutex
)

// storageSync saves the current state to a file
func storageSync(userStore *UserStore, logger *log.Logger) error {
	persistenceLock.Lock()
	defer persistenceLock.Unlock()

	// Create persistent data
	data := PersistentData{
		Users: make(map[string]PersistentUser)}

	// Save users
	userStore.mu.RLock()
	for username, user := range userStore.users {
		// Convert credentials
		credentials := make([]PersistentCredential, len(user.Credentials))
		for i, cred := range user.Credentials {
			credentials[i] = PersistentCredential{
				ID:              base64.URLEncoding.EncodeToString(cred.ID),
				PublicKey:       base64.StdEncoding.EncodeToString(cred.PublicKey),
				AttestationType: cred.AttestationType,
				Flags: PersistentCredentialFlags{
					UserPresent:    cred.Flags.UserPresent,
					UserVerified:   cred.Flags.UserVerified,
					BackupEligible: cred.Flags.BackupEligible,
					BackupState:    cred.Flags.BackupState,
				},
				Authenticator: PersistentAuthenticator{
					AAGUID:       base64.StdEncoding.EncodeToString(cred.Authenticator.AAGUID),
					SignCount:    cred.Authenticator.SignCount,
					CloneWarning: cred.Authenticator.CloneWarning,
				},
			}
		}

		// Create persistent user
		data.Users[username] = PersistentUser{
			ID:          base64.URLEncoding.EncodeToString(user.ID),
			Name:        user.Name,
			DisplayName: user.DisplayName,
			Credentials: credentials,
		}
	}
	userStore.mu.RUnlock()

	// Convert to JSON
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		logger.Printf("Error converting data to JSON: %v", err)
		return err
	}

	// Write to file
	if err := os.WriteFile(persistenceFile, jsonData, 0644); err != nil {
		logger.Printf("Error writing data file: %v", err)
		return err
	}

	logger.Printf("Saved data with %d users and %d user secret entries",
		len(data.Users))
	return nil
}

// loadFromStorage loads data from storage into the user and secret stores
func loadFromStorage(userStore *UserStore, logger *log.Logger) error {
	persistenceLock.Lock()
	defer persistenceLock.Unlock()

	// Check if file exists
	if _, err := os.Stat(persistenceFile); os.IsNotExist(err) {
		logger.Println("Data file does not exist, skipping load")
		return nil
	}

	// Read file
	data, err := os.ReadFile(persistenceFile)
	if err != nil {
		logger.Printf("Error reading data file: %v", err)
		return err
	}

	// Parse JSON
	var persistentData PersistentData
	if err := json.Unmarshal(data, &persistentData); err != nil {
		logger.Printf("Error parsing data file: %v", err)
		return err
	}

	// Load users
	for username, persistentUser := range persistentData.Users {
		// Decode user ID
		userID, err := base64.URLEncoding.DecodeString(persistentUser.ID)
		if err != nil {
			logger.Printf("Error decoding user ID for %s: %v", username, err)
			continue
		}

		// Load credentials
		credentials := make([]webauthn.Credential, len(persistentUser.Credentials))
		for i, cred := range persistentUser.Credentials {
			// Decode credential ID
			credID, err := base64.URLEncoding.DecodeString(cred.ID)
			if err != nil {
				logger.Printf("Error decoding credential ID for %s: %v", username, err)
				continue
			}

			// Decode public key
			publicKey, err := base64.StdEncoding.DecodeString(cred.PublicKey)
			if err != nil {
				logger.Printf("Error decoding public key for %s: %v", username, err)
				continue
			}

			// Decode AAGUID
			var aaguid []byte
			if cred.Authenticator.AAGUID != "" {
				aaguid, err = base64.URLEncoding.DecodeString(cred.Authenticator.AAGUID)
				if err != nil {
					// Try standard base64
					aaguid, err = base64.StdEncoding.DecodeString(cred.Authenticator.AAGUID)
					if err != nil {
						logger.Printf("Error decoding AAGUID for %s: %v", username, err)
						// Use empty AAGUID instead of failing
						aaguid = make([]byte, 0)
					}
				}
			} else {
				// Use empty AAGUID
				aaguid = make([]byte, 0)
			}

			credentials[i] = webauthn.Credential{
				ID:              credID,
				PublicKey:       publicKey,
				AttestationType: cred.AttestationType,
				Flags: webauthn.CredentialFlags{
					UserPresent:    cred.Flags.UserPresent,
					UserVerified:   cred.Flags.UserVerified,
					BackupEligible: cred.Flags.BackupEligible,
					BackupState:    cred.Flags.BackupState,
				},
				Authenticator: webauthn.Authenticator{
					AAGUID:       aaguid,
					SignCount:    cred.Authenticator.SignCount,
					CloneWarning: cred.Authenticator.CloneWarning,
				},
			}
		}

		// Create user
		user := &User{
			ID:          userID,
			Name:        persistentUser.Name,
			DisplayName: persistentUser.DisplayName,
			Credentials: credentials,
		}

		// Add user to store
		userStore.users[username] = user
		logger.Printf("Loaded user %s with %d credentials", username, len(credentials))
	}

	logger.Printf("Loaded data with %d users",
		len(persistentData.Users))
	return nil
}
