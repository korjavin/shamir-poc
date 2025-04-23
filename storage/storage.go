package storage

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"sync"

	"github.com/go-webauthn/webauthn/webauthn"
)

// AppData represents the application data to be persisted
type AppData struct {
	Users map[string]User `json:"users"`
}

// User represents a user with credentials
type User struct {
	ID          string                   `json:"id"`
	Name        string                   `json:"name"`
	DisplayName string                   `json:"displayName"`
	Credentials []SerializableCredential `json:"credentials"`
}

// SerializableCredential is a version of webauthn.Credential that can be serialized to JSON
type SerializableCredential struct {
	ID              string                        `json:"id"`
	PublicKey       string                        `json:"publicKey"`
	AttestationType string                        `json:"attestationType"`
	Flags           webauthn.CredentialFlags      `json:"flags"`
	Authenticator   SerializableAuthenticatorData `json:"authenticator"`
}

// SerializableAuthenticatorData is a version of webauthn.Authenticator that can be serialized to JSON
type SerializableAuthenticatorData struct {
	AAGUID       string `json:"aaguid"`
	SignCount    uint32 `json:"signCount"`
	CloneWarning bool   `json:"cloneWarning"`
}

var (
	dataFile  = "data.json"
	dataLock  sync.Mutex
	appLogger *log.Logger
)

// Initialize sets up the storage with a logger
func Initialize(logger *log.Logger) {
	appLogger = logger
	appLogger.Println("Storage initialized")
}

// LoadData loads data from the data.json file
func LoadData() (*AppData, error) {
	dataLock.Lock()
	defer dataLock.Unlock()

	// Check if file exists
	if _, err := os.Stat(dataFile); os.IsNotExist(err) {
		appLogger.Println("Data file does not exist, creating empty data")
		return &AppData{
			Users: make(map[string]User),
		}, nil
	}

	// Read file
	data, err := os.ReadFile(dataFile)
	if err != nil {
		appLogger.Printf("Error reading data file: %v", err)
		return nil, err
	}

	// Parse JSON
	var appData AppData
	if err := json.Unmarshal(data, &appData); err != nil {
		appLogger.Printf("Error parsing data file: %v", err)
		return nil, err
	}

	// Initialize maps if they're nil
	if appData.Users == nil {
		appData.Users = make(map[string]User)
	}

	appLogger.Printf("Loaded data with %d users",
		len(appData.Users))
	return &appData, nil
}

// SaveData saves data to the data.json file
func SaveData(data *AppData) error {
	dataLock.Lock()
	defer dataLock.Unlock()

	// Convert to JSON
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		appLogger.Printf("Error converting data to JSON: %v", err)
		return err
	}

	// Write to file
	if err := os.WriteFile(dataFile, jsonData, 0644); err != nil {
		appLogger.Printf("Error writing data file: %v", err)
		return err
	}

	appLogger.Printf("Saved data with %d users",
		len(data.Users))
	return nil
}

// ConvertAppUser converts an application User to a storage User
func ConvertAppUser(appUserID []byte, username, displayName string, credentials []webauthn.Credential) User {
	storageCredentials := make([]SerializableCredential, len(credentials))
	for i, cred := range credentials {
		storageCredentials[i] = SerializableCredential{
			ID:              base64.URLEncoding.EncodeToString(cred.ID),
			PublicKey:       base64.StdEncoding.EncodeToString(cred.PublicKey),
			AttestationType: cred.AttestationType,
			Flags:           cred.Flags,
			Authenticator: SerializableAuthenticatorData{
				AAGUID:       base64.StdEncoding.EncodeToString(cred.Authenticator.AAGUID),
				SignCount:    cred.Authenticator.SignCount,
				CloneWarning: cred.Authenticator.CloneWarning,
			},
		}
	}

	return User{
		ID:          base64.URLEncoding.EncodeToString(appUserID),
		Name:        username,
		DisplayName: displayName,
		Credentials: storageCredentials,
	}
}

// LoadUserCredentials loads credentials for a user from storage
func LoadUserCredentials(storageUser User) ([]webauthn.Credential, error) {
	credentials := make([]webauthn.Credential, len(storageUser.Credentials))
	for i, cred := range storageUser.Credentials {
		// Decode credential ID
		credID, err := base64.URLEncoding.DecodeString(cred.ID)
		if err != nil {
			return nil, err
		}

		// Decode public key
		publicKey, err := base64.StdEncoding.DecodeString(cred.PublicKey)
		if err != nil {
			return nil, err
		}

		// Decode AAGUID
		aaguid, err := base64.StdEncoding.DecodeString(cred.Authenticator.AAGUID)
		if err != nil {
			return nil, err
		}

		credentials[i] = webauthn.Credential{
			ID:              credID,
			PublicKey:       publicKey,
			AttestationType: cred.AttestationType,
			Flags:           cred.Flags,
			Authenticator: webauthn.Authenticator{
				AAGUID:       aaguid,
				SignCount:    cred.Authenticator.SignCount,
				CloneWarning: cred.Authenticator.CloneWarning,
			},
		}
	}

	return credentials, nil
}

// SyncStorage saves the current state to disk
func SyncStorage(data *AppData) error {
	return SaveData(data)
}
