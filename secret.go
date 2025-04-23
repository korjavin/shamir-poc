package main

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
)

// Secret represents a secret with its questions and encrypted data
type Secret struct {
	ID              string   `json:"id"`
	Salt            string   `json:"salt"`
	SecretQuestions []string `json:"secretQuestions"`
	Ciphertext      string   `json:"ciphertext"`
	Nonce           string   `json:"nonce"`
	AAD             string   `json:"aad"`
}

// SecretStore is an in-memory store for secrets
type SecretStore struct {
	secrets map[string][]Secret // username -> secrets
	mu      sync.RWMutex
	logger  *log.Logger
}

// NewSecretStore creates a new secret store
func NewSecretStore(logger *log.Logger) *SecretStore {
	return &SecretStore{
		secrets: make(map[string][]Secret),
		logger:  logger,
	}
}

// GetSecrets returns all secrets for a user
func (s *SecretStore) GetSecrets(username string) []Secret {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.secrets[username]
}

// GetSecret returns a specific secret for a user
func (s *SecretStore) GetSecret(username, secretID string) (Secret, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	secrets := s.secrets[username]
	for _, secret := range secrets {
		if secret.ID == secretID {
			return secret, true
		}
	}

	return Secret{}, false
}

// SaveSecret saves a secret for a user
func (s *SecretStore) SaveSecret(username string, secret Secret) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if the user already has secrets
	if _, ok := s.secrets[username]; !ok {
		s.secrets[username] = []Secret{}
	}

	// Check if the secret already exists
	for i, existingSecret := range s.secrets[username] {
		if existingSecret.ID == secret.ID {
			// Update existing secret
			s.secrets[username][i] = secret
			s.logger.Printf("Updated secret %s for user %s", secret.ID, username)
			return
		}
	}

	// Add new secret
	s.secrets[username] = append(s.secrets[username], secret)
	s.logger.Printf("Added new secret %s for user %s", secret.ID, username)
}

// DeleteSecret deletes a secret for a user
func (s *SecretStore) DeleteSecret(username, secretID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	secrets := s.secrets[username]
	for i, secret := range secrets {
		if secret.ID == secretID {
			// Remove the secret
			s.secrets[username] = append(secrets[:i], secrets[i+1:]...)
			s.logger.Printf("Deleted secret %s for user %s", secretID, username)
			return true
		}
	}

	return false
}

// LoadFromPersistence loads secrets from the persistence layer
func (s *SecretStore) LoadFromPersistence(data map[string][]Secret) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.secrets = data
	s.logger.Printf("Loaded %d user secret entries from persistence", len(data))
}

// SaveToPersistence saves secrets to the persistence layer
func (s *SecretStore) SaveToPersistence() map[string][]Secret {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.secrets
}

// setupSecretHandlers sets up the HTTP handlers for secret management
func setupSecretHandlers(secretStore *SecretStore, userStore *UserStore, sessionStore *SessionStore, logger *log.Logger) {
	// Create a new secret
	http.HandleFunc("/api/secrets/create", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get session ID from cookie
		cookie, err := r.Cookie("session_id")
		if err != nil {
			logger.Printf("No session cookie: %v", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Get session
		session, ok := sessionStore.GetSession(cookie.Value)
		if !ok {
			logger.Printf("Invalid session")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Get user
		_, username, ok := userStore.GetUserByID(session.UserID)
		if !ok {
			logger.Printf("User not found for session")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Parse request
		var secret Secret
		if err := json.NewDecoder(r.Body).Decode(&secret); err != nil {
			logger.Printf("Failed to parse request: %v", err)
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		// Validate secret
		if secret.ID == "" || secret.Salt == "" || secret.Ciphertext == "" || secret.Nonce == "" {
			logger.Printf("Invalid secret data")
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		// Save secret
		secretStore.SaveSecret(username, secret)
		logger.Printf("Created secret %s for user %s", secret.ID, username)

		// Save to persistence
		if err := saveToStorage(userStore, secretStore, logger); err != nil {
			logger.Printf("Failed to save to storage: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Return success
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "success",
			"id":     secret.ID,
		})
	})

	// Get all secrets for the current user
	http.HandleFunc("/api/secrets", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get session ID from cookie
		cookie, err := r.Cookie("session_id")
		if err != nil {
			logger.Printf("No session cookie: %v", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Get session
		session, ok := sessionStore.GetSession(cookie.Value)
		if !ok {
			logger.Printf("Invalid session")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Get user
		_, username, ok := userStore.GetUserByID(session.UserID)
		if !ok {
			logger.Printf("User not found for session")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Get secrets
		secrets := secretStore.GetSecrets(username)
		logger.Printf("Retrieved %d secrets for user %s", len(secrets), username)

		// Return secrets
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "success",
			"secrets": secrets,
		})
	})

	// Get a specific secret
	http.HandleFunc("/api/secrets/get", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get session ID from cookie
		cookie, err := r.Cookie("session_id")
		if err != nil {
			logger.Printf("No session cookie: %v", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Get session
		session, ok := sessionStore.GetSession(cookie.Value)
		if !ok {
			logger.Printf("Invalid session")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Get user
		_, username, ok := userStore.GetUserByID(session.UserID)
		if !ok {
			logger.Printf("User not found for session")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Get secret ID from query
		secretID := r.URL.Query().Get("id")
		if secretID == "" {
			logger.Printf("No secret ID provided")
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		// Get secret
		secret, ok := secretStore.GetSecret(username, secretID)
		if !ok {
			logger.Printf("Secret %s not found for user %s", secretID, username)
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}

		logger.Printf("Retrieved secret %s for user %s", secretID, username)

		// Return secret
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "success",
			"secret": secret,
		})
	})

	// Delete a secret
	http.HandleFunc("/api/secrets/delete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get session ID from cookie
		cookie, err := r.Cookie("session_id")
		if err != nil {
			logger.Printf("No session cookie: %v", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Get session
		session, ok := sessionStore.GetSession(cookie.Value)
		if !ok {
			logger.Printf("Invalid session")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Get user
		_, username, ok := userStore.GetUserByID(session.UserID)
		if !ok {
			logger.Printf("User not found for session")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Parse request
		var requestData struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
			logger.Printf("Failed to parse request: %v", err)
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		// Delete secret
		if ok := secretStore.DeleteSecret(username, requestData.ID); !ok {
			logger.Printf("Secret %s not found for user %s", requestData.ID, username)
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}

		logger.Printf("Deleted secret %s for user %s", requestData.ID, username)

		// Save to persistence
		if err := saveToStorage(userStore, secretStore, logger); err != nil {
			logger.Printf("Failed to save to storage: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Return success
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "success",
		})
	})
}

// saveToStorage saves data to storage
func saveToStorage(userStore *UserStore, secretStore *SecretStore, logger *log.Logger) error {
	// Create persistent data
	data := PersistentData{
		Users:   make(map[string]PersistentUser),
		Secrets: secretStore.SaveToPersistence(),
	}

	// Add users
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
		len(data.Users), len(data.Secrets))
	return nil
}
