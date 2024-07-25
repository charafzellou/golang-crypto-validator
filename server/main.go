package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gorilla/mux"
)

type User struct {
	Name    string
	Address common.Address
	Score   int
}

type Challenge struct {
	Sentence    string
	PublicKey   *rsa.PublicKey
	PrivateKey  *rsa.PrivateKey
	ExpireTime  time.Time
	ChallengeID string
}

var (
	users      = make(map[common.Address]*User)
	challenges = make(map[string]*Challenge)
	mu         sync.Mutex
)

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/ping", pingHandler).Methods("GET")
	r.HandleFunc("/subscribe", subscribeHandler).Methods("POST")
	r.HandleFunc("/info/{address}", infoHandler).Methods("GET")
	r.HandleFunc("/challenge/hash/{address}", hashChallengeHandler).Methods("GET")
	r.HandleFunc("/challenge/hash/{address}/{challengeID}", submitHashHandler).Methods("POST")
	r.HandleFunc("/challenge/encrypt/{address}", encryptChallengeHandler).Methods("GET")
	r.HandleFunc("/challenge/encrypt/{address}/{challengeID}", submitEncryptHandler).Methods("POST")

	go cleanupExpiredChallenges()

	log.Println("Server starting on :3000")
	log.Fatal(http.ListenAndServe(":3000", r))
}

func generateRandomSentence() string {
	log.Println("Generating random sentence...")
	words := []string{"The", "quick", "brown", "fox", "jumps", "over", "the", "lazy", "dog", "in", "the", "park", "at", "night", "under", "the", "moon", "light", "with", "a", "bowl", "of", "milk", "and", "a", "piece", "of", "cake", "on", "the", "side"}
	sentence := ""
	for i := 0; i < 5; i++ {
		randomNumber, err := rand.Int(rand.Reader, big.NewInt(int64(len(words))))
		if err != nil {
			log.Fatal("Failed to generate random number:", err)
		}
		sentence += words[randomNumber.Int64()] + " "
	}
	return sentence[:len(sentence)-1]
}

func generateChallengeID() string {
	b := make([]byte, 16)
	rand.Read(b)
	log.Printf("Generated challenge ID: %s", hex.EncodeToString(b))
	return hex.EncodeToString(b)
}

func checkWinner(address common.Address) {
	if users[address].Score >= 30 {
		log.Printf("User %s has won the challenge!", users[address].Name)
	}
}

func cleanupExpiredChallenges() {
	for {
		time.Sleep(1 * time.Minute)
		mu.Lock()
		now := time.Now()
		for id, challenge := range challenges {
			if now.After(challenge.ExpireTime) {
				log.Printf("Challenge %s has expired at %s", id, challenge.ExpireTime)
				delete(challenges, id)
			}
		}
		mu.Unlock()
	}
}

func pingHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received ping from %s", r.RemoteAddr)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("pong"))
}

func subscribeHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received subscription request from %s", r.RemoteAddr)

	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		log.Printf("Failed to decode request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if !common.IsHexAddress(user.Address.Hex()) {
		log.Printf("Invalid Ethereum address: %s", user.Address.Hex())
		http.Error(w, "Invalid Ethereum address", http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	if _, exists := users[user.Address]; exists {
		log.Printf("User already exists: %s", user.Address.Hex())
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	users[user.Address] = &user
	w.WriteHeader(http.StatusCreated)
	log.Printf("User %s subscribed successfully", user.Address.Hex())
	json.NewEncoder(w).Encode(map[string]string{"message": "User subscribed successfully"})
}

func infoHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received info request from %s", r.RemoteAddr)

	vars := mux.Vars(r)
	address := common.HexToAddress(vars["address"])

	mu.Lock()
	user, exists := users[address]
	mu.Unlock()

	if !exists {
		log.Printf("User not found: %s", address.Hex())
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	log.Printf("User info requested: %s, has score %d", user.Name, user.Score)
	json.NewEncoder(w).Encode(user)
}

func hashChallengeHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received hash challenge request from %s", r.RemoteAddr)

	vars := mux.Vars(r)
	address := common.HexToAddress(vars["address"])

	mu.Lock()
	defer mu.Unlock()

	if _, exists := users[address]; !exists {
		log.Printf("User not found: %s", address.Hex())
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	sentence := generateRandomSentence()
	challengeID := generateChallengeID()
	log.Printf("Generated hash challenge: %s for user %s", challengeID, address.Hex())
	challenges[challengeID] = &Challenge{
		Sentence:    sentence,
		ExpireTime:  time.Now().Add(5 * time.Minute),
		ChallengeID: challengeID,
	}

	json.NewEncoder(w).Encode(map[string]string{
		"sentence":     sentence,
		"challenge_id": challengeID,
	})
}

func submitHashHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received hash challenge submission from %s", r.RemoteAddr)

	vars := mux.Vars(r)
	address := common.HexToAddress(vars["address"])
	challengeID := vars["challengeID"]

	var submission struct {
		Hash string `json:"hash"`
	}
	if err := json.NewDecoder(r.Body).Decode(&submission); err != nil {
		log.Printf("Failed to decode request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	challenge, exists := challenges[challengeID]
	if !exists {
		log.Printf("Challenge not found: %s for user %s", challengeID, address.Hex())
		http.Error(w, "Challenge not found or expired", http.StatusBadRequest)
		return
	}

	if time.Now().After(challenge.ExpireTime) {
		delete(challenges, challengeID)
		log.Printf("Challenge %s has expired at %s for user %s", challengeID, challenge.ExpireTime, address.Hex())
		http.Error(w, "Challenge expired...", http.StatusBadRequest)
		return
	}

	expectedHash := sha256.Sum256([]byte(challenge.Sentence))
	if hex.EncodeToString(expectedHash[:]) == submission.Hash {
		users[address].Score++
		delete(challenges, challengeID)
		log.Printf("User %s has completed hash challenge %s successfully", address.Hex(), challengeID)
		json.NewEncoder(w).Encode(map[string]string{"message": "Hash challenge completed successfully"})
	} else {
		users[address].Score -= 3
		log.Printf("Incorrect hash: %s", submission.Hash)
		http.Error(w, "Incorrect hash or empty 'hash' field", http.StatusBadRequest)
	}

	log.Printf("User %s has score %d", users[address].Name, users[address].Score)
	checkWinner(address)
}

func encryptChallengeHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received encryption challenge request from %s", r.RemoteAddr)

	vars := mux.Vars(r)
	address := common.HexToAddress(vars["address"])

	mu.Lock()
	defer mu.Unlock()

	if _, exists := users[address]; !exists {
		log.Printf("User not found: %s", address.Hex())
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	sentence := generateRandomSentence()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("Failed to generate key: %v", err)
		http.Error(w, "Failed to generate key", http.StatusInternalServerError)
		return
	}
	publicKey := &privateKey.PublicKey

	challengeID := generateChallengeID()
	challenges[challengeID] = &Challenge{
		Sentence:    sentence,
		PublicKey:   publicKey,
		PrivateKey:  privateKey,
		ExpireTime:  time.Now().Add(5 * time.Minute),
		ChallengeID: challengeID,
	}
	log.Printf("Generated encryption challenge: %s for user %s", challengeID, address.Hex())

	pubKeyBytes := x509.MarshalPKCS1PublicKey(publicKey)
	pubKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubKeyBytes,
	})
	log.Printf("Generated encryption challenge: %s for user %s", challengeID, address.Hex())

	json.NewEncoder(w).Encode(map[string]interface{}{
		"sentence":     sentence,
		"public_key":   string(pubKeyPem),
		"challenge_id": challengeID,
	})
}

func submitEncryptHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received encryption challenge submission from %s", r.RemoteAddr)

	vars := mux.Vars(r)
	address := common.HexToAddress(vars["address"])
	challengeID := vars["challengeID"]

	var submission struct {
		Sentence   string `json:"sentence"`
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.NewDecoder(r.Body).Decode(&submission); err != nil {
		log.Printf("Failed to decode request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	challenge, exists := challenges[challengeID]
	if !exists {
		log.Printf("Challenge not found: %s for user %s", challengeID, address.Hex())
		http.Error(w, "Challenge not found or expired", http.StatusBadRequest)
		return
	}

	if time.Now().After(challenge.ExpireTime) {
		delete(challenges, challengeID)
		log.Printf("Challenge %s has expired at %s for user %s", challengeID, challenge.ExpireTime, address.Hex())
		http.Error(w, "Challenge expired", http.StatusBadRequest)
		return
	}

	ciphertext, err := hex.DecodeString(submission.Ciphertext)
	if err != nil {
		log.Printf("Failed to decode ciphertext: %v", err)
		http.Error(w, "Invalid ciphertext format", http.StatusBadRequest)
		return
	}

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, challenge.PrivateKey, ciphertext, nil)
	if err != nil {
		log.Printf("Failed to decrypt: %v", err)
		http.Error(w, "Decryption failed", http.StatusBadRequest)
		return
	}

	if string(plaintext) == challenge.Sentence {
		users[address].Score++
		delete(challenges, challengeID)
		log.Printf("User %s has completed encryption challenge %s successfully", address.Hex(), challengeID)
		json.NewEncoder(w).Encode(map[string]string{"message": "Encryption challenge completed successfully"})
	} else {
		users[address].Score -= 3
		log.Printf("Incorrect encryption or empty 'ciphertext' field")
		http.Error(w, "Incorrect encryption", http.StatusBadRequest)
	}

	checkWinner(address)
}
