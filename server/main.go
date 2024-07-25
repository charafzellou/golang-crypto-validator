package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gorilla/mux"
)

type User struct {
	Name    string
	Address common.Address
	Score   int
}

type Challenge struct {
	Sentence    string
	PublicKey   *ecdsa.PublicKey
	PrivateKey  *ecdsa.PrivateKey // Added this field
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

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

func pingHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("pong"))
}

func subscribeHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if !common.IsHexAddress(user.Address.Hex()) {
		http.Error(w, "Invalid Ethereum address", http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	if _, exists := users[user.Address]; exists {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	users[user.Address] = &user
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User subscribed successfully"})
}

func infoHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	address := common.HexToAddress(vars["address"])

	mu.Lock()
	user, exists := users[address]
	mu.Unlock()

	if !exists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(user)
}

func hashChallengeHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	address := common.HexToAddress(vars["address"])

	mu.Lock()
	defer mu.Unlock()

	if _, exists := users[address]; !exists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	sentence := generateRandomSentence()
	challengeID := generateChallengeID()
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
	vars := mux.Vars(r)
	address := common.HexToAddress(vars["address"])
	challengeID := vars["challengeID"]

	var submission struct {
		Hash string `json:"hash"`
	}
	if err := json.NewDecoder(r.Body).Decode(&submission); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	challenge, exists := challenges[challengeID]
	if !exists {
		http.Error(w, "Challenge not found or expired", http.StatusBadRequest)
		return
	}

	if time.Now().After(challenge.ExpireTime) {
		delete(challenges, challengeID)
		http.Error(w, "Challenge expired", http.StatusBadRequest)
		return
	}

	expectedHash := sha256.Sum256([]byte(challenge.Sentence))
	if hex.EncodeToString(expectedHash[:]) == submission.Hash {
		users[address].Score++
		delete(challenges, challengeID)
		json.NewEncoder(w).Encode(map[string]string{"message": "Hash challenge completed successfully"})
	} else {
		users[address].Score -= 3
		http.Error(w, "Incorrect hash", http.StatusBadRequest)
	}

	checkWinner(address)
}

func encryptChallengeHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	address := common.HexToAddress(vars["address"])

	mu.Lock()
	defer mu.Unlock()

	if _, exists := users[address]; !exists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	sentence := generateRandomSentence()
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	publicKey := &privateKey.PublicKey

	challengeID := generateChallengeID()
	challenges[challengeID] = &Challenge{
		Sentence:    sentence,
		PublicKey:   publicKey,
		PrivateKey:  privateKey, // Store the private key
		ExpireTime:  time.Now().Add(5 * time.Minute),
		ChallengeID: challengeID,
	}

	pubKeyBytes := crypto.FromECDSAPub(publicKey)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"sentence":     sentence,
		"public_key":   hex.EncodeToString(pubKeyBytes),
		"challenge_id": challengeID,
	})
}

func submitEncryptHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	address := common.HexToAddress(vars["address"])
	challengeID := vars["challengeID"]

	var submission struct {
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.NewDecoder(r.Body).Decode(&submission); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	challenge, exists := challenges[challengeID]
	if !exists {
		http.Error(w, "Challenge not found or expired", http.StatusBadRequest)
		return
	}

	if time.Now().After(challenge.ExpireTime) {
		delete(challenges, challengeID)
		http.Error(w, "Challenge expired", http.StatusBadRequest)
		return
	}

	ciphertext, err := hex.DecodeString(submission.Ciphertext)
	if err != nil {
		http.Error(w, "Invalid ciphertext format", http.StatusBadRequest)
		return
	}

	privateKey := challenge.PrivateKey // Retrieve the stored private key
	plaintext, err := decryptECIES(privateKey, ciphertext)
	if err != nil {
		http.Error(w, "Decryption failed", http.StatusBadRequest)
		return
	}

	if string(plaintext) == challenge.Sentence {
		users[address].Score++
		delete(challenges, challengeID)
		json.NewEncoder(w).Encode(map[string]string{"message": "Encryption challenge completed successfully"})
	} else {
		users[address].Score -= 3
		http.Error(w, "Incorrect encryption", http.StatusBadRequest)
	}

	checkWinner(address)
}

func generateRandomSentence() string {
	words := []string{"The", "quick", "brown", "fox", "jumps", "over", "the", "lazy", "dog"}
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
				delete(challenges, id)
			}
		}
		mu.Unlock()
	}
}

func decryptECIES(privateKey *ecdsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	curve := privateKey.Curve
	x := new(big.Int).SetBytes(ciphertext[:32])
	y := new(big.Int).SetBytes(ciphertext[32:64])

	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("invalid point")
	}

	// Perform ECDH to derive the shared secret
	sx, sy := curve.ScalarMult(x, y, privateKey.D.Bytes())
	sharedSecret := sha256.Sum256(append(sx.Bytes(), sy.Bytes()...))

	// Decrypt the ciphertext
	plaintext := make([]byte, len(ciphertext)-64)
	for i := 0; i < len(plaintext); i++ {
		plaintext[i] = ciphertext[64+i] ^ sharedSecret[i%32]
	}

	return plaintext, nil
}
