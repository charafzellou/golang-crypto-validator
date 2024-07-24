package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

const serverURL = "http://localhost:8080"

type User struct {
	Name    string
	Address common.Address
	Score   int
}

func main() {
	address := common.HexToAddress("0x1234567890123456789012345678901234567890")
	name := "Alice"

	subscribe(name, address)

	for {
		user := getInfo(address)
		fmt.Printf("Current score: %d\n", user.Score)

		performHashChallenge(address)
		performEncryptChallenge(address)

		if user.Score >= 30 {
			fmt.Println("Congratulations! You've won the challenge!")
			break
		}

		time.Sleep(5 * time.Second)
	}
}

func subscribe(name string, address common.Address) {
	user := User{Name: name, Address: address}
	jsonData, _ := json.Marshal(user)

	resp, err := http.Post(serverURL+"/subscribe", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		log.Fatalf("Failed to subscribe: %s", body)
	}

	fmt.Println("Successfully subscribed to the server.")
}

func getInfo(address common.Address) User {
	resp, err := http.Get(fmt.Sprintf("%s/info/%s", serverURL, address.Hex()))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Fatalf("Failed to get user info: %s", body)
	}

	var user User
	json.NewDecoder(resp.Body).Decode(&user)
	return user
}

func performHashChallenge(address common.Address) {
	resp, err := http.Get(fmt.Sprintf("%s/challenge/hash/%s", serverURL, address.Hex()))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Failed to get hash challenge: %s", body)
		return
	}

	var challenge struct {
		Sentence    string `json:"sentence"`
		ChallengeID string `json:"challenge_id"`
	}
	json.NewDecoder(resp.Body).Decode(&challenge)

	hash := sha256.Sum256([]byte(challenge.Sentence))
	hashHex := hex.EncodeToString(hash[:])

	solution := map[string]string{"hash": hashHex}
	jsonData, _ := json.Marshal(solution)

	resp, err = http.Post(fmt.Sprintf("%s/challenge/hash/%s/%s", serverURL, address.Hex(), challenge.ChallengeID), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		fmt.Println("Hash challenge completed successfully!")
	} else {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("Hash challenge failed: %s\n", body)
	}
}
func performEncryptChallenge(address common.Address) {
	resp, err := http.Get(fmt.Sprintf("%s/challenge/encrypt/%s", serverURL, address.Hex()))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Failed to get encryption challenge: %s", body)
		return
	}

	var challenge struct {
		Sentence    string `json:"sentence"`
		PublicKey   string `json:"public_key"`
		ChallengeID string `json:"challenge_id"`
	}
	json.NewDecoder(resp.Body).Decode(&challenge)

	pubKeyBytes, err := hex.DecodeString(challenge.PublicKey)
	if err != nil {
		log.Printf("Failed to decode public key: %v", err)
		return
	}

	pubKey, err := crypto.UnmarshalPubkey(pubKeyBytes)
	if err != nil {
		log.Printf("Failed to unmarshal public key: %v", err)
		return
	}

	ciphertext, err := encryptECIES([]byte(challenge.Sentence), pubKey)
	if err != nil {
		log.Printf("Failed to encrypt: %v", err)
		return
	}

	solution := map[string]string{"ciphertext": hex.EncodeToString(ciphertext)}
	jsonData, _ := json.Marshal(solution)

	resp, err = http.Post(fmt.Sprintf("%s/challenge/encrypt/%s/%s", serverURL, address.Hex(), challenge.ChallengeID), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		fmt.Println("Encryption challenge completed successfully!")
	} else {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("Encryption challenge failed: %s\n", body)
	}
}

func encryptECIES(plaintext []byte, publicKey *ecdsa.PublicKey) ([]byte, error) {
	eciesPublicKey := ecies.ImportECDSAPublic(publicKey)

	// Generate an ephemeral key pair
	ephemeralPrivateKey, err := ecies.GenerateKey(rand.Reader, publicKey.Curve, eciesPublicKey.Params)
	if err != nil {
		return nil, err
	}

	// Perform ECDH to derive a shared secret
	sx, sy := publicKey.Curve.ScalarMult(publicKey.X, publicKey.Y, ephemeralPrivateKey.D.Bytes())
	sharedSecret := sha256.Sum256(append(sx.Bytes(), sy.Bytes()...))

	// Use the shared secret to encrypt the plaintext
	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i++ {
		ciphertext[i] = plaintext[i] ^ sharedSecret[i%32]
	}

	// Prepare the final ciphertext: ephemeral public key + encrypted data
	ephemeralPublicKey := ephemeralPrivateKey.PublicKey
	finalCiphertext := append(ephemeralPublicKey.X.Bytes(), ephemeralPublicKey.Y.Bytes()...)
	finalCiphertext = append(finalCiphertext, ciphertext...)

	return finalCiphertext, nil
}
