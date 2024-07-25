package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

const serverURL = "http://34.163.219.17:3000"

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

	log.Printf("Received hash challenge: %s", challenge.Sentence)
	hash := sha256.Sum256([]byte(challenge.Sentence))
	log.Printf("Hash: %x", hash)
	hashHex := hex.EncodeToString(hash[:])
	log.Printf("Hash Hex: %s", hashHex)

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
	log.Printf("Received encryption challenge: %s", challenge.Sentence)
	log.Printf("Public key: %s", challenge.PublicKey)
	log.Printf("Challenge ID: %s", challenge.ChallengeID)

	block, _ := pem.Decode([]byte(challenge.PublicKey))
	if block == nil || block.Type != "RSA PUBLIC KEY" {
		log.Printf("Failed to decode PEM block containing the public key")
		return
	}

	pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		log.Printf("Failed to parse RSA public key: %v", err)
		return
	}
	log.Printf("Public key: %v", pubKey)

	ciphertext, err := encryptRSA([]byte(challenge.Sentence), pubKey)
	if err != nil {
		log.Printf("Failed to encrypt: %v", err)
		return
	}
	log.Printf("Ciphertext: %x", ciphertext)

	solution := map[string]string{"ciphertext": hex.EncodeToString(ciphertext)}
	jsonData, _ := json.Marshal(solution)
	log.Printf("Sending solution: %s", jsonData)

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

func encryptRSA(plaintext []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, plaintext, nil)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}
