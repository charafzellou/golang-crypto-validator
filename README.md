# Cryptography Challenge: Secure Communication Protocol

## Overview
In this exercise, you will implement a client application that interacts with a secure server to complete a series of cryptographic challenges. The goal is to reinforce your understanding of fundamental cryptographic concepts while simulating real-world secure communication protocols.

## Objectives
By the end of this challenge, you should be able to:
1. Implement basic cryptographic operations (hashing and encryption)
2. Interact with a RESTful API using secure protocols
3. Handle and respond to time-sensitive cryptographic challenges
4. Manage a simple score-based system in a competitive environment

## The Challenge
You are tasked with creating a client application that communicates with a provided server. The server will issue two types of cryptographic challenges: hash challenges and encryption challenges. Your client must solve these challenges correctly to earn points. The first student to reach 30 points wins the challenge.

### Server Endpoints
The server provides the following endpoints:

1. `/subscribe` (POST): Register your client with the server
2. `/info/{address}` (GET): Retrieve your current score and information
3. `/challenge/hash/{address}` (GET): Request a hash challenge
4. `/challenge/hash/{address}/{challengeID}` (POST): Submit a hash challenge solution
5. `/challenge/encrypt/{address}` (GET): Request an encryption challenge
6. `/challenge/encrypt/{address}/{challengeID}` (POST): Submit an encryption challenge solution

### Challenge Types

1. **Hash Challenge**: 
   - The server provides a random sentence.
   - Your task is to compute the SHA256 hash of the sentence and submit it back to the server.

2. **Encryption Challenge**:
   - The server provides a random sentence and a public key.
   - Your task is to encrypt the sentence using the provided public key and submit the ciphertext back to the server.

### Scoring
- Each successful challenge completion earns you 1 point.
- Each failed attempt results in a 3-point deduction.
- The first student to reach a score of 30 wins the challenge.

## Requirements
1. Implement a client application in a programming language of your choice.
2. Your client should be able to:
   - Subscribe to the server with a valid Ethereum address and name
   - Retrieve current score information
   - Request and solve both hash and encryption challenges
   - Handle errors gracefully and continue functioning
3. Implement proper error handling and logging in your client application.
4. Ensure your client can handle concurrent challenges and maintain a consistent state.

## Bonus Challenges
For extra credit, consider implementing the following features:
1. A user interface to display current score and challenge status
2. Automatic retrying of failed challenges with exponential backoff
3. Implementation of additional cryptographic algorithms beyond those required

## Submission
Submit your client application code along with a brief report describing:
1. Your implementation approach
2. Any challenges you faced and how you overcame them
3. Potential improvements or optimizations you would make with more time

Good luck, and may the best cryptographer win!