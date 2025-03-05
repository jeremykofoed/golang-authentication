package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

const apiURL = "http://localhost:8080"
const contentType = "application/json"

type User struct {
	ID       int64
	PlayerID string `json:"player_id"`
	Password string `json:"password"`
}

type ClientResponse struct {
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	Timestamp int64  `json:"timestamp"`
	Token     Token  `json:"token"`
}

type Token struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// Calls: Create user
func callCreateUser(user User) error {
	url := apiURL + "/create"
	rBody, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("failed to marshal user: %v; Error: %v", user, err)
	}

	res, err := http.Post(url, contentType, bytes.NewBuffer(rBody))
	if err != nil {
		return fmt.Errorf("failed to send request: %v; URL: %s; Error: %v", rBody, url, err)
	}
	defer res.Body.Close()

	var cRes ClientResponse
	if err = json.NewDecoder(res.Body).Decode(&cRes); err != nil {
		return fmt.Errorf("failed to unmarshal server response: %+v; Error: %v", res.Body, err)
	}

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("unsuccessful call, server response: %+v; URL: %s", cRes, url)
	}

	fmt.Printf("Successful api call: %+v\n", cRes)
	return nil
}

// Calls: Login user
func callLoginUser(user User) error {
	url := apiURL + "/login"
	rBody, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("failed to marshal user: %v; Error: %v", user, err)
	}

	res, err := http.Post(url, contentType, bytes.NewBuffer(rBody))
	if err != nil {
		return fmt.Errorf("failed to send request: %v; URL: %s; Error: %v", rBody, url, err)
	}
	defer res.Body.Close()

	var cRes ClientResponse
	if err = json.NewDecoder(res.Body).Decode(&cRes); err != nil {
		return fmt.Errorf("failed to unmarshal server response: %+v; Error: %v", res.Body, err)
	}

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("unsuccessful call, server response: %+v; URL: %s", cRes, url)
	}

	fmt.Printf("Successful api call: %+v\n", cRes)
	return nil
}

func main() {
	user := User{
		PlayerID: "jeremy@test.com",
		Password: "password12345",
	}
	//@JWK TODO: Implement check for existing user error and call login.
	if err := callCreateUser(user); err != nil {
		fmt.Printf("Error: %v\n", err)
	}
	if err := callLoginUser(user); err != nil {
		log.Printf("Error: %v\n", err)
	}
}
