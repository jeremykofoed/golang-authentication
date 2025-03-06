package main

import (
	"bytes"
	"encoding/json"
	"fmt"
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

// Call public route to create or login user.
func callUserRoute(user User, route string) (*Token, error) {
	url := apiURL + route
	rBody, err := json.Marshal(user)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal user: %v; Error: %v", user, err)
	}

	res, err := http.Post(url, contentType, bytes.NewBuffer(rBody))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v; URL: %s; Error: %v", rBody, url, err)
	}
	defer res.Body.Close()

	var cRes ClientResponse
	if err = json.NewDecoder(res.Body).Decode(&cRes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal server response: %+v; Error: %v", res.Body, err)
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unsuccessful call, server response: %+v; URL: %s", cRes, url)
	}

	token := &cRes.Token

	fmt.Printf("Successful api call: %+v\n", cRes)
	return token, nil
}

// Call public route to create or login user.
func callProtectedRoute(token *Token, route string) error {
	url := apiURL + route

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request; URL: %s; Error: %v", url, err)
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {

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
	if _, err := callUserRoute(user, "/create"); err != nil {
		fmt.Printf("Error: %v\n", err)
	}
	token, err := callUserRoute(user, "/login")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
	if token == nil {
		fmt.Println("Token is empty")
	}
	if err := callProtectedRoute(token, "/something"); err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}
