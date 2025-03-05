package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/jackc/pgx/v5/stdlib" //PostgresSQL drivers
	"golang.org/x/crypto/bcrypt"
)

// Consts
const TTL_ACCESS_TOKEN = 60   //Seconds
const TTL_REFRESH_TOKEN = 300 //Seconds = 60 * 5 minutes

// Structs
type User struct {
	ID       int64
	PlayerID string
	Password string
}

type Token struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// Vars
var (
	err       error
	db        *sql.DB
	rdb       *redis.Client
	once      sync.Once
	jwtSecret = []byte("SECRET_KEY") //@JWK TODO: Store this in ENV
)

// Initialize resources.  init() gets called before main().
func init() {
	once.Do(func() {
		initPostgres()
		initRedis()
	})
}

// Initialize callee.
func initPostgres() {
	//PostgreSQL
	connString := "postgres://main_user:pass12345@localhost:5432/sandbox?sslmode=disable" //@JWK TODO: Store this in ENV
	db, err = sql.Open("pgx", connString)
	if err != nil {
		log.Fatalf("Error making database connection: %v", err)
	}

	//Check postgres connection.
	err = db.Ping()
	if err != nil {
		log.Fatalf("Error pinging Postgres: %v", err)
	}

	log.Println("Postgres running ...")
}

// Initialize callee.
func initRedis() {
	//Redis
	rdb = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})

	//Check redis connection
	ctx := context.Background() //Send non-nil empty context.
	_, err = rdb.Ping(ctx).Result()
	if err != nil {
		log.Fatalf("Error pinging Redis: %v", err)
	}

	log.Println("Redis running ...")
}

// Close resources, deferred in main().
func closePostgres() {
	if db != nil {
		db.Close()
		db = nil
		log.Println("Postgres closed.")
	}
}

// Close resource, deferred in main().
func closeRedis() {
	if rdb != nil {
		rdb.Close()
		rdb = nil
		log.Println("Redis closed.")
	}
}

// Utility: This hashes a password string to be stored in the DB.  Make sure the hash and compare functions utilize the same library.
func utilHashPassword(p string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
	return string(bytes), err
}

// Utility: This compares hashed password and the string password to make sure they are the same.
func utilComparePassword(h, p string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(h), []byte(p))
	//If there is no error, it's a match and therefore returns True.
	return err == nil
}

// Utility: Generate JWT (Json web token).
func utilGenerateToken(playerID string, ttl time.Duration) (string, error) {
	claims := jwt.MapClaims{
		"player_id": playerID,
		"exp":       time.Now().Add(time.Second * ttl).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// Handler: Client response format.
func handlerClientResponse(res http.ResponseWriter, msg string, code int, token *Token) {
	//Set the content type and status code.
	res.Header().Set("Content-Type", "application/json")
	res.WriteHeader(code)

	//Define a limited scope struct
	type ClientResponse struct {
		Success   bool   `json:"success"`
		Message   string `json:"message"`
		Timestamp int64  `json:"timestamp"`
		Token     *Token `json:"token"`
	}

	//Create the JSON response.
	//@JWK TODO: On production deployed environment exclude the msg field.
	output := ClientResponse{
		Success:   code == http.StatusOK,
		Timestamp: time.Now().Unix(),
		Message:   msg,
		Token:     token,
	}

	if err := json.NewEncoder(res).Encode(output); err != nil {
		log.Fatalf("Error encoding client response: %v; Output: %v", err, output)
	}
}

// Handler: Better error handling to determine the location of errors.
func handlerError(res http.ResponseWriter, msg string, err string, code int) {
	//Get details about where the error took place (program counter, file, line, success)
	pc, file, line, _ := runtime.Caller(1)
	fx := runtime.FuncForPC(pc)

	//Log the HTTP error.
	//@JWK TODO: Make sure this is handled properly by streaming to central log repository.
	log.Printf("Error on %s in %s at line %d; Msg: %s", file, fx.Name(), line, msg)

	//Send reponse to client.
	var token *Token = nil
	handlerClientResponse(res, err, code, token)
}

// Handler: Create user.
func handlerCreateUser(res http.ResponseWriter, req *http.Request) {
	//Check to make sure the method is POST.
	if req.Method != http.MethodPost {
		msg := fmt.Sprintf("Request method used: %s", req.Method)
		handlerError(res, msg, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	//Define a limited scope struct.
	var params struct {
		PlayerID string `json:"player_id"`
		Password string `json:"password"`
	}

	//Decode the json body into the struct.
	if err := json.NewDecoder(req.Body).Decode(&params); err != nil {
		msg := fmt.Sprintf("Bad client input: %v", req.Body)
		handlerError(res, msg, "Unable to parse the client input", http.StatusBadRequest)
		return
	}

	hashedPassword, err := utilHashPassword(params.Password)
	if err != nil {
		msg := fmt.Sprintf("Error hashing password: %v", err)
		handlerError(res, msg, "Unable to hash password", http.StatusInternalServerError)
		return
	}

	//Query to see if the user exists already.
	sql := "SELECT id, player_id, password FROM users where player_id = $1"
	rows, err := db.Query(sql, params.PlayerID) //Optionally use QueryRow()
	if err != nil {
		msg := fmt.Sprintf("Error executing query: %v; SQL: %s; Params: %v", err, sql, params)
		handlerError(res, msg, "Unable to execute query", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	if rows.Next() { //This should be false unless the player_id already exists.
		msg := ""
		handlerError(res, msg, "Player ID already exists", http.StatusConflict)
		return
	}

	//If not, create a new user with the information.
	sql = "INSERT INTO users (player_id, password) VALUES ($1, $2)"
	_, err = db.Exec(sql, params.PlayerID, hashedPassword)
	if err != nil {
		msg := fmt.Sprintf("Error executing query: %v; SQL: %s; Params: %s, %s", err, sql, params.PlayerID, hashedPassword)
		handlerError(res, msg, "Unable to execute query", http.StatusInternalServerError)
		return
	}

	//Successful.
	var token *Token = nil
	handlerClientResponse(res, "User successfully created!", http.StatusOK, token)
}

// Handler: Login user.
func handlerLoginUser(res http.ResponseWriter, req *http.Request) {
	//Check to make sure the method is POST.
	if req.Method != http.MethodPost {
		msg := fmt.Sprintf("Request method used: %s", req.Method)
		handlerError(res, msg, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	//Define a limited scope struct.
	var params struct {
		PlayerID string `json:"player_id"`
		Password string `json:"password"`
	}

	//Decode the json body into the struct.
	if err := json.NewDecoder(req.Body).Decode(&params); err != nil {
		msg := fmt.Sprintf("Bad client input: %v", req.Body)
		handlerError(res, msg, "Unable to parse the client input", http.StatusBadRequest)
		return
	}

	//Query to get user information.
	sql := "SELECT id, player_id, password FROM users where player_id = $1"
	rows, err := db.Query(sql, params.PlayerID) //Optionally use QueryRow()
	if err != nil {
		msg := fmt.Sprintf("Error executing query: %v; SQL: %s; Params: %v", err, sql, params)
		handlerError(res, msg, "Unable to execute query", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	if !rows.Next() { //This should be true unless the player_id does not exist.
		msg := ""
		handlerError(res, msg, "Player ID does not exist", http.StatusConflict)
		return
	}

	var user User
	if err = rows.Scan(&user.ID, &user.PlayerID, &user.Password); err != nil {
		msg := fmt.Sprintf("Errow row scanning: %v", err)
		handlerError(res, msg, "Player ID does not exist", http.StatusInternalServerError)
		return
	}

	//Compare passwords.
	if !utilComparePassword(user.Password, params.Password) {
		msg := ""
		handlerError(res, msg, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	var token Token
	//Access token creation.
	token.AccessToken, err = utilGenerateToken(user.PlayerID, TTL_ACCESS_TOKEN)
	if err != nil {
		msg := fmt.Sprintf("Error generating access token: %v", err)
		handlerError(res, msg, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	//Refresh token creation.
	token.RefreshToken, err = utilGenerateToken(user.PlayerID, TTL_REFRESH_TOKEN)
	if err != nil {
		msg := fmt.Sprintf("Error generating refresh token: %v", err)
		handlerError(res, msg, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	//Store refresh token in Redis.
	key := "refresh_token:" + user.PlayerID
	err = rdb.Set(context.Background(), key, token.RefreshToken, time.Second*TTL_REFRESH_TOKEN).Err()
	if err != nil {
		msg := fmt.Sprintf("Error with Redis Set: %v", err)
		handlerError(res, msg, "Failed to save to Redis", http.StatusInternalServerError)
		return
	}

	//Successful.
	handlerClientResponse(res, "User successfully created!", http.StatusOK, &token)
}

// Main
func main() {
	//Defers for clean up and panic recovery.
	defer closePostgres()
	defer closeRedis()
	//@JWK TODO: Panic recovery

	//Router multiplexer.
	//@JWK TODO: Add in rate limiting to help with DDoS.
	router := http.NewServeMux()
	router.HandleFunc("/create", handlerCreateUser)
	router.HandleFunc("/login", handlerLoginUser)
	//@JWK TODO: refresh token handler
	//@JWK TODO: verify JWT for authentication.
	//@JWK TODO: protected routes handler or something else to do once JWT is verified.

	//Port check for deployed or local.
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	url := ":" + port

	log.Printf("Server running on port: %s ...\n", port)
	log.Fatal(http.ListenAndServe(url, router))
}
