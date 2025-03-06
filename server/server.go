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
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/jackc/pgx/v5/stdlib" //PostgresSQL drivers
	"golang.org/x/crypto/bcrypt"
)

// Consts
// @JWK TODO: Testing values, replace with proper TTL values.
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
	onceDB    sync.Once
	onceRDB   sync.Once
	jwtSecret = []byte("SECRET_KEY") //@JWK TODO: Change and Store this in ENV
)

// Runs before main(), this will initalize the resources once with connection / worker pools.
func init() {
	//@JWK TODO: Stress test this to see limitations of current configuration.
	getDB()
	getRDB()
}

// Initialize callee.
func initPostgres() {
	//PostgreSQL
	connString := "postgres://main_user:pass12345@localhost:5432/sandbox?sslmode=disable" //@JWK TODO: Store this in ENV
	db, err = sql.Open("pgx", connString)
	if err != nil {
		log.Fatalf("Error making database connection: %v", err)
	}

	//Set scaling connection pool for load distribution / concurrency.
	db.SetMaxOpenConns(20)   //Max pool size.
	db.SetMaxIdleConns(10)   //Idle pool size.
	db.SetConnMaxLifetime(0) //0, connections are not closed due to age.

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
		Password: "", //@JWK TODO: Add password
		DB:       0,
		PoolSize: 20, //Max pool size
	})

	//Check redis connection
	ctx := context.Background() //Send non-nil empty context.
	_, err = rdb.Ping(ctx).Result()
	if err != nil {
		log.Fatalf("Error pinging Redis: %v", err)
	}

	log.Println("Redis running ...")
}

// Get resource from connection pool.
func getDB() *sql.DB {
	onceDB.Do(initPostgres)
	return db
}

// Get resource from connection pool.
func getRDB() *redis.Client {
	onceRDB.Do(initRedis)
	return rdb
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
func handlerError(output bool, res http.ResponseWriter, msg string, err string, code int) {
	//Get details about where the error took place (program counter, file, line, success)
	pc, file, line, _ := runtime.Caller(1)
	fx := runtime.FuncForPC(pc)

	//Log the HTTP error.
	//@JWK TODO: Make sure this is handled properly by streaming to central log repository.
	if output {
		log.Printf("Error on %s in %s at line %d; Msg: %s", file, fx.Name(), line, msg)
	}

	//Send reponse to client.
	var token *Token = nil
	handlerClientResponse(res, err, code, token)
}

// Handler: Create user.
func handlerCreateUser(res http.ResponseWriter, req *http.Request) {
	//Check to make sure the method is POST.
	if req.Method != http.MethodPost {
		msg := fmt.Sprintf("Request method used: %s", req.Method)
		handlerError(true, res, msg, "Method not allowed", http.StatusMethodNotAllowed)
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
		handlerError(true, res, msg, "Unable to parse the client input", http.StatusBadRequest)
		return
	}

	hashedPassword, err := utilHashPassword(params.Password)
	if err != nil {
		msg := fmt.Sprintf("Error hashing password: %v", err)
		handlerError(true, res, msg, "Unable to hash password", http.StatusInternalServerError)
		return
	}

	//Grab from the connection pool.
	db := getDB()

	//Query to see if the user exists already.
	sql := "SELECT id, player_id, password FROM users where player_id = $1"
	rows, err := db.Query(sql, params.PlayerID) //Optionally use QueryRow()
	if err != nil {
		msg := fmt.Sprintf("Error executing query: %v; SQL: %s; Params: %v", err, sql, params)
		handlerError(true, res, msg, "Unable to execute query", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	if rows.Next() { //This should be false unless the player_id already exists.
		msg := ""
		handlerError(false, res, msg, "Player ID already exists", http.StatusConflict)
		return
	}

	//If not, create a new user with the information.
	sql = "INSERT INTO users (player_id, password) VALUES ($1, $2)"
	_, err = db.Exec(sql, params.PlayerID, hashedPassword)
	if err != nil {
		msg := fmt.Sprintf("Error executing query: %v; SQL: %s; Params: %s, %s", err, sql, params.PlayerID, hashedPassword)
		handlerError(true, res, msg, "Unable to execute query", http.StatusInternalServerError)
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
		handlerError(true, res, msg, "Method not allowed", http.StatusMethodNotAllowed)
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
		handlerError(true, res, msg, "Unable to parse the client input", http.StatusBadRequest)
		return
	}

	//Grab from the connection pool.
	db := getDB()

	//Query to get user information.
	sql := "SELECT id, player_id, password FROM users where player_id = $1"
	rows, err := db.Query(sql, params.PlayerID) //Optionally use QueryRow()
	if err != nil {
		msg := fmt.Sprintf("Error executing query: %v; SQL: %s; Params: %v", err, sql, params)
		handlerError(true, res, msg, "Unable to execute query", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	if !rows.Next() { //This should be true unless the player_id does not exist.
		msg := ""
		handlerError(false, res, msg, "Player ID does not exist", http.StatusConflict)
		return
	}

	var user User
	if err = rows.Scan(&user.ID, &user.PlayerID, &user.Password); err != nil {
		msg := fmt.Sprintf("Errow row scanning: %v", err)
		handlerError(true, res, msg, "Player ID does not exist", http.StatusInternalServerError)
		return
	}

	//Compare passwords.
	if !utilComparePassword(user.Password, params.Password) {
		msg := ""
		handlerError(false, res, msg, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	var token Token
	//Access token creation.
	token.AccessToken, err = utilGenerateToken(user.PlayerID, TTL_ACCESS_TOKEN)
	if err != nil {
		msg := fmt.Sprintf("Error generating access token: %v", err)
		handlerError(true, res, msg, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	//Refresh token creation.
	token.RefreshToken, err = utilGenerateToken(user.PlayerID, TTL_REFRESH_TOKEN)
	if err != nil {
		msg := fmt.Sprintf("Error generating refresh token: %v", err)
		handlerError(true, res, msg, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	//Grab from the connection pool.
	rdb := getRDB()

	//Store refresh token in Redis.
	key := "refresh_token:" + user.PlayerID
	err = rdb.Set(context.Background(), key, token.RefreshToken, time.Second*TTL_REFRESH_TOKEN).Err()
	if err != nil {
		msg := fmt.Sprintf("Error with Redis Set: %v", err)
		handlerError(true, res, msg, "Failed to save to Redis", http.StatusInternalServerError)
		return
	}

	//Successful.
	handlerClientResponse(res, "User successfully created!", http.StatusOK, &token)
}

// Protected Handler: To do something.
func pHandlerDoSomething(res http.ResponseWriter, req *http.Request) {
	//Successful.
	var token *Token = nil
	handlerClientResponse(res, "Something done!", http.StatusOK, token)
}

// Intermediary Handler: Authenticate the JWT which will allow another handler fx to be called.
func iHandlerAuthenticate(fx http.HandlerFunc) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		auth := req.Header.Get("Authorization")
		if auth == "" {
			msg := ""
			handlerError(false, res, msg, "Missing authentication token", http.StatusUnauthorized)
			return
		}

		//Grab just the token.
		sToken := strings.TrimPrefix(auth, "Bearer ")

		//Authorization wasn't formatted properly if the removal of the prefix is the same as the original.
		if sToken == auth {
			msg := ""
			handlerError(false, res, msg, "Malformed authorization request", http.StatusUnauthorized)
			return
		}

		//Parse and validate the token.  The anonymous function retuns the secret used during generation.
		token, err := jwt.Parse(sToken, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})
		if err != nil {
			msg := fmt.Sprintf("Error parsing JWT: %v", err)
			handlerError(true, res, msg, "Error parsing token", http.StatusInternalServerError)
			return
		}
		if !token.Valid {
			msg := ""
			handlerError(false, res, msg, "Invalid token", http.StatusUnauthorized)
			return
		}

		//@JWK TODO: Setup claims struct, adjust to jwt.ParseWithClaims() to extract the player id from the token and set in the request context to make it available on chained calls.

		//Success, chain next handler function (fx).
		fx(res, req)
	}
}

// Main
func main() {
	//Defers for clean up and panic recovery.
	defer closePostgres()
	defer closeRedis()
	//@JWK TODO: Panic recovery

	//Router multiplexer.
	//@JWK TODO: Add in rate limiting to help with DDoS and API request abuse.
	//@JWK TODO: Add in refresh token handler.
	router := http.NewServeMux()
	router.HandleFunc("/create", handlerCreateUser)
	router.HandleFunc("/login", handlerLoginUser)
	router.HandleFunc("/something", iHandlerAuthenticate(pHandlerDoSomething))

	//Port check for deployed or local.
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	url := ":" + port

	log.Printf("Server running on port: %s ...\n", port)
	log.Fatal(http.ListenAndServe(url, router))
}
