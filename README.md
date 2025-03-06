# Golang Authentication

## Introduction

This project is a sandbox RESTful API built with Go that handles user authentication using JSON Web Tokens (JWT). It ensures secure user registration, login, and access to protected resources.  Playing around with different methods, ideas and such to test out.

## Features

- User registration with hashed passwords
- User login with JWT issuance
- Middleware for protected routes
- Token-based authentication

## Getting Started

### Prerequisites

- [Go](https://golang.org/doc/install) (version 1.16 or higher)

### Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/jeremykofoed/golang-authentication.git
   cd golang-authentication
   ```

2. **Install dependencies:**

   ```bash
   go mod tidy
   ```

### Running the Application

  ```bash
  go run server/server.go
  go run client/client.go
  ```

## API Endpoints

- **`POST /create`**: Register a new user.
- **`POST /login`**: Authenticate a user and return a JWT.
- **`GET /something`**: Access a protected route (requires JWT).

### Example Requests

#### Register a user

```bash
curl -X POST http://localhost:8080/create -H "Content-Type: application/json" -d '{"player_id": "test1234", "password": "password123"}'
```

#### Login

```bash
curl -X POST http://localhost:8080/login -H "Content-Type: application/json" -d '{"player_id": "test1234", "password": "password123"}'
```

#### Access protected route

```bash
curl -X GET http://localhost:8080/protected -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## Project Structure

```
golang-authentication/
├── client/
│   ├── client.go
│   └── ...
├── server/
│   ├── server.go
│   └── ...
├── go.mod
├── go.sum
└── README.md
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
