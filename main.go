package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/justinas/alice"
	_ "github.com/lib/pq"
	"github.com/xeipuuv/gojsonschema"
	"golang.org/x/crypto/bcrypt"
)

type App struct {
	DB     *sql.DB
	JWTKey []byte
}

type Credentials struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type UserResponse struct {
	XataID   string `json:"xata_id"`
	Username string `json:"username"`
	Token    string `json:"token,omitempty"`
}

type ErrorResponse struct {
	Message string `json:"message"`
}

type RouteMessage struct {
	Message string `json:"message"`
	ID      string `json:"id,omitempty"`
}

type Claims struct {
	Username string `json:"username"`
	XataID   string `json:"xata_id"`
	jwt.RegisteredClaims
}

func main() {

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	var loadErr error
	userSchema, loadErr := loadSchema("schemas/user.json")

	if loadErr != nil {
		log.Fatal(loadErr)
	}



	JWTKey := []byte(os.Getenv("JWT_SECRET"))
	if len(JWTKey) == 0 {
		log.Fatal("Error environment variable")
	}

	connString := os.Getenv("XATA_PSQL_URL")
	if len(connString) == 0 {
		log.Fatal("Error loading .env file")
	}

	database, err := sql.Open("postgres", connString)
	if err != nil {
		log.Fatal(err)
	}
	defer database.Close()

	app := &App{DB: database}

	router := mux.NewRouter()

	chain := alice.New(logginMiddleware).Then(router)

	userChain:= alice.New(logginMiddleware, validateMiddleware(userSchema)).Then(router)

	router.HandleFunc("/register", app.register).Methods("POST")
	router.HandleFunc("/login", app.login).Methods("POST")
	router.HandleFunc("/project", createProject).Methods("POST")
	router.HandleFunc("/project/{id}", updateProject).Methods("PUT")
	router.HandleFunc("/project/{id}", getProject).Methods("GET")
	router.HandleFunc("/projects", getProjects).Methods("GET")
	router.HandleFunc("/project/{id}", deleteProject).Methods("DELETE")

	log.Fatal(http.ListenAndServe(":8080", chain))

	log.Fatal(http.ListenAndServe(":8080", router))
}


// LoadSchema function to load schema from file
func loadSchema(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func logginMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL)
		next.ServeHTTP(w, r)
	})
}

func (app *App) jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			respondWithError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		claims := &Claims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return app.JWTKey, nil
		})

		if err != nil {
			respondWithError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		if !token.Valid {
			respondWithError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		ctx := context.WithValue(r.Context(), "claims", claims)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func validateMiddleware(schema string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body map[string]interface{}

			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				respondWithError(w, http.StatusInternalServerError, "Error reading request")
				return
			}

			err = json.Unmarshal(bodyBytes, &body)
			if err != nil {
				respondWithError(w, http.StatusBadRequest, "Invalid request")
				return
			}

			schemaLoader := gojsonschema.NewStringLoader(schema)

			documentLoader := gojsonschema.NewGoLoader(body)

			result, err := gojsonschema.Validate(schemaLoader, documentLoader)

			if err != nil {
				respondWithError(w, http.StatusInternalServerError, "Error validating JSON")
				return
			}

			if !result.Valid() {
				var errs []string
				for _, err := range result.Errors() {
					errs = append(errs, err.String())
				}
				respondWithError(w, http.StatusBadRequest, "Invalid request: "+strings.Join(errs, ", "))
			}

			r.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))

			next.ServeHTTP(w, r)

		})
	}
}

func respondWithError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(ErrorResponse{Message: message})
}

func (app *App) createToken(xataID, username string) (string, error) {
	expirationTime := time.Now().Add(5 * time.Minute)

	claims := &Claims{
		Username: username,
		XataID:   xataID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(app.JWTKey)

	if err != nil {
		return "", err
	}

	return tokenString, nil

}

// Register function to handle registration
func (app *App) register(w http.ResponseWriter, r *http.Request) {

	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)

	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error generating hash password")
		return
	}

	var xataID string
	err = app.DB.QueryRow("INSERT INTO users (username, password) VALUES ($1, $2) RETURNING xata_id", creds.Username, string(hashedPassword)).Scan(&xataID)

	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error inserting user")
		return
	}

	tokenString, err := app.createToken(xataID, creds.Username)

	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error creating token")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(UserResponse{XataID: xataID, Username: creds.Username, Token: tokenString})

}

// Login
func (app *App) login(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	var xataID string
	var storedCreds Credentials

	err = app.DB.QueryRow("SELECT xata_id, username, password FROM users WHERE username = $1", creds.Username).Scan(&xataID, &storedCreds.Username, &storedCreds.Password)

	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusUnauthorized, "Invalid username or password")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "Error querying database")
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedCreds.Password), []byte(creds.Password))
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	tokenString, err := app.createToken(xataID, creds.Username)

	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error creating token")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(UserResponse{XataID: xataID, Username: creds.Username, Token: tokenString})

}

// Create Project
func createProject(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(RouteMessage{Message: "Create Project"})
}

// Update Project
func updateProject(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(RouteMessage{Message: "Update Project", ID: params["id"]})
}

// Get Project
func getProject(w http.ResponseWriter, r *http.Request) {

	params := mux.Vars(r)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(RouteMessage{Message: "Get Project", ID: params["id"]})
}

// Get Projects
func getProjects(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(RouteMessage{Message: "Get Projects"})
}

// Delete Project
func deleteProject(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(RouteMessage{Message: "Delete Project", ID: params["id"]})
}
