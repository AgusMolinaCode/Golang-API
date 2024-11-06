package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/justinas/alice"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type App struct {
	DB *sql.DB
}

type Credentials struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type UserResponse struct {
	XataID   string `json:"xata_id"`
	Username string `json:"username"`
}

type ErrorResponse struct {
	Message string `json:"message"`
}

type RouteMessage struct {
	Message string `json:"message"`
	ID      string `json:"id,omitempty"`
}

func main() {

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
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

	router.HandleFunc("/register", register).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/project", createProject).Methods("POST")
	router.HandleFunc("/project/{id}", updateProject).Methods("PUT")
	router.HandleFunc("/project/{id}", getProject).Methods("GET")
	router.HandleFunc("/projects", getProjects).Methods("GET")
	router.HandleFunc("/project/{id}", deleteProject).Methods("DELETE")

	log.Fatal(http.ListenAndServe(":8080", chain))

	log.Fatal(http.ListenAndServe(":8080", router))
}

func logginMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL)
		next.ServeHTTP(w, r)
	})
}

func respondWithError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(ErrorResponse{Message: message})
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


}

// Login
func login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(RouteMessage{Message: "Login"})
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
