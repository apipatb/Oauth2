package main

import (
	"log"
	"net/http"
	"time"

	"github.com/apipatb/oauth2-system/auth"
	"github.com/apipatb/oauth2-system/resource"
	"github.com/apipatb/oauth2-system/storage"
)

func main() {
	// Initialize storage with demo data
	store := storage.NewStorage()

	// Create OAuth2 authorization server
	authServer := auth.NewServer(store)

	// Create resource server
	resourceServer := resource.NewServer(authServer)

	// Start cleanup routine for expired tokens
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			store.CleanupExpired()
			log.Println("Cleaned up expired tokens")
		}
	}()

	// Setup routes
	mux := http.NewServeMux()

	// OAuth2 endpoints
	mux.HandleFunc("/oauth/authorize", authServer.HandleAuthorize)
	mux.HandleFunc("/oauth/token", authServer.HandleToken)

	// Protected resource endpoints
	mux.HandleFunc("/api/userinfo", resourceServer.HandleUserInfo)
	mux.HandleFunc("/api/data", resourceServer.HandleProtectedData)
	mux.HandleFunc("/api/public", resourceServer.HandlePublicEndpoint)

	// Client application endpoints
	mux.HandleFunc("/", serveHome)
	mux.HandleFunc("/callback", serveCallback)

	// Static files
	fs := http.FileServer(http.Dir("./static"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	// Start server
	port := "8080"
	log.Printf("🚀 OAuth2 Server starting on http://localhost:%s", port)
	log.Printf("📝 Demo credentials:")
	log.Printf("   Client ID: demo-client-id")
	log.Printf("   Client Secret: demo-client-secret")
	log.Printf("   Username: demo")
	log.Printf("   Password: password")
	log.Printf("\n🌐 Open http://localhost:%s in your browser to test", port)

	if err := http.ListenAndServe(":"+port, logRequest(mux)); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}

// serveHome serves the main test client page
func serveHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, "./static/index.html")
}

// serveCallback handles the OAuth2 callback
func serveCallback(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./static/index.html")
}

// logRequest logs all HTTP requests
func logRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL.Path)
		handler.ServeHTTP(w, r)
	})
}
