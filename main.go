package main

import (
	"log"
	"net/http"
	"time"

	"golang.org/x/time/rate"

	"github.com/apipatb/oauth2-system/auth"
	"github.com/apipatb/oauth2-system/config"
	"github.com/apipatb/oauth2-system/database"
	"github.com/apipatb/oauth2-system/handlers"
	"github.com/apipatb/oauth2-system/jwt"
	"github.com/apipatb/oauth2-system/middleware"
	"github.com/apipatb/oauth2-system/resource"
)

func main() {
	// Load configuration
	cfg := config.LoadConfig()

	// Initialize database
	db, err := database.NewDatabase(cfg.DatabaseType, cfg.DatabaseURL)
	if err != nil {
		log.Fatal("Failed to initialize database:", err)
	}
	defer db.Close()

	// Initialize JWT manager
	jwtManager := jwt.NewJWTManager(cfg.JWTSecret)

	// Create servers
	authServer := auth.NewServerV2(db, jwtManager, cfg)
	resourceServer := resource.NewServerV2(authServer)

	// Create handlers
	userHandler := handlers.NewUserHandler(db)
	clientHandler := handlers.NewClientHandler(db)

	// Create rate limiter (10 requests per second with burst of 20)
	rateLimiter := middleware.NewRateLimiter(rate.Limit(10), 20)

	// Start cleanup routine for expired tokens
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			db.CleanupExpiredCodes()
			rateLimiter.Cleanup()
			log.Println("✓ Cleaned up expired codes and rate limiters")
		}
	}()

	// Setup routes
	mux := http.NewServeMux()

	// OAuth2 endpoints (with rate limiting)
	mux.Handle("/oauth/authorize", rateLimiter.Limit(http.HandlerFunc(authServer.HandleAuthorize)))
	mux.Handle("/oauth/token", rateLimiter.Limit(http.HandlerFunc(authServer.HandleToken)))
	mux.Handle("/oauth/revoke", rateLimiter.Limit(http.HandlerFunc(authServer.HandleRevoke)))

	// Protected resource endpoints
	mux.HandleFunc("/api/userinfo", resourceServer.HandleUserInfo)
	mux.HandleFunc("/api/data", resourceServer.HandleProtectedData)
	mux.HandleFunc("/api/public", resourceServer.HandlePublicEndpoint)

	// Admin endpoints
	mux.Handle("/admin/user/register", rateLimiter.Limit(http.HandlerFunc(userHandler.HandleRegister)))
	mux.Handle("/admin/client/create", rateLimiter.Limit(http.HandlerFunc(clientHandler.HandleCreateClient)))
	mux.HandleFunc("/admin/user/get", userHandler.HandleGetUser)
	mux.HandleFunc("/admin/client/get", clientHandler.HandleGetClient)

	// Client application endpoints
	mux.HandleFunc("/", serveHome)
	mux.HandleFunc("/callback", serveCallback)
	mux.HandleFunc("/admin", serveAdmin)

	// Static files
	fs := http.FileServer(http.Dir("./static"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	// Start server
	log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	log.Printf("🚀 OAuth2 Server v2.0 starting on http://localhost:%s", cfg.ServerPort)
	log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	log.Println("📋 Configuration:")
	log.Printf("   Database: %s", cfg.DatabaseType)
	log.Printf("   Port: %s", cfg.ServerPort)
	log.Println("")
	log.Println("🔐 Demo Credentials:")
	log.Println("   Client ID: demo-client-id")
	log.Println("   Client Secret: demo-client-secret")
	log.Println("   Username: demo")
	log.Println("   Password: password")
	log.Println("")
	log.Println("✨ New Features:")
	log.Println("   ✓ JWT-based tokens")
	log.Println("   ✓ Database storage (SQLite/PostgreSQL)")
	log.Println("   ✓ PKCE support")
	log.Println("   ✓ Token revocation")
	log.Println("   ✓ Rate limiting")
	log.Println("   ✓ Password hashing (bcrypt)")
	log.Println("   ✓ User registration")
	log.Println("   ✓ Client management")
	log.Println("   ✓ Admin dashboard")
	log.Println("")
	log.Println("🌐 URLs:")
	log.Printf("   Test Client: http://localhost:%s", cfg.ServerPort)
	log.Printf("   Admin Dashboard: http://localhost:%s/admin", cfg.ServerPort)
	log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	if err := http.ListenAndServe(":"+cfg.ServerPort, logRequest(mux)); err != nil {
		log.Fatal("❌ Server failed to start:", err)
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

// serveAdmin serves the admin dashboard
func serveAdmin(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./static/admin.html")
}

// logRequest logs all HTTP requests
func logRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		handler.ServeHTTP(w, r)
		log.Printf("%-7s %-30s %s", r.Method, r.URL.Path, time.Since(start))
	})
}
