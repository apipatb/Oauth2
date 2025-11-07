# OAuth2 Authorization Server v2.0 - Golang

ระบบ OAuth2 Authorization Server เต็มรูปแบบที่พัฒนาด้วย Golang พร้อม JWT tokens, Database storage, PKCE, และ Admin Dashboard

## 🌟 Features

### Core OAuth2 Features
- ✅ **OAuth2 Authorization Code Flow** (RFC 6749)
- ✅ **OAuth2 Refresh Token Flow**
- ✅ **OAuth2 Client Credentials Flow**
- ✅ **PKCE Support** (Proof Key for Code Exchange - RFC 7636)
- ✅ **Token Revocation** (RFC 7009)

### Security Features
- ✅ **JWT-based Tokens** - Self-contained tokens with claims
- ✅ **Password Hashing** - bcrypt for secure password storage
- ✅ **Rate Limiting** - Protection against abuse
- ✅ **Token Validation** - Comprehensive token verification
- ✅ **CSRF Protection** - State parameter validation

### Storage & Database
- ✅ **Database Support** - SQLite (default) and PostgreSQL
- ✅ **Persistent Storage** - Users, clients, and auth codes
- ✅ **Auto Cleanup** - Expired tokens and codes removal

### Management Features
- ✅ **User Registration API** - Create new users programmatically
- ✅ **Client Management API** - Dynamic OAuth2 client creation
- ✅ **Admin Dashboard** - Beautiful web UI for management
- ✅ **Token Inspection** - JWT decoder in admin panel

### Web Interface
- ✅ **Test Client** - Interactive OAuth2 flow testing
- ✅ **Admin Panel** - Manage users and clients
- ✅ **Responsive Design** - Works on all devices

## 📋 Prerequisites

- Go 1.16 or higher
- Docker (optional)
- PostgreSQL (optional)

## 🚀 Quick Start

### Method 1: Run Directly

```bash
# 1. Clone and navigate to directory
cd /home/user/Oauth2

# 2. Install dependencies
go mod tidy

# 3. Run the server (uses SQLite by default)
go run main_v2.go

# 4. Access the applications
# Test Client: http://localhost:8080
# Admin Dashboard: http://localhost:8080/admin
```

### Method 2: Using Docker (SQLite)

```bash
# Build and run with SQLite
docker-compose up oauth2-server-sqlite

# Access at http://localhost:8080
```

### Method 3: Using Docker (PostgreSQL)

```bash
# Run with PostgreSQL
docker-compose --profile postgres up

# SQLite version: http://localhost:8080
# PostgreSQL version: http://localhost:8081
```

## 🔐 Demo Credentials

### OAuth2 Client
```
Client ID: demo-client-id
Client Secret: demo-client-secret
Redirect URI: http://localhost:8080/callback
```

### User Account
```
Username: demo
Password: password
Email: demo@example.com
```

## ⚙️ Configuration

Create a `.env` file or set environment variables:

```bash
# Server
SERVER_PORT=8080

# Database (sqlite or postgres)
DATABASE_TYPE=sqlite
DATABASE_URL=./oauth2.db

# For PostgreSQL:
# DATABASE_TYPE=postgres
# DATABASE_URL=postgres://user:password@localhost:5432/oauth2db?sslmode=disable

# JWT Secret (CHANGE THIS IN PRODUCTION!)
JWT_SECRET=your-secret-key-change-this-in-production

# Token Lifetimes (seconds)
ACCESS_TOKEN_LIFETIME=3600       # 1 hour
REFRESH_TOKEN_LIFETIME=2592000   # 30 days
AUTH_CODE_LIFETIME=600           # 10 minutes
```

## 📖 API Endpoints

### OAuth2 Endpoints

#### 1. Authorization Endpoint
```http
GET /oauth/authorize
```
**Parameters:**
- `response_type=code` (required)
- `client_id` (required)
- `redirect_uri` (required)
- `scope` (optional)
- `state` (recommended for CSRF protection)
- `code_challenge` (optional, for PKCE)
- `code_challenge_method` (optional, "plain" or "S256")

**Example:**
```
http://localhost:8080/oauth/authorize?response_type=code&client_id=demo-client-id&redirect_uri=http://localhost:8080/callback&scope=read%20write&state=xyz&code_challenge=abc123&code_challenge_method=S256
```

#### 2. Token Endpoint
```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded
```

**Authorization Code Grant:**
```
grant_type=authorization_code
code=<authorization_code>
client_id=<client_id>
client_secret=<client_secret>
redirect_uri=<redirect_uri>
code_verifier=<code_verifier>  # if PKCE was used
```

**Refresh Token Grant:**
```
grant_type=refresh_token
refresh_token=<refresh_token>
client_id=<client_id>
client_secret=<client_secret>
```

**Client Credentials Grant:**
```
grant_type=client_credentials
client_id=<client_id>
client_secret=<client_secret>
scope=<scope>
```

#### 3. Token Revocation Endpoint
```http
POST /oauth/revoke
Content-Type: application/x-www-form-urlencoded
```
**Parameters:**
```
token=<access_token_or_refresh_token>
token_type_hint=access_token  # or refresh_token
client_id=<client_id>
client_secret=<client_secret>
```

### Protected Resource Endpoints

#### 1. User Info (Protected)
```http
GET /api/userinfo
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "user_id": "user1",
  "client_id": "demo-client-id",
  "scope": "read write",
  "issued_at": 1699000000,
  "expires_at": 1699003600
}
```

#### 2. Protected Data (Protected)
```http
GET /api/data
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "user_id": "user1",
  "data": [
    {"id": "1", "title": "Item 1"},
    {"id": "2", "title": "Item 2"}
  ]
}
```

#### 3. Public Endpoint
```http
GET /api/public
```

### Admin Endpoints

#### 1. Register User
```http
POST /admin/user/register
Content-Type: application/json
```
**Body:**
```json
{
  "username": "newuser",
  "email": "user@example.com",
  "password": "securepassword"
}
```

**Response:**
```json
{
  "user_id": "abc123",
  "message": "User registered successfully"
}
```

#### 2. Create OAuth2 Client
```http
POST /admin/client/create
Content-Type: application/json
```
**Body:**
```json
{
  "name": "My Application",
  "redirect_uris": [
    "http://localhost:3000/callback",
    "https://myapp.com/auth/callback"
  ]
}
```

**Response:**
```json
{
  "client_id": "client_xyz789",
  "client_secret": "secret_abc123",
  "name": "My Application",
  "redirect_uris": [...],
  "message": "Client created successfully. Save the secret - it won't be shown again!"
}
```

## 🎯 OAuth2 Authorization Code Flow with PKCE

### Complete Example

#### Step 1: Generate PKCE Parameters (Client-side)
```javascript
// Generate code verifier
const codeVerifier = generateRandomString(128);

// Generate code challenge
const encoder = new TextEncoder();
const data = encoder.encode(codeVerifier);
const hash = await crypto.subtle.digest('SHA-256', data);
const codeChallenge = base64URLEncode(hash);
```

#### Step 2: Authorization Request
```
GET /oauth/authorize?
  response_type=code&
  client_id=demo-client-id&
  redirect_uri=http://localhost:8080/callback&
  scope=read%20write&
  state=random_state&
  code_challenge=<code_challenge>&
  code_challenge_method=S256
```

#### Step 3: User Authentication
User logs in and authorizes the application.

#### Step 4: Authorization Code Response
```
HTTP/1.1 302 Found
Location: http://localhost:8080/callback?code=<auth_code>&state=random_state
```

#### Step 5: Token Exchange
```bash
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=<auth_code>" \
  -d "client_id=demo-client-id" \
  -d "client_secret=demo-client-secret" \
  -d "redirect_uri=http://localhost:8080/callback" \
  -d "code_verifier=<code_verifier>"
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "scope": "read write"
}
```

#### Step 6: Access Protected Resource
```bash
curl -X GET http://localhost:8080/api/userinfo \
  -H "Authorization: Bearer <access_token>"
```

#### Step 7: Refresh Token (Optional)
```bash
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=<refresh_token>" \
  -d "client_id=demo-client-id" \
  -d "client_secret=demo-client-secret"
```

## 🧪 Testing Examples

### Using cURL

#### Test Client Credentials Flow
```bash
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=demo-client-id" \
  -d "client_secret=demo-client-secret" \
  -d "scope=read"
```

#### Create New User via API
```bash
curl -X POST http://localhost:8080/admin/user/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "password123"
  }'
```

#### Create New OAuth2 Client
```bash
curl -X POST http://localhost:8080/admin/client/create \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Application",
    "redirect_uris": ["http://localhost:3000/callback"]
  }'
```

#### Revoke Token
```bash
curl -X POST http://localhost:8080/oauth/revoke \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=<your_token>" \
  -d "token_type_hint=access_token" \
  -d "client_id=demo-client-id" \
  -d "client_secret=demo-client-secret"
```

## 📁 Project Structure

```
Oauth2/
├── main.go                 # Original main (v1)
├── main_v2.go             # New main with all features (v2)
├── go.mod                 # Go module definition
├── go.sum                 # Go dependencies
├── Dockerfile             # Docker build file
├── docker-compose.yml     # Docker compose configuration
├── .env.example          # Environment variables example
├── README.md             # Original README
├── README_V2.md          # This file (v2 README)
├── .gitignore            # Git ignore rules
│
├── config/               # Configuration
│   └── config.go         # Config loading and defaults
│
├── models/               # Data models
│   └── models.go         # OAuth2 models (User, Client, Token, etc.)
│
├── storage/              # Old storage (v1)
│   └── storage.go        # In-memory storage
│
├── database/             # New database layer (v2)
│   └── database.go       # SQLite & PostgreSQL support
│
├── jwt/                  # JWT token management
│   └── jwt.go            # JWT generation and validation
│
├── pkce/                 # PKCE implementation
│   └── pkce.go           # PKCE verification
│
├── middleware/           # HTTP middleware
│   └── ratelimit.go      # Rate limiting
│
├── auth/                 # Authorization server
│   ├── server.go         # Original server (v1)
│   └── server_v2.go      # New server with JWT & DB (v2)
│
├── resource/             # Resource server
│   ├── server.go         # Original resource server (v1)
│   └── server_v2.go      # New resource server (v2)
│
├── handlers/             # API handlers
│   ├── user.go           # User management
│   └── client.go         # Client management
│
└── static/               # Static files
    ├── index.html        # OAuth2 test client
    └── admin.html        # Admin dashboard
```

## 🐳 Docker Deployment

### Build Docker Image
```bash
docker build -t oauth2-server:v2 .
```

### Run with SQLite
```bash
docker run -d \
  -p 8080:8080 \
  -e DATABASE_TYPE=sqlite \
  -e JWT_SECRET=your-secret \
  -v $(pwd)/data:/root \
  oauth2-server:v2
```

### Run with PostgreSQL
```bash
# Start PostgreSQL first
docker-compose up -d postgres

# Then start OAuth2 server
docker-compose --profile postgres up oauth2-server-postgres
```

## 🔒 Security Best Practices

### For Production:

1. **Change JWT Secret**
   ```bash
   export JWT_SECRET=$(openssl rand -base64 32)
   ```

2. **Use HTTPS Only**
   - Deploy behind reverse proxy (nginx, Caddy)
   - Enable TLS/SSL certificates
   - Set secure cookie flags

3. **Database Security**
   - Use strong database passwords
   - Enable database encryption
   - Regular backups

4. **Rate Limiting**
   - Already implemented (10 req/s)
   - Adjust based on your needs
   - Consider using Redis for distributed rate limiting

5. **Token Lifetimes**
   - Access tokens: 15-60 minutes
   - Refresh tokens: 7-30 days
   - Auth codes: 1-10 minutes

6. **Client Secrets**
   - Generate strong secrets (32+ characters)
   - Store securely
   - Rotate regularly

7. **PKCE**
   - Required for public clients (SPAs, mobile apps)
   - Recommended for all clients

8. **Monitoring**
   - Log all authentication attempts
   - Monitor for suspicious activity
   - Set up alerts

## 🧪 Testing Checklist

- [ ] Authorization Code Flow
- [ ] Authorization Code Flow with PKCE
- [ ] Refresh Token Flow
- [ ] Client Credentials Flow
- [ ] Token Revocation
- [ ] Rate Limiting
- [ ] User Registration
- [ ] Client Creation
- [ ] JWT Token Validation
- [ ] Database Persistence
- [ ] Admin Dashboard

## 📚 Standards & Compliance

This implementation follows these RFCs:

- **RFC 6749** - OAuth 2.0 Authorization Framework
- **RFC 6750** - OAuth 2.0 Bearer Token Usage
- **RFC 7009** - OAuth 2.0 Token Revocation
- **RFC 7636** - Proof Key for Code Exchange (PKCE)
- **RFC 7519** - JSON Web Token (JWT)

## 🐛 Troubleshooting

### Database Connection Issues

**SQLite:**
```bash
# Check file permissions
ls -la oauth2.db

# Check SQLite version
sqlite3 --version
```

**PostgreSQL:**
```bash
# Test connection
psql "postgres://oauth2:oauth2password@localhost:5432/oauth2db"

# Check logs
docker logs oauth2-postgres
```

### JWT Token Issues

```bash
# Decode JWT token online: https://jwt.io
# Or use the admin dashboard decoder

# Check JWT secret is set
echo $JWT_SECRET
```

### Rate Limiting Issues

```bash
# Current limits: 10 requests/second with burst of 20
# Adjust in main_v2.go:
rateLimiter := middleware.NewRateLimiter(rate.Limit(10), 20)
```

## 🚀 Performance Tips

1. **Database Indexes** - Already created for common queries
2. **Token Cleanup** - Runs every 10 minutes automatically
3. **Rate Limiter Cleanup** - Runs with token cleanup
4. **Connection Pooling** - Built into database/sql
5. **Caching** - Consider Redis for token validation

## 📝 Migration from v1 to v2

If you're migrating from the original version:

1. **Install new dependencies:**
   ```bash
   go mod tidy
   ```

2. **Run v2:**
   ```bash
   go run main_v2.go
   ```

3. **Update client code:**
   - Tokens are now JWT format
   - Add PKCE support (recommended)
   - Update redirect URIs if needed

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📄 License

MIT License

## 👨‍💻 Author

Created with ❤️ for learning and demonstrating OAuth2 implementation in Go

## 🙏 Acknowledgments

- [RFC 6749](https://tools.ietf.org/html/rfc6749) - OAuth 2.0
- [RFC 7636](https://tools.ietf.org/html/rfc7636) - PKCE
- [golang-jwt](https://github.com/golang-jwt/jwt) - JWT library
- Go community for excellent packages

---

## 🆘 Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Check existing documentation
- Review the code examples

**Happy OAuth2-ing! 🎉**
