# OAuth2 Authorization Server - Golang

ระบบ OAuth2 Authorization Server ที่พัฒนาด้วย Golang พร้อม Web Interface สำหรับทดสอบ

## 🌟 Features

- ✅ OAuth2 Authorization Code Flow
- ✅ OAuth2 Refresh Token Flow
- ✅ OAuth2 Client Credentials Flow
- ✅ Token Management (Access Token & Refresh Token)
- ✅ Protected Resource Server (API)
- ✅ Web-based Test Client
- ✅ In-memory Storage
- ✅ Automatic Token Cleanup

## 📋 Prerequisites

- Go 1.16 or higher
- Web browser

## 🚀 Quick Start

### 1. Clone and Navigate

```bash
cd /home/user/Oauth2
```

### 2. Install Dependencies

```bash
go mod tidy
```

### 3. Run the Server

```bash
go run main.go
```

Server จะรันที่ `http://localhost:8080`

### 4. Test OAuth2 Flow

เปิดเว็บเบราว์เซอร์และไปที่: **http://localhost:8080**

## 🔐 Demo Credentials

### OAuth2 Client
- **Client ID:** `demo-client-id`
- **Client Secret:** `demo-client-secret`
- **Redirect URI:** `http://localhost:8080/callback`

### User Account
- **Username:** `demo`
- **Password:** `password`

## 📖 API Endpoints

### OAuth2 Endpoints

#### 1. Authorization Endpoint
```
GET /oauth/authorize
```
**Parameters:**
- `response_type=code`
- `client_id` - Client ID
- `redirect_uri` - Redirect URI
- `scope` - Requested scopes
- `state` - CSRF protection token

#### 2. Token Endpoint
```
POST /oauth/token
```
**Authorization Code Grant:**
```
grant_type=authorization_code
code=<authorization_code>
client_id=<client_id>
client_secret=<client_secret>
redirect_uri=<redirect_uri>
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

### Protected Resource Endpoints

#### 1. User Info (Protected)
```
GET /api/userinfo
Authorization: Bearer <access_token>
```

#### 2. Protected Data (Protected)
```
GET /api/data
Authorization: Bearer <access_token>
```

#### 3. Public Endpoint
```
GET /api/public
```

## 🎯 OAuth2 Authorization Code Flow

### Step-by-Step Process

1. **Start Authorization**
   - User clicks "Start OAuth2 Flow"
   - Redirects to `/oauth/authorize`

2. **User Login**
   - User enters credentials (demo/password)
   - User authorizes the application

3. **Authorization Code**
   - Server generates authorization code
   - Redirects back to client with code

4. **Token Exchange**
   - Client exchanges code for access token
   - Receives access token and refresh token

5. **Access Protected Resources**
   - Client uses access token to call APIs
   - Token is validated by resource server

6. **Refresh Token (Optional)**
   - When access token expires
   - Use refresh token to get new access token

## 📁 Project Structure

```
Oauth2/
├── main.go                 # Main application entry point
├── go.mod                  # Go module definition
├── README.md              # This file
├── .gitignore            # Git ignore rules
├── models/               # Data models
│   └── models.go         # OAuth2 models
├── storage/              # Data storage
│   └── storage.go        # In-memory storage implementation
├── auth/                 # Authorization server
│   └── server.go         # OAuth2 endpoints handler
├── resource/             # Resource server
│   └── server.go         # Protected API endpoints
└── static/               # Static files
    └── index.html        # Web test client
```

## 🧪 Testing with cURL

### 1. Get Authorization Code (via browser)
Navigate to:
```
http://localhost:8080/oauth/authorize?response_type=code&client_id=demo-client-id&redirect_uri=http://localhost:8080/callback&scope=read%20write&state=xyz
```

### 2. Exchange Code for Token
```bash
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=<your_auth_code>" \
  -d "client_id=demo-client-id" \
  -d "client_secret=demo-client-secret" \
  -d "redirect_uri=http://localhost:8080/callback"
```

### 3. Access Protected Resource
```bash
curl -X GET http://localhost:8080/api/userinfo \
  -H "Authorization: Bearer <your_access_token>"
```

### 4. Refresh Token
```bash
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=<your_refresh_token>" \
  -d "client_id=demo-client-id" \
  -d "client_secret=demo-client-secret"
```

### 5. Client Credentials Grant
```bash
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=demo-client-id" \
  -d "client_secret=demo-client-secret" \
  -d "scope=read"
```

## 🔒 Security Features

- ✅ State parameter for CSRF protection
- ✅ Authorization code expiration (10 minutes)
- ✅ Access token expiration (1 hour)
- ✅ Refresh token expiration (30 days)
- ✅ Single-use authorization codes
- ✅ Client secret validation
- ✅ Redirect URI validation
- ✅ Token cleanup for expired tokens

## ⚠️ Production Considerations

This is a **demonstration** implementation. For production use, consider:

1. **Database Storage**: Replace in-memory storage with persistent database
2. **Password Hashing**: Use bcrypt or similar for password storage
3. **HTTPS**: Always use HTTPS in production
4. **Token Storage**: Use secure token storage mechanisms
5. **Rate Limiting**: Implement rate limiting for API endpoints
6. **Logging**: Add comprehensive logging and monitoring
7. **Error Handling**: Enhance error handling and validation
8. **PKCE**: Implement PKCE for public clients
9. **Scope Management**: Implement proper scope validation
10. **Multi-tenancy**: Support for multiple clients and users

## 📚 References

- [RFC 6749 - OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [RFC 6750 - OAuth 2.0 Bearer Token Usage](https://tools.ietf.org/html/rfc6750)

## 📝 License

MIT License

## 👨‍💻 Author

Created with ❤️ for learning OAuth2 implementation in Go
