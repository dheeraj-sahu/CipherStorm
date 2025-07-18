# CipherStorm API Documentation

## Overview
CipherStorm is a comprehensive fraud detection and cybersecurity platform that provides multiple services through its REST API endpoints. The platform offers various security features including text analysis, URL scanning, transaction monitoring, vishing detection, and fake customer care identification.

## Base URL
```
https://api.cipherstorm.com/
```

## Authentication
Most endpoints require authentication using JWT (JSON Web Token). Include the token in the Authorization header:
```
Authorization: Bearer <your_jwt_token>
```

## API Endpoints

### 1. Authentication (`/auth`)
#### Login
- **POST** `/auth/login`
  - Authenticates user and returns JWT token
  - **Body**: `{username: string, password: string}`
  - **Response**: `{access_token: string, token_type: string}`

#### Register
- **POST** `/auth/register`
  - Registers a new user
  - **Body**: `{username: string, email: string, password: string}`

### 2. Text Analysis (`/text`)
#### Analyze Text
- **POST** `/text/analyze`
  - Analyzes text for potential phishing content
  - **Body**: 
    ```json
    {
      "text": "string"
    }
    ```
  - **Response**: Returns analysis result including phishing probability and risk factors

#### Text History
- **GET** `/text/history`
  - Retrieves user's text analysis history
  - **Query Parameters**: `limit: int, offset: int`

### 3. URL Analysis (`/url`)
#### Scan URL
- **POST** `/url/scan`
  - Scans URL for potential threats
  - **Body**: `{url: string}`
  - **Response**: Returns security analysis including domain age, SSL status, and risk score

#### URL History
- **GET** `/url/history`
  - Retrieves user's URL scan history
  - **Query Parameters**: `limit: int, offset: int`

### 4. Transaction Monitoring (`/transaction`)
#### Process Transaction
- **POST** `/transaction/process`
  - Analyzes transaction for potential fraud
  - **Body**:
    ```json
    {
      "amount": number,
      "currency": string,
      "recipient": string,
      "description": string
    }
    ```
  - **Response**: Returns fraud probability and risk factors

#### Transaction History
- **GET** `/transaction/history`
  - Retrieves user's transaction history
  - **Query Parameters**: `limit: int, offset: int`

### 5. Profile Management (`/profile`)
#### Get Profile
- **GET** `/profile/me`
  - Retrieves user profile information

#### Update Profile
- **PUT** `/profile/update`
  - Updates user profile
  - **Body**: User profile fields

### 6. Customer Care Verification (`/customer-care`)
#### Verify Call
- **POST** `/customer-care/verify`
  - Verifies potential vishing (voice phishing) calls
  - **Body**: Call details and transcription

## Core Service Endpoints

### 1. Text Analysis (`/text/analyze`)
- **POST** `/text/analyze`
- **Description**: Advanced phishing detection in text using ML ensemble models
- **Features**:
  - Real-time analysis of suspicious text
  - Support for both API and form submissions
  - Maximum 5000 characters
- **Input**:
  ```json
  {
    "text": "string (required)"
  }
  ```
  OR Form data: `text_content=string`
- **Response**: Analysis results including:
  - Phishing probability
  - Risk factors
  - Detected patterns
  - Recommended actions

### 2. URL Analysis (`/url/scan`)
- **POST** `/url/scan`
- **Description**: Comprehensive URL security analysis
- **Features**:
  - Domain age verification
  - SSL certificate validation
  - Phishing pattern detection
  - Web traffic analysis
- **Input**:
  ```json
  {
    "url": "string (required)"
  }
  ```
- **Response**: Detailed security analysis including:
  - Risk score (0-100)
  - Feature analysis (IP address, URL length, SSL state, etc.)
  - Domain information
  - Security recommendations

### 3. Transaction Monitoring (`/transaction/process`)
- **POST** `/transaction/process`
- **Description**: Real-time fraud detection for financial transactions
- **Features**:
  - ML-based fraud detection
  - Device fingerprinting
  - Location analysis
  - Temporal pattern detection
- **Input**:
  ```json
  {
    "amount": "number (required)",
    "transaction_type": "string (P2P/P2M)",
    "payment_method": "string",
    "recipient_upi_id": "string"
  }
  ```
- **Response**:
  - Fraud probability score
  - Risk level assessment
  - Transaction safety recommendations
  - OTP verification if high risk

### 4. Vishing Detection (`/services/vishing/analyze`)
- **POST** `/services/vishing/analyze`
- **Description**: Voice phishing (vishing) call analysis
- **Features**:
  - Audio file analysis
  - Voice pattern recognition
  - Transcript analysis
  - Risk assessment
- **Input**: 
  - Multipart form data:
    - `audio_file`: WAV/MP3 file
    - `user_opinion`: "confirm_suspicious" or "insufficient_evidence"
- **Response**:
  - Risk level (high/medium/low)
  - Confidence score
  - Voice feature analysis
  - Detected suspicious patterns
  - Recommended actions

### 5. Customer Care Verification (`/customer-care/verify`)
- **POST** `/customer-care/verify`
- **Description**: Verify legitimacy of customer care numbers
- **Features**:
  - Company database verification
  - Number type analysis
  - Risk assessment
  - Historical data comparison
- **Input**:
  ```json
  {
    "company_name": "string (required)",
    "phone_number": "string (required)"
  }
  ```
- **Response**:
  - Verification status
  - Risk score
  - Number details (toll-free/landline/mobile)
  - Company verification status
  - Source verification count

### 6. Profile Management (`/profile`)
- **GET** `/profile`
  - Retrieves user profile and security settings
- **POST** `/profile`
  - Updates user profile and security preferences
- **Features**:
  - Security level customization
  - Notification preferences
  - Device management
  - Geographic restrictions

## Security and Rate Limits

Each core service endpoint has specific rate limits:
- Text Analysis: 20 requests/minute
- URL Scan: 15 requests/minute
- Transaction Process: 10 requests/minute
- Vishing Analysis: 5 requests/minute
- Customer Care Verify: 10 requests/minute

## Data Models

### User Model
```json
{
  "user_id": "integer (primary key)",
  "username": "string (unique)",
  "email": "string (unique)",
  "password_hash": "string",
  "is_verified": "boolean",
  "created_at": "datetime",
  "last_login": "datetime"
}
```

### Profile Model
```json
{
  "profile_id": "integer (primary key)",
  "user_id": "integer (foreign key)",
  "full_name": "string",
  "phone_number": "string",
  "country": "string",
  "security_level": "string (enum: low, medium, high)",
  "notification_settings": "json"
}
```

### Transaction Model
```json
{
  "transaction_id": "string(35) (primary key)",
  "user_id": "integer (foreign key)",
  "amount": "decimal(9,2)",
  "transaction_type": "string(20)",  // P2P, P2M
  "payment_instrument": "string(10)", // UPI, Card
  "payer_vpa": "string(50)",
  "beneficiary_vpa": "string(50)",
  "initiation_mode": "string(10)",
  "device_id": "string(40)",
  "ip_address": "string(20)",
  "latitude": "float",
  "longitude": "float",
  "country": "string(50)",
  "city": "string(50)",
  "day_of_week": "integer",
  "hour": "integer",
  "minute": "integer",
  "is_night": "boolean",
  "created_at": "datetime",
  "is_fraud": "boolean"
}
```

### Text Analysis Model
```json
{
  "text_id": "integer (primary key)",
  "user_id": "integer (foreign key)",
  "text": "text",
  "created_at": "datetime"
}
```

### URL Analysis Model
```json
{
  "id": "integer (primary key)",
  "user_id": "integer (foreign key)",
  "url": "string(2048)",
  "is_phishing": "boolean",
  "scanned_at": "datetime",
  "risk_score": "integer",
  "having_ip_address": "integer (-1,0,1)",
  "url_length": "integer (-1,0,1)",
  "shortening_service": "integer (-1,1)",
  "having_at_symbol": "integer (-1,1)",
  "double_slash_redirecting": "integer (-1,1)",
  "prefix_suffix": "integer (-1,1)",
  "having_sub_domain": "integer (-1,0,1)",
  "domain_registration_length": "integer (-1,1)",
  "age_of_domain": "integer (-1,1)",
  "dns_record": "integer (-1,1)",
  "web_traffic": "integer (-1,0,1)",
  "page_rank": "integer (-1,0,1)",
  "ssl_final_state": "integer (-1,0,1)"
}
```

### Customer Care Verification Model
```json
{
  "verification_id": "integer (primary key)",
  "user_id": "integer (foreign key)",
  "phone_number": "string",
  "organization": "string",
  "verification_result": "json",
  "created_at": "datetime"
}
```

## Error Responses
All endpoints may return the following error status codes:
- `400`: Bad Request - Invalid input
  ```json
  {
    "detail": "Error description",
    "code": "ERROR_CODE"
  }
  ```
- `401`: Unauthorized - Authentication required
- `403`: Forbidden - Insufficient permissions
- `404`: Not Found - Resource not found
- `422`: Validation Error - Invalid input data
- `429`: Too Many Requests - Rate limit exceeded
- `500`: Internal Server Error

### Rate Limiting
- API calls are limited to 100 requests per minute per IP
- Authentication endpoints are limited to 5 requests per minute per IP
- Scan endpoints (URL, Text) are limited to 20 requests per minute per user

## Best Practices
1. Always validate response status codes
2. Implement proper error handling
3. Use HTTPS for all API calls
4. Store and transmit tokens securely
5. Implement request retry with exponential backoff

## Support
For API support or to report issues:
- Email: support@cipherstorm.com
- Documentation Updates: https://docs.cipherstorm.com
