# Security Deployment Guide

This document outlines security configurations and headers required for any future web or API interfaces for Sentra.

## Recommended HTTP Headers

When deploying Sentra as a web service, ensure the following HTTP headers are configured in your web server (Nginx, Apache) or application framework.

### 1. Strict-Transport-Security (HSTS)
Enforces HTTPS connections.
```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

### 2. Content-Security-Policy (CSP)
Prevents XSS/Injection attacks. Adjust `script-src` as needed for your specific frontend framework.
```
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';
```

### 3. X-Content-Type-Options
Prevents MIME-sniffing.
```
X-Content-Type-Options: nosniff
```

### 4. X-Frame-Options
Prevents Clickjacking.
```
X-Frame-Options: DENY
```

### 5. Referrer-Policy
Controls how much referrer information is sent.
```
Referrer-Policy: strict-origin-when-cross-origin
```

### 6. Permissions-Policy
Restricts browser features.
```
Permissions-Policy: ch-ua-form-factor=(), geolocation=(), microphone=(), camera=(), payment=()
```

## Cookie Security
If using cookies for session management:
- **Secure**: Only send over HTTPS.
- **HttpOnly**: Prevent access via JavaScript.
- **SameSite**: Set to `Strict` or `Lax`.
