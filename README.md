<p align="center">
  <img src="logo.png" alt="axil-auth logo" width="220" />
</p>

# axil-auth

[![C99](https://img.shields.io/badge/C-C99-555?logo=c)](#)
[![BSD-2-Clause](https://img.shields.io/badge/License-BSD--2--Clause-blue)](#)
[![Authentication](https://img.shields.io/badge/security-auth%20%2B%20sessions-16A34A)](#)
[![axil module](https://img.shields.io/badge/module-axil-4B8BBE)](#)

> Secure session management, user registration, credential verification, and terminal access gating for [axil](https://github.com/tty-pt/axil).

`axil-auth` is the canonical authentication and session security module for the axil web server. It provides bcrypt-hashed user accounts, cookie-based session tracking (`QSESSION`), CSRF token verification, resource ownership tracking, and fail-closed shell gating for interactive services like [axil-tty](https://github.com/tty-pt/axil-tty).

---

## Contents

- [Architecture & Security Model](#architecture--security-model)
- [Features](#features)
- [Quickstart: Run and Verify](#quickstart-run-and-verify)
- [HTTP Endpoints](#http-endpoints)
- [Configuration Reference](#configuration-reference)
- [C API Integration](#c-api-integration)
- [Terminal Access Gating](#terminal-access-gating)
- [Installation & Build](#installation--build)
- [License](#license)

---

## Architecture & Security Model

`axil-auth` mounts into Axil's request lifecycle via [libxylem](https://github.com/tty-pt/libxylem):

- **In-Memory Session Store**: Tracks active session tokens in high-throughput [libcorm](https://github.com/tty-pt/libcorm) maps with automatic expiry and O(1) retrieval.
- **Credential Storage**: Uses standard `/etc/passwd` (or sandboxed chroot shadow files) with bcrypt hashing (`libcrypt`).
- **Clean Header Split**: Public types and configuration are separated into `<ttypt/auth-config.h>`, while outcome callbacks and verification primitives reside in `<ttypt/auth-outcome.h>` and `<ttypt/auth.h>`.
- **Fail-Closed Terminal Gating**: Enforces `/bin/false` as the default shell for web-registered users, preventing unauthorized interactive terminal or shell spawning over WebSockets.

---

## Features

- **Bcrypt Password Security**: Robust password verification and hashing without third-party crypto bloat.
- **Session Tokens via Cookie**: Configurable session cookie (`QSESSION` by default) with `SameSite=Lax` and `HttpOnly` flags.
- **Programmatic Credential Verification**: Exports `auth_password_matches()` for custom auth hooks and zero-copy credential checks.
- **Resource Ownership Tracking**: Automatically enforces file ownership (`chown` when running privileged, or metadata files when unprivileged).
- **CSRF Token Generation & Validation**: Issues session-bound CSRF tokens to protect state-mutating endpoints (`POST`, `PUT`, `DELETE`).

---

## Quickstart: Run and Verify

Start Axil with `axil-auth` loaded:

```bash
axil -d -p 8080 -m libaxil-auth
```

### Verified `curl` Walkthrough

#### 1. Register a User Account
```bash
curl -s -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "CorrectHorseBatteryStaple!"
  }'
```

#### 2. Log In & Capture Session Cookie
```bash
curl -s -i -X POST http://localhost:8080/auth/login \
  -c cookies.txt \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "CorrectHorseBatteryStaple!"
  }'
```

#### 3. Inspect Active Session
```bash
curl -s http://localhost:8080/auth/api/session -b cookies.txt
```

**Response**:
```json
{
  "authenticated": true,
  "username": "alice",
  "csrf_token": "a1b2c3d4e5f6..."
}
```

#### 4. Log Out
```bash
curl -s -X POST http://localhost:8080/auth/logout -b cookies.txt
```

---

## HTTP Endpoints

| Method | Endpoint | Auth | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/auth/register` | Public | Register a new user account |
| `POST` | `/auth/login` | Public | Authenticate credentials and issue session cookie |
| `GET` | `/auth/api/session` | Public | Return current authentication status and username |
| `POST` / `GET` | `/auth/logout` | Session | Invalidate current session token and clear cookie |
| `POST` / `GET` | `/auth/confirm` | Token | Confirm email or invitation token |

---

## Configuration Reference

Configure behavior using environment variables:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `AXIL_AUTH_COOKIE` | `QSESSION` | Name of the HTTP session cookie |
| `AXIL_AUTH_GID` | `67` | POSIX Group ID assigned to newly created users |
| `AXIL_AUTH_GROUP` | `www` | POSIX Group name assigned to newly created users |
| `AXIL_AUTH_DB` | `NULL` | Optional path to persistent corm session database |
| `AXIL_AUTH_SHELL` | `/bin/false` | Default login shell for newly registered accounts |

---

## C API Integration

Consume authentication checks directly from other Axil modules or C daemons:

```c
#include <stdio.h>
#include <ttypt/auth.h>
#include <ttypt/auth-config.h>

void check_user(const char *user, const char *pass) {
    if (auth_password_matches(user, pass)) {
        printf("User %s authenticated successfully.\n", user);
    } else {
        printf("Invalid credentials for %s.\n", user);
    }
}
```

Link against `axil-auth`:
```sh
cc my_module.c $(pkg-config --cflags --libs axil-auth)
```

---

## Terminal Access Gating

When deploying interactive services like [axil-tty](https://github.com/tty-pt/axil-tty), security requires that web-registered users cannot spawn arbitrary shell processes over WebSockets. `axil-auth` enforces:

1. **Restricted Shell Default**: Web registration assigns `/bin/false` (or `AXIL_AUTH_SHELL`).
2. **Interactive Gating**: `axil-tty` checks the user's login shell via `getpwnam()`; if set to `/bin/false` or `nologin`, WebSocket PTY spawning fails closed with HTTP 403 Forbidden.
3. **Privileged Terminal Elevation**: Only system accounts provisioned with a valid shell (e.g. `/bin/sh` or `/bin/bash`) can establish interactive terminal sessions.

---

## Installation & Build

### Prebuilt Packages
Prebuilt packages are distributed on tty.pt for Linux (APT / Alpine / Arch / Fedora-RHEL), macOS (Homebrew), Windows (winget / MSYS2), and OpenBSD. Follow the [installation instructions](https://github.com/tty-pt/ci/blob/main/docs/install.md) and use **axil-auth** as the package name.

### Build from Source
```sh
make                  # builds lib/libaxil-auth.so
make test             # run unit and authentication test suite
sudo make install     # install lib, headers, and axil-auth.pc to $(PREFIX)
```

**Dependencies:** `axil`, `libcorm`, `libxylem` (+ `libcrypt` on Linux).

---

## License

BSD 2-Clause License. Copyright (c) 2026, tty-pt. See `LICENSE`.
