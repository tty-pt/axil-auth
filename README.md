<p align="center">
  <img src="logo.png" alt="axil-auth logo" width="220" />
</p>

# axil-auth

[![C99](https://img.shields.io/badge/C-C99-555?logo=c)](#)
[![BSD-2-Clause](https://img.shields.io/badge/License-BSD--2--Clause-blue)](#)
[![Authentication](https://img.shields.io/badge/security-auth%20%2B%20sessions-16A34A)](#)
[![axil module](https://img.shields.io/badge/module-axil-4B8BBE)](#)

> Secure session management, user registration, credential verification, and terminal access gating for [axil](https://github.com/tty-pt/axil). Canonical header is `<ttypt/auth.h>`.

---

## 1. Quickstart: Run and Verify

Start Axil with `axil-auth` loaded:

```bash
axil -d -p 8080 -m libaxil-auth
```

### Verified `curl` Walkthrough

```bash
# 1. Register an account
curl -s -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "CorrectHorseBatteryStaple!"}'

# 2. Log in and save session cookie
curl -s -i -X POST http://localhost:8080/auth/login \
  -c cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "CorrectHorseBatteryStaple!"}'

# 3. Verify session
curl -s http://localhost:8080/auth/api/session -b cookies.txt

# 4. Log out
curl -s -X POST http://localhost:8080/auth/logout -b cookies.txt
```

---

## 2. HTTP Endpoints

| Method | Endpoint | Auth | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/auth/register` | Public | Register a new user account |
| `POST` | `/auth/login` | Public | Authenticate credentials and issue session cookie |
| `GET` | `/auth/api/session` | Public | Return current authentication status and username |
| `POST` / `GET` | `/auth/logout` | Session | Invalidate current session token and clear cookie |
| `POST` / `GET` | `/auth/confirm` | Token | Confirm email or invitation token |

---

## 3. Configuration & Multi-Instance Isolation

| Variable | Default | Description |
| :--- | :--- | :--- |
| `AXIL_AUTH_COOKIE` | `QSESSION` (or `QSESSION_<port>`) | Name of the HTTP session cookie |
| `AXIL_AUTH_GID` | `67` | POSIX Group ID assigned to newly created users |
| `AXIL_AUTH_GROUP` | `www` | POSIX Group name assigned to newly created users |
| `AXIL_AUTH_DB` | `NULL` | Optional path to persistent corm session database |
| `AXIL_AUTH_SHELL` | `/bin/false` | Default login shell for newly registered accounts |

*When running multiple Axil instances simultaneously on the same host (e.g. `:8080` and `:4242`), cookies automatically scope to `QSESSION_<port>` to prevent session collisions.*

---

## 4. C API Integration

Consume authentication checks directly from other Axil modules or C daemons:

```c
#include <stdio.h>
#include <ttypt/auth.h>

void check_user(const char *user, const char *pass) {
    if (auth_password_matches(user, pass)) {
        printf("User %s authenticated successfully.\n", user);
    } else {
        printf("Invalid credentials for %s.\n", user);
    }
}
```

Compile and link:
```sh
cc my_module.c $(pkg-config --cflags --libs axil-auth) -o my_module
```

---

## 5. Installation & Build

### Prebuilt Packages
Prebuilt packages are distributed on tty.pt for Linux (APT / Alpine / Arch / Fedora-RHEL), macOS (Homebrew), Windows (winget / MSYS2), and OpenBSD. Follow the [installation instructions](https://github.com/tty-pt/ci/blob/main/docs/install.md) and use **axil-auth** as the package name.

### Build from Source
```sh
make                  # builds lib/libaxil-auth.so
make test             # run unit and authentication test suite
sudo make install     # install lib, headers, and axil-auth.pc to system
```

## License

BSD 2-Clause License. Copyright (c) 2026, tty-pt. See `LICENSE`.
