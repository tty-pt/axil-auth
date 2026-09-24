# axil-auth

[![C99](https://img.shields.io/badge/C-C99-555?logo=c)](#)
[![BSD-2-Clause](https://img.shields.io/badge/License-BSD--2--Clause-blue)](#)
[![sessions-and-auth](https://img.shields.io/badge/sessions-and-auth-4B8BBE)](#)

> Sessions, registration, and ownership for [axil](https://github.com/tty-pt/axil).

Authentication module for axil — session management, user registration, login,
and ownership helpers.

## Contents

- [Features](#features)
- [Install](#install)
- [Build from source](#build-from-source)
- [Configuration](#configuration)
- [HTTP Endpoints](#http-endpoints)
- [Documentation](#documentation)
- [Testing](#testing)
- [License](#license)

## Features

- User registration and login with bcrypt password hashing
- Session tokens via cookie
- Ownership tracking (chown when root, owner-file when not)
- Configurable via environment variables

## Install

Prebuilt packages are distributed on tty.pt for Linux (APT / Alpine / Arch /
Fedora-RHEL), macOS (Homebrew), Windows (winget / MSYS2), and OpenBSD.
Follow the [installation instructions](
https://github.com/tty-pt/ci/blob/main/docs/install.md) and use
**axil-auth** as the package name.

## Build from source

The module builds with a plain `make` (the shared [`mk` include.mk](
https://github.com/tty-pt/mk)):

```sh
make                  # builds lib/libaxil-auth.so
make test             # run the in-tree test suite
sudo make install     # lib + headers -> $(PREFIX), default /usr/local
```

**Dependencies:** `axil`, `libcorm`, `libxylem` (+ `libcrypt` on Linux).
There is no `axil-auth.pc`; link as an axil module with `xy_load`:

```c
xy_load("axil-auth");
```

## Configuration

| Variable         | Default    | Description              |
|------------------|------------|--------------------------|
| `AXIL_AUTH_GID`   | `67`       | Group ID for new users   |
| `AXIL_AUTH_GROUP` | `www`      | Group name for new users |
| `AXIL_AUTH_COOKIE`| `QSESSION` | Session cookie name      |

## HTTP Endpoints

| Method | Path                  | Description            |
|--------|-----------------------|------------------------|
| POST   | `/auth/login`         | Login                  |
| POST   | `/auth/register`      | Register               |
| GET    | `/auth/api/session`   | Get current username   |
| *      | `/auth/logout`        | Logout                 |
| *      | `/auth/confirm`       | Confirm registration   |

## Documentation

- [CHANGELOG.md](./CHANGELOG.md) — version history
- [include/ttypt/auth.h](./include/ttypt/auth.h) — full API

## Testing

```sh
make && ./test.sh
```

## License

BSD 2-Clause License. Copyright (c) 2026, tty-pt. See `LICENSE`.