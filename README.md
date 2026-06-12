# axil-auth

Authentication module for [axil](https://github.com/tty-pt/axil) — session management, user registration, login, and ownership helpers.

## Features

- User registration and login with bcrypt password hashing
- Session tokens via cookie
- Ownership tracking (chown when root, owner-file when not)
- Configurable via environment variables

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

## Install

```sh
make
sudo make install
```

Then load in your axil module:

```c
ndx_load("axil-auth");
```
