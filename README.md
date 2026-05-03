# ndc-auth

Authentication module for [NDC](https://github.com/tty-pt/ndc) — session management, user registration, login, and ownership helpers.

## Features

- User registration and login with bcrypt password hashing
- Session tokens via cookie
- Ownership tracking (chown when root, owner-file when not)
- Configurable via environment variables

## Configuration

| Variable         | Default    | Description              |
|------------------|------------|--------------------------|
| `NDC_AUTH_GID`   | `67`       | Group ID for new users   |
| `NDC_AUTH_GROUP` | `www`      | Group name for new users |
| `NDC_AUTH_COOKIE`| `QSESSION` | Session cookie name      |

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

Then load in your NDC module:

```c
ndx_load("ndc-auth");
```
