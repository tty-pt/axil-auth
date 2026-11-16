<p align="center">
  <img src="https://raw.githubusercontent.com/tty-pt/axil-auth/main/assets/logo.png" alt="@tty-pt/axil-auth logo" width="220" />
</p>

# @tty-pt/axil-auth

[![npm version](https://img.shields.io/npm/v/@tty-pt/axil-auth.svg)](https://www.npmjs.com/package/@tty-pt/axil-auth)
[![License: BSD-2-Clause](https://img.shields.io/badge/License-BSD--2--Clause-blue)](https://github.com/tty-pt/axil-auth/blob/main/LICENSE)
[![TypeScript Ready](https://img.shields.io/badge/TypeScript-Ready-3178C6?logo=typescript)](#)
[![Node.js Native](https://img.shields.io/badge/Node.js-N--API-339933?logo=node.js)](#)
[![Authentication](https://img.shields.io/badge/security-auth%20%2B%20sessions-16A34A)](#)

> Session management, user registration, credential verification, and terminal access gating for [`@tty-pt/axil`](https://www.npmjs.com/package/@tty-pt/axil). Canonical C headers: `<ttypt/auth.h>`, `<ttypt/auth-config.h>`, and `<ttypt/auth-outcome.h>`.

📖 **Full C & Systems Documentation**: See the main [**axil-auth GitHub README**](https://github.com/tty-pt/axil-auth#readme) for HTTP endpoint contracts, multi-instance cookie isolation, and C module integration.

---

## 1. Overview & Domain Concepts

`axil-auth` (`libaxil-auth.so` / `@tty-pt/axil-auth`) provides complete HTTP authentication and session lifecycle management for the `axil` web server and Node.js applications:

1. **HTTP Authentication Lifecycle**:
   - Exposes `/auth/register`, `/auth/login`, `/auth/logout`, `/auth/confirm`, and `/auth/api/session` endpoints when mounted in `axil`.
2. **Multi-Instance Session Cookie Isolation**:
   - Issues `HttpOnly; SameSite=Lax` session cookies (`QSESSION` or `QSESSION_<port>`) backed by [`libcorm`](https://github.com/tty-pt/libcorm) session tables, preventing collisions across multiple local daemon ports.
3. **Structured Outcome Codes (`<ttypt/auth-outcome.h>`)**:
   - Standardized status codes for registration, login, password updates, and token confirmation across SSR HTML forms and JSON API clients.
4. **POSIX & Terminal Gating Integration**:
   - Coordinates with [`@tty-pt/axil-tty`](https://www.npmjs.com/package/@tty-pt/axil-tty) to verify user login shells before allocating interactive PTY sessions.

---

## 2. Installation

```bash
npm install @tty-pt/axil-auth
```

**Native OS Packages (`tty.pt`)**: Prebuilt native C packages (`axil-auth`) for Linux (`apt`, `apk`, `pacman`, `dnf`), macOS (`brew`), Windows (`winget`, MSYS2), and OpenBSD (`pkg_add`) are available via the [**tty.pt package repositories**](https://github.com/tty-pt/ci/blob/main/docs/install.md).

---

## 3. Quickstart

### Launch `axil` with Authentication Enabled

```bash
npx axil -d -p 8080 -m auth
```

### Node.js Session & Credential Verification

```typescript
import {
  configure,
  initAuth,
  extractCookie,
  getSessionUser,
  verifyPassword,
  usernameTaken,
  getConfig,
  getModulePath
} from "@tty-pt/axil-auth";

// 1. Configure session TTL and directories
configure({
  cookieName: "QSESSION",
  sessionTtl: 86400,
  routePrefix: "/auth"
});
initAuth();

// 2. Extract session token from HTTP Cookie header and resolve user
const token = extractCookie("QSESSION=8f9a2b3c4d5e; Path=/");
const user = token ? getSessionUser(token) : null;
console.log("Authenticated user:", user);

// 3. Check username availability & verify password
if (usernameTaken("alice")) {
  const ok = verifyPassword("alice", "CorrectHorseBatteryStaple!");
  console.log("Password valid:", ok);
}

console.log("Active config:", getConfig());
console.log("Bundled Xylem module:", getModulePath());
```

---

## 4. JavaScript / TypeScript API Reference

- `configure(options?: Partial<AuthConfig>): boolean`: Updates authentication configuration (`cookieName`, `cookieAttrs`, `etcDir`, `usersDir`, `homeDir`, `routePrefix`, `wwwGid`, `maxSessions`, `maxUsers`, `sessionTtl`).
- `getConfig(): AuthConfig`: Returns the active authentication configuration object.
- `initAuth(): boolean`: Initializes the underlying authentication tables and storage directories.
- `extractCookie(cookieHeader: string, cookieName?: string): string | null`: Extracts the session token value from a raw HTTP `Cookie` header string.
- `getSessionUser(token: string): string | null`: Resolves an active session token to its authenticated username, or `null` if expired/invalid.
- `verifyPassword(username: string, password: string): boolean`: Verifies plaintext credentials against the stored password hash (`auth_password_matches`).
- `usernameTaken(username: string): boolean`: Returns `true` if the username is already registered.
- `getModulePath(): string | null`: Returns the filesystem path to the prebuilt `libaxil-auth` module for `axil -m`.
- `hasNativeModule(): boolean` / `getNativeAuth()`: Inspects or retrieves the loaded N-API binding.

---

## 5. C Development Headers & Native Integration

```makefile
CFLAGS += -I./node_modules/@tty-pt/axil-auth/include
LDLIBS += -laxil-auth
```

---

## License

BSD-2-Clause — Copyright (c) 2026, Paulo Quirino <quirinpa@gmail.com>. See [LICENSE](https://github.com/tty-pt/axil-auth/blob/main/LICENSE).
