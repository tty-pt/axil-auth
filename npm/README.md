# @tty-pt/axil-auth

Node.js SDK, C header distribution (`<ttypt/auth.h>`, `<ttypt/auth-config.h>`, `<ttypt/auth-outcome.h>`), and prebuilt Xylem HTTP authentication module (`libaxil-auth`) for [`@tty-pt/axil`](https://www.npmjs.com/package/@tty-pt/axil).

## Usage

```js
import { getModulePath, extractCookie, getConfig, configure } from "@tty-pt/axil-auth";

const modPath = getModulePath();
const token = extractCookie(req.headers.cookie);
```

With the `axil` CLI (`@tty-pt/axil`):

```bash
npx axil -m auth
```
