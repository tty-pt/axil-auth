/**
 * @file index.js
 * @brief Node.js bindings, cookie/session utilities, and Xylem module locator for @tty-pt/axil-auth.
 */

let loadNativeAddon = () => null;
let getPlatformPrebuildKeys = () => [];

if (typeof window === "undefined" && typeof process !== "undefined") {
  const candidates = [
    "@tty-pt/stele",
    new URL("../../../libstele/npm/dist/index.js", import.meta.url).href,
    new URL("../../../site/external/libstele/npm/dist/index.js", import.meta.url).href,
  ];
  for (const cand of candidates) {
    try {
      const stele = await import(cand);
      if (stele?.loadNativeAddon) {
        loadNativeAddon = stele.loadNativeAddon;
        if (typeof stele.getPlatformPrebuildKeys === "function") {
          getPlatformPrebuildKeys = stele.getPlatformPrebuildKeys;
        }
        break;
      }
    } catch {}
  }
}

const nativeBinding = loadNativeAddon ? loadNativeAddon(import.meta.url, "axil_auth") : null;

const fallbackConfig = {
  cookieName: "QSESSION",
  cookieAttrs: "; Path=/; SameSite=Lax; HttpOnly",
  etcDir: "./etc",
  usersDir: "./users",
  homeDir: "./home",
  routePrefix: "/auth",
  wwwGid: 67,
  maxSessions: 0xff,
  maxUsers: 0xffff,
  sessionTtl: 86400,
};

export function getNativeAuth() {
  return nativeBinding;
}

export function hasNativeModule() {
  if (nativeBinding && typeof nativeBinding.hasNativeModule === "function") {
    return Boolean(nativeBinding.hasNativeModule());
  }
  return getModulePath() !== null;
}

/**
 * Resolve the path to the bundled `libaxil-auth` Xylem module (without `.so`/`.dylib`/`.dll` suffix)
 * for loading into `axil -m <modulePath>`. Returns null when unavailable (e.g. browser).
 *
 * @returns {string | null}
 */
export function getModulePath() {
  if (typeof process === "undefined" || !process.versions?.node) {
    return null;
  }
  const getModule = globalThis.process?.getBuiltinModule;
  if (!getModule) return null;
  const fs = getModule("fs");
  const path = getModule("path");
  const url = getModule("url");
  const pkgRoot = path.resolve(path.dirname(url.fileURLToPath(import.meta.url)), "..");
  const keys = getPlatformPrebuildKeys();
  const dirs = [
    ...keys.map((k) => path.join(pkgRoot, "prebuilds", k)),
    path.join(pkgRoot, "build", "Release"),
    path.resolve(pkgRoot, "..", "lib"),
  ];
  for (const d of dirs) {
    const stem = path.join(d, "libaxil-auth");
    if (
      fs.existsSync(`${stem}.so`) ||
      fs.existsSync(`${stem}.dylib`) ||
      fs.existsSync(`${stem}.dll`)
    ) {
      return stem;
    }
  }
  return null;
}

export function getConfig() {
  if (nativeBinding && typeof nativeBinding.getConfig === "function") {
    return nativeBinding.getConfig();
  }
  return { ...fallbackConfig };
}

export function configure(options = {}) {
  if (!options || typeof options !== "object") {
    return false;
  }
  for (const k of Object.keys(fallbackConfig)) {
    if (options[k] !== undefined) {
      fallbackConfig[k] = options[k];
    }
  }
  if (nativeBinding && typeof nativeBinding.configure === "function") {
    return Boolean(nativeBinding.configure(options));
  }
  return true;
}

export function initAuth() {
  if (nativeBinding && typeof nativeBinding.init === "function") {
    return Boolean(nativeBinding.init());
  }
  return false;
}

function extractCookieJs(cookieHeader, name) {
  if (!cookieHeader || !name) return null;
  const parts = String(cookieHeader).split(";");
  for (const raw of parts) {
    const trimmed = raw.trim();
    if (trimmed.startsWith(`${name}=`)) {
      const val = trimmed.slice(name.length + 1).trim();
      return val || null;
    }
  }
  return null;
}

/**
 * Extract the session token from an HTTP Cookie header using `libaxil-auth` (with JS fallback).
 *
 * @param {string} cookieHeader
 * @param {string} [cookieName]
 * @returns {string | null}
 */
export function extractCookie(cookieHeader, cookieName) {
  if (!cookieHeader || typeof cookieHeader !== "string") {
    return null;
  }
  if (!cookieName && nativeBinding && typeof nativeBinding.extractCookie === "function") {
    return nativeBinding.extractCookie(cookieHeader);
  }
  const targetName = cookieName || getConfig().cookieName || "QSESSION";
  const found = extractCookieJs(cookieHeader, targetName);
  if (found) return found;
  if (!cookieName && targetName !== "QSESSION") {
    return extractCookieJs(cookieHeader, "QSESSION");
  }
  return null;
}

export function getSessionUser(token) {
  if (!token || typeof token !== "string") return null;
  if (nativeBinding && typeof nativeBinding.getSessionUser === "function") {
    return nativeBinding.getSessionUser(token);
  }
  return null;
}

export function verifyPassword(username, password) {
  if (!username || !password) return false;
  if (nativeBinding && typeof nativeBinding.verifyPassword === "function") {
    return Boolean(nativeBinding.verifyPassword(String(username), String(password)));
  }
  return false;
}

export function usernameTaken(username) {
  if (!username) return false;
  if (nativeBinding && typeof nativeBinding.usernameTaken === "function") {
    return Boolean(nativeBinding.usernameTaken(String(username)));
  }
  return false;
}
