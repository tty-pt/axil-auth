import test from "node:test";
import assert from "node:assert/strict";
import {
  getConfig,
  configure,
  extractCookie,
  getSessionUser,
  verifyPassword,
  getModulePath,
  hasNativeModule,
} from "../dist/index.js";

test("axil-auth configuration and cookie extraction", () => {
  const cfg = getConfig();
  assert.equal(cfg.cookieName, "QSESSION");
  assert.equal(cfg.routePrefix, "/auth");

  assert.equal(extractCookie("foo=bar; QSESSION=tok123; baz=qux"), "tok123");
  assert.equal(extractCookie("QSESSION=abc999"), "abc999");
  assert.equal(extractCookie("foo=bar"), null);
  assert.equal(extractCookie(""), null);

  assert.equal(configure({ cookieName: "CUSTOM_SID" }), true);
  assert.equal(getConfig().cookieName, "CUSTOM_SID");
  assert.equal(extractCookie("CUSTOM_SID=s777"), "s777");
  // Fallback to QSESSION still works when custom cookie is configured
  assert.equal(extractCookie("QSESSION=legacy888"), "legacy888");

  // Restore default
  configure({ cookieName: "QSESSION" });
  assert.equal(getConfig().cookieName, "QSESSION");
});

test("axil-auth module path resolution and safe native fallbacks", () => {
  assert.equal(getSessionUser(""), null);
  assert.equal(verifyPassword("", ""), false);

  if (process.platform !== "win32") {
    const modPath = getModulePath();
    assert.ok(modPath && modPath.includes("libaxil-auth"), `expected libaxil-auth module path, got ${modPath}`);
    assert.equal(hasNativeModule(), true);
  }
});
