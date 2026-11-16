/**
 * @file index.d.ts
 * @brief TypeScript definitions for @tty-pt/axil-auth.
 */

export interface AuthConfig {
  cookieName: string;
  cookieAttrs: string;
  etcDir: string;
  usersDir: string;
  homeDir: string;
  routePrefix: string;
  wwwGid: number;
  maxSessions: number;
  maxUsers: number;
  sessionTtl: number;
}

export interface AuthNativeBinding {
  hasNativeModule(): boolean;
  getConfig(): AuthConfig;
  configure(options: Partial<AuthConfig>): boolean;
  init(): boolean;
  extractCookie(cookieHeader: string): string | null;
  getSessionUser(token: string): string | null;
  verifyPassword(username: string, password: string): boolean;
  usernameTaken(username: string): boolean;
}

export declare function getNativeAuth(): AuthNativeBinding | null;
export declare function hasNativeModule(): boolean;
export declare function getModulePath(): string | null;
export declare function getConfig(): AuthConfig;
export declare function configure(options?: Partial<AuthConfig>): boolean;
export declare function initAuth(): boolean;
export declare function extractCookie(cookieHeader: string, cookieName?: string): string | null;
export declare function getSessionUser(token: string): string | null;
export declare function verifyPassword(username: string, password: string): boolean;
export declare function usernameTaken(username: string): boolean;
