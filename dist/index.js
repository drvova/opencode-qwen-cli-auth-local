/**
 * Qwen OAuth authentication plugin for OpenCode
 *
 * Architecture follows OpenCode's Copilot/Codex plugin pattern:
 * - auth.loader returns { fetch, apiKey, baseURL, timeout }
 * - Custom fetch handles DashScope headers and token refresh
 * - OpenCode handles timeout, retries, and streaming natively
 *
 * @version 3.0.0
 */
import { createPKCE, requestDeviceCode, pollForToken, getApiBaseUrl, saveToken, refreshAccessToken, loadStoredToken, getValidToken, upsertOAuthAccount, getActiveOAuthAccount, markOAuthAccountQuotaExhausted, switchToNextHealthyOAuthAccount, } from "./lib/auth/auth.js";
import { openBrowserUrl } from "./lib/auth/browser.js";
import { PROVIDER_ID, AUTH_LABELS, DEVICE_FLOW, PORTAL_HEADERS, TOKEN_REFRESH_BUFFER_MS, } from "./lib/constants.js";
import { logInfo, logWarn, LOGGING_ENABLED } from "./lib/logger.js";
import { readFileSync, writeFileSync, existsSync, mkdirSync, renameSync, unlinkSync } from "fs";
import { dirname } from "path";
// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const QWEN_CLI_VERSION = "0.13.1";
const PLUGIN_USER_AGENT = `QwenCode/${QWEN_CLI_VERSION} (${process.platform}; ${process.arch})`;
const MAX_CONSECUTIVE_POLL_FAILURES = 3;
const CHAT_MAX_TOKENS_CAP = 65536;
const LOAD_BALANCE_DEFAULT = process.env.OPENCODE_QWEN_LOAD_BALANCE !== "0";
const LOAD_BALANCE_PRESET_DEFAULT = process.env.OPENCODE_QWEN_LB_PRESET === "round_robin"
    ? "round_robin"
    : "cache_friendly";
const LOAD_BALANCE_SETTINGS_PATH = `${process.env.HOME || ""}/.qwen/opencode_qwen_settings.json`;
const LOAD_BALANCE_CACHE_TTL_MS = 5000;
const LOAD_BALANCE_STICKY_MS_DEFAULT = 90_000;
const LOAD_BALANCE_STICKY_MS_MAX = 10 * 60 * 1000;
const LOAD_BALANCE_STICKY_REQUESTS_DEFAULT = 8;
const LOAD_BALANCE_STICKY_REQUESTS_MAX = 128;
const QUOTA_STATS_PATH = `${process.env.HOME || ""}/.qwen/opencode_qwen_quota_stats.json`;
const QUOTA_DAY_LIMIT = 1000;
const QUOTA_MINUTE_LIMIT = 60;
const QUOTA_STATS_WINDOW_DAY_MS = 24 * 60 * 60 * 1000;
const QUOTA_STATS_WINDOW_MINUTE_MS = 60 * 1000;
const QUOTA_STATS_CACHE_TTL_MS = 3000;
/** In-memory token cache to reduce Disk I/O per request (Issue 3.0) */
const TOKEN_CACHE_TTL_MS = 10_000; // 10 seconds
let cachedAccountResponse = null;
let cachedAccountResponseExpiry = 0;
let loadBalanceConfigCache = {
    enabled: LOAD_BALANCE_DEFAULT,
    preset: LOAD_BALANCE_PRESET_DEFAULT,
    stickyMs: LOAD_BALANCE_STICKY_MS_DEFAULT,
    stickyRequests: LOAD_BALANCE_STICKY_REQUESTS_DEFAULT,
};
let loadBalanceConfigCacheExpiry = 0;
let stickyAccountId = null;
let stickyAccountExpiry = 0;
let stickyAccountRequestsLeft = 0;
let quotaStatsCache = null;
let quotaStatsCacheExpiry = 0;
// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function dayStartAt(ts) {
    const d = new Date(ts);
    d.setHours(0, 0, 0, 0);
    return d.getTime();
}
function normalizeQuotaStats(raw) {
    const source = typeof raw === "object" && raw !== null ? raw : {};
    const srcAccounts = typeof source.accounts === "object" && source.accounts !== null
        ? source.accounts
        : {};
    const accounts = {};
    for (const [accountId, value] of Object.entries(srcAccounts)) {
        if (typeof accountId !== "string" || !accountId)
            continue;
        const obj = typeof value === "object" && value !== null ? value : {};
        const now = Date.now();
        const dayStart = typeof obj.dayStart === "number" ? obj.dayStart : dayStartAt(now);
        const minuteWindowStart = typeof obj.minuteWindowStart === "number" ? obj.minuteWindowStart : now;
        accounts[accountId] = {
            dayStart,
            dayCount: typeof obj.dayCount === "number" ? Math.max(0, Math.floor(obj.dayCount)) : 0,
            minuteWindowStart,
            minuteCount: typeof obj.minuteCount === "number" ? Math.max(0, Math.floor(obj.minuteCount)) : 0,
            lastRequestAt: typeof obj.lastRequestAt === "number" ? obj.lastRequestAt : 0,
            lastStatus: typeof obj.lastStatus === "number" ? obj.lastStatus : 0,
        };
    }
    return {
        version: 1,
        dayLimit: QUOTA_DAY_LIMIT,
        minuteLimit: QUOTA_MINUTE_LIMIT,
        accounts,
    };
}
function readQuotaStats() {
    const now = Date.now();
    if (quotaStatsCache && now < quotaStatsCacheExpiry) {
        return quotaStatsCache;
    }
    try {
        const raw = readFileSync(QUOTA_STATS_PATH, "utf-8");
        quotaStatsCache = normalizeQuotaStats(JSON.parse(raw));
    }
    catch {
        quotaStatsCache = normalizeQuotaStats(null);
    }
    quotaStatsCacheExpiry = now + QUOTA_STATS_CACHE_TTL_MS;
    return quotaStatsCache;
}
function writeQuotaStats(stats) {
    const data = normalizeQuotaStats(stats);
    const targetDir = dirname(QUOTA_STATS_PATH);
    let tempPath = null;
    try {
        if (!existsSync(targetDir)) {
            mkdirSync(targetDir, { recursive: true, mode: 0o700 });
        }
        tempPath = `${QUOTA_STATS_PATH}.tmp.${Date.now().toString(36)}-${Math.random().toString(16).slice(2)}`;
        writeFileSync(tempPath, `${JSON.stringify(data, null, 2)}\n`, {
            encoding: "utf-8",
            mode: 0o600,
        });
        renameSync(tempPath, QUOTA_STATS_PATH);
    }
    catch {
        try {
            if (tempPath && existsSync(tempPath)) {
                unlinkSync(tempPath);
            }
        }
        catch {
        }
    }
    quotaStatsCache = data;
    quotaStatsCacheExpiry = Date.now() + QUOTA_STATS_CACHE_TTL_MS;
}
function mutateQuotaStats(accountId, mutator) {
    if (!accountId)
        return;
    const stats = readQuotaStats();
    const now = Date.now();
    const entry = stats.accounts[accountId] || {
        dayStart: dayStartAt(now),
        dayCount: 0,
        minuteWindowStart: now,
        minuteCount: 0,
        lastRequestAt: 0,
        lastStatus: 0,
    };
    const currentDayStart = dayStartAt(now);
    if (entry.dayStart !== currentDayStart) {
        entry.dayStart = currentDayStart;
        entry.dayCount = 0;
    }
    if (now - entry.minuteWindowStart >= QUOTA_STATS_WINDOW_MINUTE_MS) {
        entry.minuteWindowStart = now;
        entry.minuteCount = 0;
    }
    mutator(entry, now);
    stats.accounts[accountId] = entry;
    writeQuotaStats(stats);
}
function recordQuotaRequest(accountId) {
    mutateQuotaStats(accountId, (entry, now) => {
        entry.dayCount += 1;
        entry.minuteCount += 1;
        entry.lastRequestAt = now;
    });
}
function recordQuotaStatus(accountId, status) {
    if (typeof status !== "number")
        return;
    mutateQuotaStats(accountId, (entry) => {
        entry.lastStatus = status;
    });
}
function normalizePreset(value) {
    return value === "round_robin" ? "round_robin" : "cache_friendly";
}
function normalizeInt(value, fallback, min, max) {
    const num = typeof value === "number" ? value : Number(value);
    if (!Number.isFinite(num))
        return fallback;
    const n = Math.floor(num);
    if (n < min)
        return min;
    if (n > max)
        return max;
    return n;
}
function getLoadBalanceConfig() {
    const now = Date.now();
    if (now < loadBalanceConfigCacheExpiry) {
        return loadBalanceConfigCache;
    }
    loadBalanceConfigCacheExpiry = now + LOAD_BALANCE_CACHE_TTL_MS;
    const next = {
        enabled: LOAD_BALANCE_DEFAULT,
        preset: LOAD_BALANCE_PRESET_DEFAULT,
        stickyMs: LOAD_BALANCE_STICKY_MS_DEFAULT,
        stickyRequests: LOAD_BALANCE_STICKY_REQUESTS_DEFAULT,
    };
    try {
        const raw = readFileSync(LOAD_BALANCE_SETTINGS_PATH, "utf-8");
        const parsed = JSON.parse(raw);
        if (typeof parsed?.loadBalance === "boolean") {
            next.enabled = parsed.loadBalance;
        }
        next.preset = normalizePreset(parsed?.lbPreset);
        next.stickyMs = normalizeInt(parsed?.stickyMs, LOAD_BALANCE_STICKY_MS_DEFAULT, 10_000, LOAD_BALANCE_STICKY_MS_MAX);
        next.stickyRequests = normalizeInt(parsed?.stickyRequests, LOAD_BALANCE_STICKY_REQUESTS_DEFAULT, 1, LOAD_BALANCE_STICKY_REQUESTS_MAX);
    }
    catch {
    }
    loadBalanceConfigCache = next;
    return loadBalanceConfigCache;
}
function clearStickyAccount() {
    stickyAccountId = null;
    stickyAccountExpiry = 0;
    stickyAccountRequestsLeft = 0;
}
function pinStickyAccount(accountId, config, now = Date.now()) {
    if (!accountId || config.preset !== "cache_friendly") {
        clearStickyAccount();
        return;
    }
    stickyAccountId = accountId;
    stickyAccountExpiry = now + config.stickyMs;
    stickyAccountRequestsLeft = Math.max(config.stickyRequests - 1, 0);
}
function canUseStickyAccount(now = Date.now()) {
    return !!stickyAccountId && now < stickyAccountExpiry && stickyAccountRequestsLeft > 0;
}
function consumeStickyAccount(accountId, now = Date.now()) {
    if (accountId && stickyAccountId === accountId && now < stickyAccountExpiry && stickyAccountRequestsLeft > 0) {
        stickyAccountRequestsLeft -= 1;
    }
}
function getBaseUrl(resourceUrl) {
    if (typeof resourceUrl === "string" && resourceUrl.length > 0) {
        return getApiBaseUrl(resourceUrl);
    }
    try {
        const stored = loadStoredToken();
        if (stored?.resource_url)
            return getApiBaseUrl(stored.resource_url);
    }
    catch {
        // ignore — use default
    }
    return getApiBaseUrl();
}
/**
 * Resolve a valid access token from multi-account store, disk, or SDK state.
 */
async function getValidAccessToken(getAuth) {
    // 1) Multi-account store
    const active = await getActiveOAuthAccount({ allowExhausted: false });
    if (active?.accessToken) {
        return {
            accessToken: active.accessToken,
            resourceUrl: active.resourceUrl,
            accountId: active.accountId,
        };
    }
    // 2) Disk token (~/.qwen/oauth_creds.json)
    const disk = await getValidToken();
    if (disk?.accessToken) {
        return { accessToken: disk.accessToken, resourceUrl: disk.resourceUrl };
    }
    // 3) SDK auth state
    const auth = await getAuth();
    if (!auth || auth.type !== "oauth")
        return null;
    let accessToken = auth.access;
    let resourceUrl;
    if (accessToken &&
        auth.expires &&
        Date.now() > auth.expires - TOKEN_REFRESH_BUFFER_MS &&
        auth.refresh) {
        try {
            const r = await refreshAccessToken(auth.refresh);
            if (r.type === "success") {
                accessToken = r.access;
                resourceUrl = r.resourceUrl;
                saveToken(r);
                await upsertOAuthAccount(r, { setActive: false });
                // Fix 1.1: Return early to prevent bootstrap block from overwriting
                // the freshly refreshed token with stale SDK auth state
                return { accessToken, resourceUrl };
            }
            else {
                accessToken = undefined;
            }
        }
        catch {
            accessToken = undefined;
        }
    }
    // Bootstrap to disk for future use
    if (auth.access && auth.refresh) {
        try {
            const t = {
                type: "success",
                access: accessToken || auth.access,
                refresh: auth.refresh,
                expires: typeof auth.expires === "number"
                    ? auth.expires
                    : Date.now() + 3600_000,
                resourceUrl,
            };
            saveToken(t);
            await upsertOAuthAccount(t, { setActive: false });
        }
        catch {
            // non-fatal
        }
    }
    return accessToken ? { accessToken, resourceUrl } : null;
}
/**
 * Set required DashScope headers on a Headers object.
 * Matches qwen-code DashScopeOpenAICompatibleProvider.buildHeaders().
 */
function applyDashScopeHeaders(h) {
    if (!h.has("X-DashScope-AuthType"))
        h.set("X-DashScope-AuthType", PORTAL_HEADERS.AUTH_TYPE_VALUE);
    if (!h.has("X-DashScope-CacheControl"))
        h.set("X-DashScope-CacheControl", "enable");
    if (!h.has("User-Agent"))
        h.set("User-Agent", PLUGIN_USER_AGENT);
    if (!h.has("X-DashScope-UserAgent"))
        h.set("X-DashScope-UserAgent", PLUGIN_USER_AGENT);
}
async function pollDeviceFlow(deviceAuth, verifier, onSuccess) {
    let interval = (deviceAuth.interval || 5) * 1000;
    const margin = 3000;
    const maxInterval = DEVICE_FLOW.MAX_POLL_INTERVAL;
    const deadline = Date.now() + deviceAuth.expires_in * 1000;
    let failures = 0;
    while (Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, interval + margin));
        const r = await pollForToken(deviceAuth.device_code, verifier);
        if (r.type === "success") {
            await onSuccess(r);
            return {
                type: "success",
                access: r.access,
                refresh: r.refresh,
                expires: r.expires,
            };
        }
        if (r.type === "slow_down") {
            failures = 0;
            interval = Math.min(interval + 5000, maxInterval);
            continue;
        }
        if (r.type === "pending") {
            failures = 0;
            continue;
        }
        if (r.type === "failed" && !r.fatal) {
            failures += 1;
            if (failures >= MAX_CONSECUTIVE_POLL_FAILURES)
                break;
            continue;
        }
        break; // denied, expired, fatal, or unknown
    }
    return { type: "failed" };
}
// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------
export const QwenAuthPlugin = async () => ({
    // ---- auth ----------------------------------------------------------------
    auth: {
        provider: PROVIDER_ID,
        /**
         * Called by OpenCode during provider initialization (provider.ts ~line 937).
         * Returns options merged into the AI-SDK provider constructor.
         *
         * Pattern identical to Copilot / Codex plugins:
         *   - apiKey for SDK constructor validation
         *   - custom fetch for auth + headers
         *   - timeout: false so OpenCode's own timeout wrapper is the only guard
         *
         * OpenCode wraps our fetch with its own timeout logic in getSDK():
         *   options["fetch"] = (input, init) => {
         *     if (options["timeout"] !== false) signals.push(AbortSignal.timeout(...))
         *     return customFetch(input, { ...init, timeout: false })
         *   }
         *
         * By returning timeout: false, we ensure NO AbortSignal.timeout is added.
         * OpenCode's streamText() passes abortSignal from the session — that's
         * the only cancellation mechanism, which is correct.
         */
        async loader(getAuth, provider) {
            // Zero cost for free OAuth models
            if (provider?.models) {
                for (const m of Object.values(provider.models)) {
                    if (m)
                        m.cost = {
                            input: 0,
                            output: 0,
                        };
                }
            }
            const token = await getValidAccessToken(getAuth);
            if (!token?.accessToken)
                return {};
            const baseURL = getBaseUrl(token.resourceUrl);
            if (LOGGING_ENABLED)
                logInfo("loader baseURL:", baseURL);
            return {
                apiKey: token.accessToken,
                baseURL,
                timeout: false,
                /**
                 * Custom fetch — innermost layer in OpenCode's fetch chain.
                 *
                 * Call chain:
                 *   AI SDK → streamText headers → OpenCode getSDK() wrapper → THIS → global fetch
                 *
                 * We handle:
                 *   1. DashScope-specific headers (like qwen-code CLI)
                 *   2. Fresh Authorization header (token may expire between turns)
                 *   3. 401 → token refresh + single retry
                 *   4. 429 insufficient_quota → account switch + single retry
                 *
                 * We do NOT handle:
                 *   - Timeout (OpenCode's getSDK wrapper handles via AbortSignal)
                 *   - Retries (AI SDK maxRetries handles, OpenCode sets maxRetries: 0)
                 *   - Streaming (OpenCode/AI SDK handle natively)
                 *   - Payload sanitization (not needed — AI SDK builds clean payloads)
                 */
                async fetch(input, init) {
                    const opts = init ? { ...init } : {};
                    // -- Headers --
                    const headers = new Headers(opts.headers);
                    applyDashScopeHeaders(headers);
                    const lb = getLoadBalanceConfig();
                    const now = Date.now();
                    // Per-request round-robin across healthy accounts.
                    let fresh = null;
                    if (lb.enabled && lb.preset === "cache_friendly" && canUseStickyAccount(now)) {
                        fresh = await getActiveOAuthAccount({
                            preferredAccountId: stickyAccountId,
                            allowExhausted: false,
                        });
                        if (fresh?.accountId === stickyAccountId) {
                            consumeStickyAccount(stickyAccountId, now);
                        }
                        else {
                            clearStickyAccount();
                        }
                    }
                    if (!fresh && lb.enabled) {
                        fresh = await switchToNextHealthyOAuthAccount();
                        if (!fresh) {
                            fresh = await getActiveOAuthAccount({
                                allowExhausted: false,
                            });
                        }
                        if (fresh?.accountId) {
                            pinStickyAccount(fresh.accountId, lb, now);
                        }
                        else {
                            clearStickyAccount();
                        }
                        cachedAccountResponse = fresh;
                        cachedAccountResponseExpiry = Date.now() + TOKEN_CACHE_TTL_MS;
                    }
                    else if (cachedAccountResponse && Date.now() < cachedAccountResponseExpiry) {
                        fresh = cachedAccountResponse;
                    }
                    else {
                        fresh = await getActiveOAuthAccount({
                            allowExhausted: false,
                        });
                        cachedAccountResponse = fresh;
                        cachedAccountResponseExpiry = Date.now() + TOKEN_CACHE_TTL_MS;
                    }
                    // Fix 1.2: Track the current account ID dynamically for 429 handling
                    const currentAccountId = fresh?.accountId || null;
                    if (fresh?.accessToken) {
                        headers.set("Authorization", `Bearer ${fresh.accessToken}`);
                        if (currentAccountId) {
                            recordQuotaRequest(currentAccountId);
                        }
                    }
                    opts.headers = headers;
                    // -- Request --
                    let response = await globalThis.fetch(input, opts);
                    if (currentAccountId) {
                        recordQuotaStatus(currentAccountId, response.status);
                    }
                    // -- 401: token expired mid-session --
                    if (response.status === 401) {
                        const body = await response.text().catch(() => ""); // consume body
                        if (LOGGING_ENABLED)
                            logWarn("401 — refreshing token");
                        try {
                            // Fix 2.2: Mark current account as auth_invalid BEFORE fetching
                            // a new one. Otherwise getActiveOAuthAccount may return the same
                            // token because isTokenExpired() checks local time, not server state.
                            if (currentAccountId) {
                                await markOAuthAccountQuotaExhausted(currentAccountId, "auth_invalid");
                            }
                            if (stickyAccountId === currentAccountId) {
                                clearStickyAccount();
                            }
                            // Invalidate cache so we get a genuinely different account
                            cachedAccountResponse = null;
                            cachedAccountResponseExpiry = 0;
                            const refreshed = await getActiveOAuthAccount({
                                allowExhausted: false,
                            });
                            if (refreshed?.accessToken) {
                                // Update cache with the new account
                                cachedAccountResponse = refreshed;
                                cachedAccountResponseExpiry = Date.now() + TOKEN_CACHE_TTL_MS;
                                if (refreshed.accountId) {
                                    pinStickyAccount(refreshed.accountId, lb);
                                }
                                else {
                                    clearStickyAccount();
                                }
                                headers.set("Authorization", `Bearer ${refreshed.accessToken}`);
                                opts.headers = headers;
                                response = await globalThis.fetch(input, opts);
                                if (refreshed.accountId) {
                                    recordQuotaStatus(refreshed.accountId, response.status);
                                }
                            }
                            else {
                                // Fix 1.3: Reconstruct response with consumed body
                                response = new Response(body, {
                                    status: 401,
                                    statusText: response.statusText,
                                    headers: response.headers,
                                });
                            }
                        }
                        catch {
                            // Fix 1.3: Reconstruct original 401 since body was consumed
                            response = new Response(body, {
                                status: 401,
                                statusText: response.statusText,
                                headers: response.headers,
                            });
                        }
                    }
                    // -- 429 insufficient_quota: switch account --
                    // Fix 1.2: Use currentAccountId (dynamic) instead of capturedAccountId (static)
                    if (response.status === 429 && currentAccountId) {
                        const body = await response.text().catch(() => "");
                        if (body.includes("insufficient_quota")) {
                            try {
                                await markOAuthAccountQuotaExhausted(currentAccountId, "insufficient_quota");
                                if (stickyAccountId === currentAccountId) {
                                    clearStickyAccount();
                                }
                                // Invalidate cache after marking account exhausted
                                cachedAccountResponse = null;
                                cachedAccountResponseExpiry = 0;
                                const next = await switchToNextHealthyOAuthAccount([
                                    currentAccountId,
                                ]);
                                if (next?.accessToken) {
                                    // Update cache with the new account
                                    cachedAccountResponse = next;
                                    cachedAccountResponseExpiry = Date.now() + TOKEN_CACHE_TTL_MS;
                                    if (next.accountId) {
                                        pinStickyAccount(next.accountId, lb);
                                    }
                                    else {
                                        clearStickyAccount();
                                    }
                                    headers.set("Authorization", `Bearer ${next.accessToken}`);
                                    opts.headers = headers;
                                    if (LOGGING_ENABLED)
                                        logInfo("Switched account after quota", {
                                            to: next.accountId,
                                        });
                                    response = await globalThis.fetch(input, opts);
                                    if (next.accountId) {
                                        recordQuotaStatus(next.accountId, response.status);
                                    }
                                }
                                else {
                                    // No healthy account — reconstruct 429 with original body
                                    response = new Response(body, {
                                        status: 429,
                                        statusText: "Too Many Requests",
                                        headers: response.headers,
                                    });
                                }
                            }
                            catch {
                                response = new Response(body, {
                                    status: 429,
                                    statusText: "Too Many Requests",
                                    headers: response.headers,
                                });
                            }
                        }
                        else {
                            // Non-quota 429 — reconstruct response with consumed body
                            response = new Response(body, {
                                status: 429,
                                statusText: response.statusText,
                                headers: response.headers,
                            });
                        }
                    }
                    return response;
                },
            };
        },
        methods: [
            // -- Primary login --
            {
                label: AUTH_LABELS.OAUTH,
                type: "oauth",
                authorize: async () => {
                    const pkce = await createPKCE();
                    const dev = await requestDeviceCode(pkce);
                    if (!dev)
                        throw new Error("Failed to request device code");
                    console.log(`\nPlease visit: ${dev.verification_uri}`);
                    console.log(`And enter code: ${dev.user_code}\n`);
                    const url = dev.verification_uri_complete || dev.verification_uri;
                    openBrowserUrl(url);
                    return {
                        url,
                        method: "auto",
                        instructions: AUTH_LABELS.INSTRUCTIONS,
                        callback: () => pollDeviceFlow(dev, pkce.verifier, async (r) => {
                            saveToken(r);
                            await upsertOAuthAccount(r, { setActive: true });
                        }).then((r) => r.type === "success"
                            ? {
                                type: "success",
                                access: r.access,
                                refresh: r.refresh,
                                expires: r.expires,
                            }
                            : { type: "failed" }),
                    };
                },
            },
            // -- Add another account --
            {
                label: "Add another Qwen account (multi-account switch)",
                type: "oauth",
                authorize: async () => {
                    const pkce = await createPKCE();
                    const dev = await requestDeviceCode(pkce);
                    if (!dev)
                        throw new Error("Failed to request device code");
                    console.log(`\n[Add Account] Please visit: ${dev.verification_uri}`);
                    console.log(`[Add Account] Enter code: ${dev.user_code}\n`);
                    const url = dev.verification_uri_complete || dev.verification_uri;
                    openBrowserUrl(url);
                    return {
                        url,
                        method: "auto",
                        instructions: "Login with a DIFFERENT Qwen account to add it as backup.",
                        callback: () => pollDeviceFlow(dev, pkce.verifier, async (r) => {
                            await upsertOAuthAccount(r, {
                                setActive: false,
                                forceNew: true,
                            });
                            // Restore active account token file
                            await getActiveOAuthAccount({ allowExhausted: true }).catch(() => null);
                        }).then((r) => r.type === "success"
                            ? {
                                type: "success",
                                access: r.access,
                                refresh: r.refresh,
                                expires: r.expires,
                            }
                            : { type: "failed" }),
                    };
                },
            },
        ],
    },
    // ---- config --------------------------------------------------------------
    config: async (config) => {
        const providers = config.provider ||
            {};
        providers[PROVIDER_ID] = {
            npm: "@ai-sdk/openai-compatible",
            name: "Qwen Code",
            options: { baseURL: getBaseUrl(), timeout: false },
            models: {
                "coder-model": {
                    id: "coder-model",
                    name: "Qwen 3.6 Plus",
                    attachment: false,
                    reasoning: true,
                    limit: { context: 1_048_576, output: CHAT_MAX_TOKENS_CAP },
                    cost: { input: 0, output: 0 },
                    modalities: { input: ["text"], output: ["text"] },
                    variants: {
                        low: { disabled: true },
                        medium: { disabled: true },
                        high: { disabled: true },
                    },
                },
                "vision-model": {
                    id: "vision-model",
                    name: "Qwen Vision",
                    attachment: true,
                    reasoning: false,
                    limit: { context: 131_072, output: 8192 },
                    cost: { input: 0, output: 0 },
                    modalities: { input: ["text", "image"], output: ["text"] },
                },
            },
        };
        config.provider =
            providers;
    },
    // ---- chat.params ---------------------------------------------------------
    "chat.params": async (_input, output) => {
        try {
            const out = output;
            out.options = out.options || {};
            const cap = CHAT_MAX_TOKENS_CAP;
            for (const key of [
                "max_tokens",
                "max_completion_tokens",
                "maxTokens",
            ]) {
                if (typeof out[key] === "number" && out[key] > cap)
                    out[key] = cap;
                if (typeof out.options[key] === "number" &&
                    out.options[key] > cap)
                    out.options[key] = cap;
            }
        }
        catch (e) {
            logWarn("chat.params error:", e);
        }
    },
    // ---- chat.headers --------------------------------------------------------
    "chat.headers": async (_input, output) => {
        try {
            const out = output;
            out.headers = out.headers || {};
            out.headers["X-DashScope-CacheControl"] = "enable";
            out.headers[PORTAL_HEADERS.AUTH_TYPE] = PORTAL_HEADERS.AUTH_TYPE_VALUE;
            out.headers["User-Agent"] = PLUGIN_USER_AGENT;
            out.headers["X-DashScope-UserAgent"] = PLUGIN_USER_AGENT;
        }
        catch (e) {
            logWarn("chat.headers error:", e);
        }
    },
});
export default QwenAuthPlugin;
//# sourceMappingURL=index.js.map
