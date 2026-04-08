import { writeFileSync, mkdirSync, readFileSync } from "fs";
import { dirname } from "path";
import { createPKCE, requestDeviceCode, pollForToken, upsertOAuthAccount } from "./lib/auth/auth.js";
import { openBrowserUrl } from "./lib/auth/browser.js";

const SETTINGS_PATH = `${process.env.HOME || ""}/.qwen/opencode_qwen_settings.json`;
const ACCOUNTS_PATH = `${process.env.HOME || ""}/.qwen/oauth_accounts.json`;
const QUOTA_STATS_PATH = `${process.env.HOME || ""}/.qwen/opencode_qwen_quota_stats.json`;
const QUOTA_DAY_LIMIT = 1000;
const QUOTA_MINUTE_LIMIT = 60;
const DEFAULT_STICKY_MS = 90_000;
const DEFAULT_STICKY_REQUESTS = 8;
const STICKY_MS_MIN = 10_000;
const STICKY_MS_MAX = 600_000;
const STICKY_REQUESTS_MIN = 1;
const STICKY_REQUESTS_MAX = 128;
const OAUTH_RESTART_DELAY_MS = 1200;
const OAUTH_POLL_WARN_COOLDOWN_MS = 8000;
const OAUTH_POLL_INTERVAL_MAX_SEC = 15;
const OAUTH_TRANSIENT_BACKOFF_MAX_MS = 6000;
let oauthAddInProgress = false;

function ensureSettingsDir() {
    try {
        mkdirSync(dirname(SETTINGS_PATH), { recursive: true, mode: 0o700 });
    }
    catch {
    }
}

function clampInt(value, fallback, min, max) {
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

function normalizePreset(value) {
    return value === "round_robin" ? "round_robin" : "cache_friendly";
}

function normalizeSettings(raw) {
    const obj = typeof raw === "object" && raw !== null ? raw : {};
    return {
        loadBalance: typeof obj.loadBalance === "boolean"
            ? obj.loadBalance
            : process.env.OPENCODE_QWEN_LOAD_BALANCE !== "0",
        lbPreset: normalizePreset(obj.lbPreset),
        stickyMs: clampInt(obj.stickyMs, DEFAULT_STICKY_MS, STICKY_MS_MIN, STICKY_MS_MAX),
        stickyRequests: clampInt(obj.stickyRequests, DEFAULT_STICKY_REQUESTS, STICKY_REQUESTS_MIN, STICKY_REQUESTS_MAX),
    };
}

function readSettings() {
    try {
        const raw = readFileSync(SETTINGS_PATH, "utf-8");
        return normalizeSettings(JSON.parse(raw));
    }
    catch {
        return normalizeSettings({});
    }
}

function writeSettings(next) {
    ensureSettingsDir();
    const normalized = normalizeSettings(next);
    writeFileSync(SETTINGS_PATH, `${JSON.stringify({ ...normalized, updatedAt: Date.now() }, null, 2)}\n`, {
        encoding: "utf-8",
        mode: 0o600,
    });
}

function patchSettings(patch) {
    const current = readSettings();
    writeSettings({ ...current, ...patch });
}

function readAccountStoreRaw() {
    try {
        const raw = readFileSync(ACCOUNTS_PATH, "utf-8");
        const parsed = JSON.parse(raw);
        if (typeof parsed !== "object" || parsed === null)
            return null;
        const accounts = Array.isArray(parsed.accounts) ? parsed.accounts : [];
        const safeAccounts = accounts.filter((a) => a && typeof a.id === "string").map((a) => ({
            id: a.id,
            token: a.token,
            resource_url: a.resource_url,
            exhaustedUntil: typeof a.exhaustedUntil === "number" ? a.exhaustedUntil : 0,
            lastErrorCode: typeof a.lastErrorCode === "string" ? a.lastErrorCode : undefined,
            accountKey: typeof a.accountKey === "string" ? a.accountKey : undefined,
            createdAt: typeof a.createdAt === "number" ? a.createdAt : undefined,
            updatedAt: typeof a.updatedAt === "number" ? a.updatedAt : undefined,
        }));
        return {
            version: parsed.version,
            activeAccountId: typeof parsed.activeAccountId === "string" ? parsed.activeAccountId : null,
            accounts: safeAccounts,
        };
    }
    catch {
        return null;
    }
}

function writeAccountStoreRaw(store) {
    if (!store)
        return false;
    try {
        const dir = dirname(ACCOUNTS_PATH);
        mkdirSync(dir, { recursive: true, mode: 0o700 });
        const payload = {
            version: store.version || 2,
            activeAccountId: store.activeAccountId || null,
            accounts: Array.isArray(store.accounts) ? store.accounts : [],
        };
        writeFileSync(ACCOUNTS_PATH, `${JSON.stringify(payload, null, 2)}\n`, {
            encoding: "utf-8",
            mode: 0o600,
        });
        return true;
    }
    catch {
        return false;
    }
}

function readQuotaStatsRaw() {
    try {
        const raw = readFileSync(QUOTA_STATS_PATH, "utf-8");
        const parsed = JSON.parse(raw);
        return typeof parsed === "object" && parsed !== null ? parsed : { accounts: {} };
    }
    catch {
        return { accounts: {} };
    }
}

function getQuotaForAccount(accountId) {
    const stats = readQuotaStatsRaw();
    const obj = stats.accounts && typeof stats.accounts === "object" ? stats.accounts[accountId] : null;
    const dayCount = typeof obj?.dayCount === "number" ? Math.max(0, Math.floor(obj.dayCount)) : 0;
    const minuteCount = typeof obj?.minuteCount === "number" ? Math.max(0, Math.floor(obj.minuteCount)) : 0;
    const dayLeft = Math.max(0, QUOTA_DAY_LIMIT - dayCount);
    const minuteLeft = Math.max(0, QUOTA_MINUTE_LIMIT - minuteCount);
    return {
        dayCount,
        dayLeft,
        minuteCount,
        minuteLeft,
        lastStatus: typeof obj?.lastStatus === "number" ? obj.lastStatus : 0,
    };
}

function formatRemainingCooldown(exhaustedUntil) {
    if (typeof exhaustedUntil !== "number" || exhaustedUntil <= Date.now()) {
        return "ready";
    }
    const left = exhaustedUntil - Date.now();
    const mins = Math.ceil(left / 60000);
    return `${mins}m`;
}

function readAccountSummary() {
    const store = readAccountStoreRaw();
    if (!store) {
        return {
            total: 0,
            healthy: 0,
            exhausted: 0,
            activeAccountId: "none",
        };
    }
    const now = Date.now();
    let healthy = 0;
    let exhausted = 0;
    for (const account of store.accounts) {
        if (typeof account.exhaustedUntil === "number" && account.exhaustedUntil > now) {
            exhausted += 1;
        }
        else {
            healthy += 1;
        }
    }
    return {
        total: store.accounts.length,
        healthy,
        exhausted,
        activeAccountId: store.activeAccountId || "none",
    };
}

function shortAccountId(accountId, max = 14) {
    if (typeof accountId !== "string")
        return "unknown";
    return accountId.length > max ? `${accountId.slice(0, max)}...` : accountId;
}

async function sleep(ms) {
    await new Promise((resolve) => setTimeout(resolve, ms));
}

function showOAuthDialog(api, state) {
    const DialogAlert = api.ui.DialogAlert;
    const codeLine = state.code ? `Code: ${state.code}` : "Code: (none)";
    const urlLine = state.url ? `URL: ${state.url}` : "URL: (none)";
    const message = `${codeLine}\n${urlLine}\n\nStatus: ${state.status}`;
    api.ui.dialog.setSize("large");
    api.ui.dialog.replace(() => DialogAlert({
        title: "Qwen OAuth Device Login",
        message,
        onConfirm: () => {
            api.ui.dialog.clear();
        },
    }));
}

function showActionResultDialog(api, title, message, onClose) {
    const DialogAlert = api.ui.DialogAlert;
    api.ui.dialog.setSize("medium");
    api.ui.dialog.replace(() => DialogAlert({
        title,
        message,
        onConfirm: () => {
            if (typeof onClose === "function") {
                onClose();
            }
            else {
                api.ui.dialog.clear();
            }
        },
    }));
}

function showPoolAccountDialog(api, accountId) {
    const DialogAlert = api.ui.DialogAlert;
    const store = readAccountStoreRaw();
    const account = store?.accounts.find((a) => a.id === accountId);
    if (!store || !account) {
        showActionResultDialog(api, "Qwen Accounts Pool", "Account not found.", () => showAccountsPoolDialog(api));
        return;
    }
    const quota = getQuotaForAccount(account.id);
    const cooldown = formatRemainingCooldown(account.exhaustedUntil);
    const state = cooldown === "ready" ? "healthy" : `cooldown ${cooldown}`;
    const isActive = store.activeAccountId === account.id ? "yes" : "no";
    const resource = typeof account.resource_url === "string" && account.resource_url.length > 0
        ? account.resource_url
        : "unknown";
    const message = `ID: ${account.id}\nActive: ${isActive}\nState: ${state}\nMinute: ${quota.minuteCount}/${QUOTA_MINUTE_LIMIT} (left ${quota.minuteLeft})\nDay: ${quota.dayCount}/${QUOTA_DAY_LIMIT} (left ${quota.dayLeft})\nResource: ${resource}`;
    api.ui.dialog.setSize("large");
    api.ui.dialog.replace(() => DialogAlert({
        title: `Pool Account · ${shortAccountId(account.id, 18)}`,
        message,
        onConfirm: () => {
            showAccountsPoolDialog(api);
        },
    }));
}

function getAccountShortLabel(account, activeId) {
    const isActive = account.id === activeId;
    const now = Date.now();
    const exhausted = typeof account.exhaustedUntil === "number" && account.exhaustedUntil > now;
    const shortId = shortAccountId(account.id);
    const quota = getQuotaForAccount(account.id);
    const state = exhausted
        ? `cooldown ${formatRemainingCooldown(account.exhaustedUntil)}`
        : "healthy";
    return {
        title: `${isActive ? "* " : ""}${shortId}  m${quota.minuteCount}/${QUOTA_MINUTE_LIMIT} d${quota.dayCount}/${QUOTA_DAY_LIMIT}`,
        description: `${state} | left m${quota.minuteLeft} d${quota.dayLeft}`,
    };
}

function setActiveAccount(accountId) {
    const store = readAccountStoreRaw();
    if (!store)
        return false;
    const exists = store.accounts.some((a) => a.id === accountId);
    if (!exists)
        return false;
    store.activeAccountId = accountId;
    return writeAccountStoreRaw(store);
}

function clearAccountCooldown(accountId) {
    const store = readAccountStoreRaw();
    if (!store)
        return false;
    const account = store.accounts.find((a) => a.id === accountId);
    if (!account)
        return false;
    account.exhaustedUntil = 0;
    account.lastErrorCode = undefined;
    account.updatedAt = Date.now();
    return writeAccountStoreRaw(store);
}

function removeAccount(accountId) {
    const store = readAccountStoreRaw();
    if (!store)
        return false;
    const nextAccounts = store.accounts.filter((a) => a.id !== accountId);
    if (nextAccounts.length === store.accounts.length)
        return false;
    store.accounts = nextAccounts;
    if (!store.accounts.length) {
        store.activeAccountId = null;
    }
    else if (store.activeAccountId === accountId) {
        store.activeAccountId = store.accounts[0].id;
    }
    return writeAccountStoreRaw(store);
}

function clearAllCooldowns() {
    const store = readAccountStoreRaw();
    if (!store)
        return 0;
    const now = Date.now();
    let changed = 0;
    for (const account of store.accounts) {
        const hasCooldown = typeof account.exhaustedUntil === "number" && account.exhaustedUntil > 0;
        const hasError = typeof account.lastErrorCode === "string" && account.lastErrorCode.length > 0;
        if (hasCooldown || hasError) {
            account.exhaustedUntil = 0;
            account.lastErrorCode = undefined;
            account.updatedAt = now;
            changed += 1;
        }
    }
    if (changed === 0) {
        return 0;
    }
    return writeAccountStoreRaw(store) ? changed : -1;
}

function confirmRemoveAccount(api, accountId) {
    const DialogConfirm = api.ui.DialogConfirm;
    const label = shortAccountId(accountId, 18);
    api.ui.dialog.setSize("medium");
    api.ui.dialog.replace(() => DialogConfirm({
        title: "Remove account from pool?",
        message: `This will remove ${label} from local account pool.`,
        onConfirm: () => {
            const ok = removeAccount(accountId);
            showActionResultDialog(api, "Qwen", ok ? `Removed: ${label}` : "Failed to remove account", () => showQuotaDashboardMenu(api));
        },
        onCancel: () => {
            showQuotaDashboardMenu(api);
        },
    }));
}

function startAddAccountFlow(api) {
    if (oauthAddInProgress) {
        showActionResultDialog(api, "Qwen OAuth", "OAuth login already running. Finish that flow first.", () => showQuotaDashboardMenu(api));
        return;
    }
    oauthAddInProgress = true;
    void (async () => {
        try {
            for (;;) {
                let lastPollWarnAt = 0;
                let transientBackoffMs = 1000;
                const pkce = await createPKCE();
                const dev = await requestDeviceCode(pkce);
                if (!dev) {
                    showActionResultDialog(api, "Qwen OAuth", "Failed to request device code.", () => showQuotaDashboardMenu(api));
                    return;
                }
                const url = dev.verification_uri_complete || dev.verification_uri;
                const code = dev.user_code || "";
                showOAuthDialog(api, {
                    code,
                    url,
                    status: "Open browser and sign in. Waiting for authorization...",
                });
                openBrowserUrl(url);
                let pollIntervalSec = typeof dev.interval === "number" && dev.interval > 0 ? dev.interval : 2;
                for (;;) {
                    await sleep(Math.max(1, pollIntervalSec) * 1000);
                    const result = await pollForToken(dev.device_code, pkce.verifier, pollIntervalSec);
                    if (result.type === "pending" || result.type === "slow_down") {
                        if (result.type === "slow_down") {
                            pollIntervalSec = Math.min(OAUTH_POLL_INTERVAL_MAX_SEC, pollIntervalSec + 2);
                        }
                        transientBackoffMs = 1000;
                        continue;
                    }
                    if (result.type === "success") {
                        showOAuthDialog(api, {
                            code,
                            url,
                            status: "Authorized. Saving account...",
                        });
                        await upsertOAuthAccount(result, {
                            setActive: false,
                            forceNew: true,
                        });
                        showActionResultDialog(api, "Qwen OAuth", "Account added via OAuth.", () => showQuotaDashboardMenu(api));
                        return;
                    }
                    if (result.type === "denied") {
                        showOAuthDialog(api, {
                            code,
                            url,
                            status: "Login denied. Stopped.",
                        });
                        return;
                    }
                    if (result.type === "expired") {
                        showOAuthDialog(api, {
                            code,
                            url,
                            status: "Code expired. Generating new code...",
                        });
                        await sleep(OAUTH_RESTART_DELAY_MS);
                        break;
                    }
                    if (result.type === "failed" && result.fatal === false) {
                        const now = Date.now();
                        if (now - lastPollWarnAt >= OAUTH_POLL_WARN_COOLDOWN_MS) {
                            lastPollWarnAt = now;
                            showOAuthDialog(api, {
                                code,
                                url,
                                status: "Temporary polling issue. Retrying...",
                            });
                        }
                        await sleep(transientBackoffMs);
                        transientBackoffMs = Math.min(OAUTH_TRANSIENT_BACKOFF_MAX_MS, transientBackoffMs + 500);
                        continue;
                    }
                    if (result.type === "failed") {
                        const msg = typeof result.error === "string" && result.error.length > 0
                            ? result.error
                            : "OAuth failed";
                        showOAuthDialog(api, {
                            code,
                            url,
                            status: `Failed: ${msg}`,
                        });
                        return;
                    }
                    showOAuthDialog(api, {
                        code,
                        url,
                        status: "OAuth returned unknown state. Stopped.",
                    });
                    return;
                }
            }
        }
        catch {
            showActionResultDialog(api, "Qwen OAuth", "OAuth flow failed unexpectedly.", () => showQuotaDashboardMenu(api));
        }
        finally {
            oauthAddInProgress = false;
        }
    })();
}

function showStatusToast(api) {
    const summary = readAccountSummary();
    const s = readSettings();
    showActionResultDialog(api, "Qwen Accounts", `lb=${s.loadBalance ? "on" : "off"}, preset=${s.lbPreset}, sticky=${s.stickyRequests} req/${s.stickyMs} ms, total=${summary.total}, healthy=${summary.healthy}, exhausted=${summary.exhausted}, active=${summary.activeAccountId}`, () => showQuotaDashboardMenu(api));
}

function showAccountActionsMenu(api, accountId) {
    const DialogSelect = api.ui.DialogSelect;
    const store = readAccountStoreRaw();
    const account = store?.accounts.find((a) => a.id === accountId);
    if (!store || !account) {
        showActionResultDialog(api, "Qwen", "Account not found", () => showQuotaDashboardMenu(api));
        return;
    }
    const quota = getQuotaForAccount(account.id);
    const cooldown = formatRemainingCooldown(account.exhaustedUntil);
    const statusText = cooldown === "ready" ? "healthy" : `cooldown ${cooldown}`;
    const label = getAccountShortLabel(account, store.activeAccountId).title;

    api.ui.dialog.setSize("large");
    api.ui.dialog.replace(() => DialogSelect({
        title: `Account: ${label}`,
        options: [
            {
                title: `Usage m${quota.minuteCount}/${QUOTA_MINUTE_LIMIT} d${quota.dayCount}/${QUOTA_DAY_LIMIT}`,
                value: "usage",
                description: `${statusText} | left m${quota.minuteLeft} d${quota.dayLeft} | last=${quota.lastStatus || "n/a"}`,
                disabled: true,
            },
            {
                title: "Set as active",
                value: "set-active",
                description: store.activeAccountId === account.id ? "Already active" : "Use for new requests",
            },
            {
                title: "Clear cooldown",
                value: "clear-cooldown",
                description: "Mark account healthy now",
            },
            {
                title: "Remove account",
                value: "remove",
                description: "Delete this account from local store",
            },
            {
                title: "Back",
                value: "back",
                description: "Return to dashboard",
            },
        ],
        onSelect: (item) => {
            if (item.value === "back") {
                showQuotaDashboardMenu(api);
                return;
            }
            if (item.value === "set-active") {
                const ok = setActiveAccount(account.id);
                showActionResultDialog(api, "Qwen", ok ? "Active account updated" : "Failed to set active account", () => showAccountActionsMenu(api, account.id));
                return;
            }
            if (item.value === "clear-cooldown") {
                const ok = clearAccountCooldown(account.id);
                showActionResultDialog(api, "Qwen", ok ? "Cooldown cleared" : "Failed to clear cooldown", () => showAccountActionsMenu(api, account.id));
                return;
            }
            if (item.value === "remove") {
                const ok = removeAccount(account.id);
                showActionResultDialog(api, "Qwen", ok ? "Account removed" : "Failed to remove account", () => showQuotaDashboardMenu(api));
            }
        },
    }));
}

function showQuotaDashboardMenu(api) {
    const DialogSelect = api.ui.DialogSelect;
    const store = readAccountStoreRaw();
    const s = readSettings();
    const lbStatus = s.loadBalance ? "ON" : "OFF";
    const nextPreset = s.lbPreset === "cache_friendly" ? "round_robin" : "cache_friendly";
    const globalOptions = [
        {
            title: `Load balancing: ${lbStatus}`,
            value: "toggle-lb",
            description: `Toggle ${s.loadBalance ? "OFF" : "ON"}`,
        },
        {
            title: `Preset: ${s.lbPreset}`,
            value: "toggle-preset",
            description: `Switch to ${nextPreset}`,
        },
        {
            title: "View accounts pool",
            value: "view-pool",
            description: "Read-only pool list",
        },
        {
            title: "Add account",
            value: "add",
            description: "Open login flow in prompt",
        },
        {
            title: "Refresh",
            value: "refresh",
            description: "Reload counters and states",
        },
        {
            title: "Recover all cooled accounts",
            value: "recover-all",
            description: "Clear cooldown/errors and return all accounts to pool",
        },
        {
            title: "Close",
            value: "close",
            description: "Dismiss dialog",
        },
    ];

    if (!store || !store.accounts.length) {
        api.ui.dialog.setSize("large");
        api.ui.dialog.replace(() => DialogSelect({
            title: "Qwen Quota Dashboard",
            options: [
                {
                    title: "No accounts found",
                    value: "none",
                    description: "Add an account first",
                    disabled: true,
                },
                ...globalOptions,
            ],
            onSelect: (item) => {
                if (item.value === "toggle-lb") {
                    patchSettings({ loadBalance: !s.loadBalance });
                    showQuotaDashboardMenu(api);
                    return;
                }
                if (item.value === "toggle-preset") {
                    patchSettings({ lbPreset: nextPreset });
                    showQuotaDashboardMenu(api);
                    return;
                }
                if (item.value === "add") {
                    api.ui.dialog.clear();
                    startAddAccountFlow(api);
                    return;
                }
                if (item.value === "view-pool") {
                    showAccountsPoolDialog(api);
                    return;
                }
                if (item.value === "refresh") {
                    showQuotaDashboardMenu(api);
                    return;
                }
                if (item.value === "recover-all") {
                    const changed = clearAllCooldowns();
                    showActionResultDialog(api, "Qwen", changed > 0
                        ? `Recovered ${changed} account${changed === 1 ? "" : "s"}`
                        : changed === 0
                            ? "All accounts already in pool"
                            : "Failed to recover accounts", () => showQuotaDashboardMenu(api));
                    return;
                }
                if (item.value === "close") {
                    api.ui.dialog.clear();
                }
            },
        }));
        return;
    }

    const accountOptions = [];
    for (let i = 0; i < store.accounts.length; i += 1) {
        const account = store.accounts[i];
        const quota = getQuotaForAccount(account.id);
        const shortId = shortAccountId(account.id);
        const cooldown = formatRemainingCooldown(account.exhaustedUntil);
        accountOptions.push({
            title: `${store.activeAccountId === account.id ? "* " : ""}${shortId}  m${quota.minuteCount}/${QUOTA_MINUTE_LIMIT} d${quota.dayCount}/${QUOTA_DAY_LIMIT}`,
            value: `acct:${account.id}`,
            description: `${cooldown === "ready" ? "healthy" : `cooldown ${cooldown}`} | left m${quota.minuteLeft} d${quota.dayLeft} | enter to manage`,
        });
        if (i < store.accounts.length - 1) {
            accountOptions.push({
                title: "----------------",
                value: `sep:${account.id}`,
                description: "",
                disabled: true,
            });
        }
    }

    api.ui.dialog.setSize("large");
    api.ui.dialog.replace(() => DialogSelect({
        title: "Qwen Quota Dashboard",
        options: [
            ...accountOptions,
            {
                title: "Global controls",
                value: "controls-header",
                description: "",
                disabled: true,
            },
            ...globalOptions,
        ],
        onSelect: (item) => {
            if (item.value === "toggle-lb") {
                patchSettings({ loadBalance: !s.loadBalance });
                showQuotaDashboardMenu(api);
                return;
            }
            if (item.value === "toggle-preset") {
                patchSettings({ lbPreset: nextPreset });
                showQuotaDashboardMenu(api);
                return;
            }
            if (item.value === "add") {
                api.ui.dialog.clear();
                startAddAccountFlow(api);
                return;
            }
            if (item.value === "view-pool") {
                showAccountsPoolDialog(api);
                return;
            }
            if (item.value === "refresh") {
                showQuotaDashboardMenu(api);
                return;
            }
            if (item.value === "recover-all") {
                const changed = clearAllCooldowns();
                showActionResultDialog(api, "Qwen", changed > 0
                    ? `Recovered ${changed} account${changed === 1 ? "" : "s"}`
                    : changed === 0
                        ? "All accounts already in pool"
                        : "Failed to recover accounts", () => showQuotaDashboardMenu(api));
                return;
            }
            if (item.value === "close") {
                api.ui.dialog.clear();
                return;
            }
            if (typeof item.value === "string" && item.value.startsWith("acct:")) {
                const id = item.value.slice(5);
                showAccountActionsMenu(api, id);
            }
        },
    }));
}

function showAccountsPoolDialog(api) {
    const DialogSelect = api.ui.DialogSelect;
    const store = readAccountStoreRaw();
    if (!store || !store.accounts.length) {
        api.ui.dialog.setSize("large");
        api.ui.dialog.replace(() => DialogSelect({
            title: "Qwen Accounts Pool",
            options: [
                {
                    title: "No accounts in pool",
                    value: "none",
                    description: "Use Add account to onboard one",
                    disabled: true,
                },
                {
                    title: "Back",
                    value: "back",
                    description: "Return to dashboard",
                },
            ],
            onSelect: (item) => {
                if (item.value === "back") {
                    showQuotaDashboardMenu(api);
                }
            },
        }));
        return;
    }

    let healthy = 0;
    let cooled = 0;
    const accountRows = [];
    for (let i = 0; i < store.accounts.length; i += 1) {
        const account = store.accounts[i];
        const quota = getQuotaForAccount(account.id);
        const cooldown = formatRemainingCooldown(account.exhaustedUntil);
        const isHealthy = cooldown === "ready";
        if (isHealthy)
            healthy += 1;
        else
            cooled += 1;
        const state = isHealthy ? "healthy" : `cooldown ${cooldown}`;
        accountRows.push({
            title: `${store.activeAccountId === account.id ? "* " : ""}${shortAccountId(account.id)}  m${quota.minuteCount}/${QUOTA_MINUTE_LIMIT} d${quota.dayCount}/${QUOTA_DAY_LIMIT}`,
            value: `pool:${account.id}`,
            description: `${state} | left m${quota.minuteLeft} d${quota.dayLeft}`,
        });
    }

    api.ui.dialog.setSize("large");
    api.ui.dialog.replace(() => DialogSelect({
        title: "Qwen Accounts Pool",
        options: [
            {
                title: `Pool summary  total=${store.accounts.length} healthy=${healthy} cooled=${cooled}`,
                value: "summary",
                description: `active=${store.activeAccountId || "none"}`,
            },
            ...accountRows,
            {
                title: "Back",
                value: "back",
                description: "Return to dashboard",
            },
        ],
        onSelect: (item) => {
            if (item.value === "back") {
                showQuotaDashboardMenu(api);
                return;
            }
            if (typeof item.value === "string" && item.value.startsWith("pool:")) {
                const id = item.value.slice(5);
                showPoolAccountDialog(api, id);
            }
        },
    }));
}

function showAccountManagerMenu(api) {
    const DialogSelect = api.ui.DialogSelect;
    const store = readAccountStoreRaw();
    if (!store || !store.accounts.length) {
        api.ui.dialog.setSize("large");
        api.ui.dialog.replace(() => DialogSelect({
            title: "Qwen Accounts",
            options: [
                {
                    title: "No accounts found",
                    value: "none",
                    description: "Use Add account first",
                    disabled: true,
                },
                {
                    title: "Back",
                    value: "back",
                    description: "Return to Qwen Control Center",
                },
            ],
            onSelect: (item) => {
                if (item.value === "back") {
                    showQwenMenu(api);
                }
            },
        }));
        return;
    }

    const accountOptions = store.accounts.map((account) => {
        const label = getAccountShortLabel(account, store.activeAccountId);
        return {
            title: label.title,
            value: `acct:${account.id}`,
            description: label.description,
        };
    });

    api.ui.dialog.setSize("large");
    api.ui.dialog.replace(() => DialogSelect({
        title: "Qwen Accounts",
        options: [
            ...accountOptions,
            {
                title: "Add account",
                value: "add",
                description: "Open login flow in prompt",
            },
            {
                title: "Back",
                value: "back",
                description: "Return to Qwen Control Center",
            },
        ],
        onSelect: (item) => {
            if (item.value === "back") {
                showQwenMenu(api);
                return;
            }
            if (item.value === "add") {
                api.ui.dialog.clear();
                startAddAccountFlow(api);
                return;
            }
            if (typeof item.value === "string" && item.value.startsWith("acct:")) {
                const id = item.value.slice(5);
                showAccountActionsMenu(api, id);
            }
        },
    }));
}

function showLoadBalancerStickyMenu(api) {
    const DialogSelect = api.ui.DialogSelect;
    const s = readSettings();
    const stickyMsOptions = [30_000, 60_000, 90_000, 120_000, 180_000];
    const stickyReqOptions = [2, 4, 8, 12, 16, 24];

    api.ui.dialog.setSize("large");
    api.ui.dialog.replace(() => DialogSelect({
        title: "Qwen LB Sticky Window",
        options: [
            ...stickyMsOptions.map((ms) => ({
                title: `Sticky time: ${Math.floor(ms / 1000)}s`,
                value: `ms:${ms}`,
                description: s.stickyMs === ms ? "Current" : "",
            })),
            ...stickyReqOptions.map((req) => ({
                title: `Sticky requests: ${req}`,
                value: `req:${req}`,
                description: s.stickyRequests === req ? "Current" : "",
            })),
            {
                title: "Back",
                value: "back",
                description: "Return to Load Balancer menu",
            },
        ],
        onSelect: (item) => {
            if (item.value === "back") {
                showLoadBalancerMenu(api);
                return;
            }
            if (typeof item.value === "string" && item.value.startsWith("ms:")) {
                const ms = Number(item.value.slice(3));
                patchSettings({ stickyMs: ms });
                showActionResultDialog(api, "Qwen", `Sticky time set to ${Math.floor(ms / 1000)}s`, () => showLoadBalancerStickyMenu(api));
                return;
            }
            if (typeof item.value === "string" && item.value.startsWith("req:")) {
                const req = Number(item.value.slice(4));
                patchSettings({ stickyRequests: req });
                showActionResultDialog(api, "Qwen", `Sticky requests set to ${req}`, () => showLoadBalancerStickyMenu(api));
            }
        },
    }));
}

function showLoadBalancerMenu(api) {
    const DialogSelect = api.ui.DialogSelect;
    const s = readSettings();

    api.ui.dialog.setSize("large");
    api.ui.dialog.replace(() => DialogSelect({
        title: "Qwen Load Balancer",
        options: [
            {
                title: s.loadBalance ? "Disable load balancing" : "Enable load balancing",
                value: s.loadBalance ? "lb-off" : "lb-on",
                description: `Current: ${s.loadBalance ? "ON" : "OFF"}`,
            },
            {
                title: "Preset: Cache-friendly",
                value: "preset-cache",
                description: s.lbPreset === "cache_friendly"
                    ? `Current | sticky ${s.stickyRequests} req / ${s.stickyMs} ms`
                    : "Sticky account window for better cache hit",
            },
            {
                title: "Preset: Round-robin",
                value: "preset-rr",
                description: s.lbPreset === "round_robin" ? "Current" : "Rotate each request",
            },
            {
                title: "Sticky window tuning",
                value: "sticky-menu",
                description: `${s.stickyRequests} requests / ${s.stickyMs} ms`,
            },
            {
                title: "Back",
                value: "back",
                description: "Return to Qwen Control Center",
            },
        ],
        onSelect: (item) => {
            if (item.value === "back") {
                showQwenMenu(api);
                return;
            }
            if (item.value === "sticky-menu") {
                showLoadBalancerStickyMenu(api);
                return;
            }
            if (item.value === "lb-on") {
                patchSettings({ loadBalance: true });
                showActionResultDialog(api, "Qwen", "Load balancing enabled", () => showLoadBalancerMenu(api));
                return;
            }
            if (item.value === "lb-off") {
                patchSettings({ loadBalance: false });
                showActionResultDialog(api, "Qwen", "Load balancing disabled", () => showLoadBalancerMenu(api));
                return;
            }
            if (item.value === "preset-cache") {
                patchSettings({ lbPreset: "cache_friendly" });
                showActionResultDialog(api, "Qwen", "Load balancer preset set to cache-friendly", () => showLoadBalancerMenu(api));
                return;
            }
            if (item.value === "preset-rr") {
                patchSettings({ lbPreset: "round_robin" });
                showActionResultDialog(api, "Qwen", "Load balancer preset set to round-robin", () => showLoadBalancerMenu(api));
            }
        },
    }));
}

function showQwenMenu(api) {
    showQuotaDashboardMenu(api);
}

const tui = async (api) => {
    api.command.register(() => [
        {
            title: "Qwen control center",
            value: "plugin.qwen.menu",
            category: "Plugin",
            slash: {
                name: "qwen",
            },
            onSelect: () => {
                showQuotaDashboardMenu(api);
            },
        },
    ]);
};

const plugin = {
    id: "qwen-auth-ui",
    tui,
};

export default plugin;
