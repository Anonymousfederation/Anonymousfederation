const SUPABASE_URL = "https://kgscurlvuevcpkaxdxur.supabase.co";
const SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imtnc2N1cmx2dWV2Y3BrYXhkeHVyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODExMDM3MzYsImV4cCI6MjA5NjY3OTczNn0.l01Gx-gvoNzYHejrJPa7-TSYdmGApP89LByDr4pIQ9o";

const supabaseClient =
window.supabase.createClient(
SUPABASE_URL,
SUPABASE_ANON_KEY
);

function resetChatPageLayout() {
    document.body.classList.remove("chat-page");
    document.body.style.justifyContent = "";
    document.body.style.alignItems = "";
    if (window.chatRefreshInterval) {
        clearInterval(window.chatRefreshInterval);
        window.chatRefreshInterval = null;
    }
    if (window.chatBackgroundRefreshInterval) {
        clearInterval(window.chatBackgroundRefreshInterval);
        window.chatBackgroundRefreshInterval = null;
    }
}

function centerPage() {
    resetChatPageLayout();
    document.body.style.justifyContent = "center";
    document.body.style.alignItems = "center";
}

function chatPage() {
    document.body.style.justifyContent = "flex-start";
    document.body.style.alignItems = "flex-start";
}
let lastUsersHtml =
    "";

let selectedChat = {
    type: "global",
    id: null
};

const chatMessagesCache = new Map();
const chatMessagesSnapshots = new Map();
const renderedChatSnapshots = new Map();
const chatRenderVersions = new Map();
const chatTargets = new Map();
const chatMessageRequests = new Map();
let renderedChatKey = "";

let chatRealtime = null;

const CHAT_KEY_DB_NAME = "my-site-chat-keys";
const CHAT_KEY_DB_STORE = "keys";
const CHAT_KEY_RECORD_ID = "shared-chat-v2";
const CHAT_CIPHERTEXT_PREFIX = "enc:v1:";
const CHAT_KEY_KDF_SALT = new TextEncoder().encode("my-site:chat:shared-key:v2");
let chatCryptoKey = null;
let chatEncryptionEnabled = true;

function bytesToBase64Url(bytes) {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return window.btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(value, expectedLength) {
    if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) {
        throw new Error("Invalid base64url value");
    }
    const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
    const binary = window.atob(base64 + "=".repeat((4 - (base64.length % 4)) % 4));
    const bytes = Uint8Array.from(binary, character => character.charCodeAt(0));
    if ((expectedLength && bytes.length !== expectedLength) || bytesToBase64Url(bytes) !== value) {
        throw new Error("Invalid encoded value length");
    }
    return bytes;
}

function openChatKeyDatabase() {
    if (!window.indexedDB) return Promise.reject(new Error("IndexedDB unavailable"));
    return new Promise((resolve, reject) => {
        const request = window.indexedDB.open(CHAT_KEY_DB_NAME, 1);
        request.onupgradeneeded = () => {
            if (!request.result.objectStoreNames.contains(CHAT_KEY_DB_STORE)) {
                request.result.createObjectStore(CHAT_KEY_DB_STORE);
            }
        };
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error || new Error("Could not open key storage"));
        request.onblocked = () => reject(new Error("Key storage is blocked"));
    });
}

async function readStoredChatKey() {
    const database = await openChatKeyDatabase();
    return new Promise((resolve, reject) => {
        const transaction = database.transaction(CHAT_KEY_DB_STORE, "readonly");
        const request = transaction.objectStore(CHAT_KEY_DB_STORE).get(CHAT_KEY_RECORD_ID);
        request.onsuccess = () => {
            database.close();
            const key = request.result;
            resolve(key && key.type === "secret" && key.algorithm?.name === "AES-GCM" &&
                key.extractable === false && key.usages.includes("encrypt") && key.usages.includes("decrypt")
                ? key : null);
        };
        request.onerror = () => {
            database.close();
            reject(request.error || new Error("Could not read key storage"));
        };
        transaction.onabort = () => {
            database.close();
            reject(transaction.error || new Error("Could not read key storage"));
        };
    });
}

async function saveStoredChatKey(key) {
    const database = await openChatKeyDatabase();
    return new Promise((resolve, reject) => {
        const transaction = database.transaction(CHAT_KEY_DB_STORE, "readwrite");
        transaction.objectStore(CHAT_KEY_DB_STORE).put(key, CHAT_KEY_RECORD_ID);
        transaction.oncomplete = () => { database.close(); resolve(); };
        transaction.onerror = () => {
            database.close();
            reject(transaction.error || new Error("Could not save key"));
        };
        transaction.onabort = () => {
            database.close();
            reject(transaction.error || new Error("Could not save key"));
        };
    });
}

async function deleteStoredChatKey() {
    const database = await openChatKeyDatabase();
    return new Promise((resolve, reject) => {
        const transaction = database.transaction(CHAT_KEY_DB_STORE, "readwrite");
        transaction.objectStore(CHAT_KEY_DB_STORE).delete(CHAT_KEY_RECORD_ID);
        transaction.oncomplete = () => { database.close(); resolve(); };
        transaction.onerror = () => {
            database.close();
            reject(transaction.error || new Error("Could not remove saved key"));
        };
        transaction.onabort = () => {
            database.close();
            reject(transaction.error || new Error("Could not remove saved key"));
        };
    });
}

async function deriveChatKey(passphrase) {
    const passphraseBytes = new TextEncoder().encode(passphrase);
    try {
        const material = await window.crypto.subtle.importKey("raw", passphraseBytes, "PBKDF2", false, ["deriveKey"]);
        return await window.crypto.subtle.deriveKey(
            { name: "PBKDF2", salt: CHAT_KEY_KDF_SALT, iterations: 600000, hash: "SHA-256" },
            material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
        );
    } finally {
        passphraseBytes.fill(0);
    }
}

function promptForChatKey() {
    return new Promise(resolve => {
        const overlay = document.createElement("div");
        overlay.className = "chat-key-overlay";
        overlay.innerHTML =
            '<section class="chat-key-dialog" role="dialog" aria-modal="true" aria-labelledby="chatKeyTitle">' +
                '<h2 id="chatKeyTitle">Unlock encrypted chat</h2>' +
                '<p>Enter the shared 18-character random key provided to your group. Generate it randomly with a password manager using only letters, numbers, - and _. Use the same key on every trusted user&apos;s device. This site does not generate or contain the key. Keep a secure backup: if every copy is lost, messages cannot be decrypted.</p>' +
                '<label class="chat-key-label" for="chatKeyInput">Shared key (18 random base64url characters)</label>' +
                '<input id="chatKeyInput" class="chat-key-input" type="password" maxlength="18" autocomplete="off" autocapitalize="none" spellcheck="false" placeholder="Enter the 18-character shared key">' +
                '<div class="chat-key-actions"><button type="button" id="chatKeyUnlock">Unlock chat</button></div>' +
                '<p class="chat-key-status" id="chatKeyStatus" role="status" aria-live="polite"></p>' +
                '<div class="chat-key-secondary-actions"><button type="button" class="chat-key-continue" id="chatKeyContinue">Continue without encryption...</button></div>' +
            '</section>';
        document.body.append(overlay);
        const keyInput = overlay.querySelector("#chatKeyInput");
        const status = overlay.querySelector("#chatKeyStatus");
        let busy = false;
        overlay.querySelector("#chatKeyContinue").addEventListener("click", () => {
            if (busy) return;
            chatEncryptionEnabled = false;
            finish(null);
        });
        const finish = key => {
            keyInput.value = "";
            overlay.remove();
            resolve(key);
        };

        overlay.querySelector("#chatKeyUnlock").addEventListener("click", async () => {
            if (busy) return;
            busy = true;
            const passphrase = keyInput.value;
            keyInput.value = "";
            try {
                if (!/^[A-Za-z0-9_-]{18}$/.test(passphrase)) throw new Error("Invalid key");
                const key = await deriveChatKey(passphrase);
                await saveStoredChatKey(key);
                chatCryptoKey = key;
                finish(key);
            } catch (error) {
                status.textContent = "Enter an exactly 18-character random key using letters, numbers, - or _ and make sure browser storage is available.";
                busy = false;
                keyInput.focus();
            }
        });
        keyInput.addEventListener("keydown", event => {
            if (event.key === "Enter") {
                event.preventDefault();
                overlay.querySelector("#chatKeyUnlock").click();
            }
        });
        keyInput.focus();
    });
}

async function ensureChatKey() {
    if (!window.isSecureContext || !window.crypto || !window.crypto.subtle) {
        throw new Error("Web Crypto requires a secure browser context");
    }
    if (chatCryptoKey) return chatCryptoKey;
    chatCryptoKey = await readStoredChatKey();
    if (!chatCryptoKey) chatCryptoKey = await promptForChatKey();
    return chatCryptoKey;
}

function chatAdditionalData(chat, currentUserId) {
    if (chat.type === "global") return "my-site-chat:v1:global";
    if (chat.type !== "user" || !chat.id || !currentUserId) throw new Error("Invalid conversation");
    const participants = [String(currentUserId), String(chat.id)].sort();
    return "my-site-chat:v1:direct:" + participants[0] + ":" + participants[1];
}

async function encryptChatMessage(plaintext, chat, currentUserId) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const additionalData = new TextEncoder().encode(chatAdditionalData(chat, currentUserId));
    const ciphertext = new Uint8Array(await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData, tagLength: 128 },
        chatCryptoKey,
        new TextEncoder().encode(plaintext)
    ));
    return CHAT_CIPHERTEXT_PREFIX + JSON.stringify({
        v: 1, alg: "AES-256-GCM",
        iv: bytesToBase64Url(iv), data: bytesToBase64Url(ciphertext)
    });
}

async function decryptChatMessage(value, chat, currentUserId) {
    const storedValue = String(value ?? "");
    if (!storedValue.startsWith(CHAT_CIPHERTEXT_PREFIX)) {
        if (storedValue.startsWith("enc:")) return { text: "Encrypted message uses an unsupported format.", error: true };
        return { text: storedValue, legacy: true };
    }
    try {
        if (!chatCryptoKey) return { text: "Encrypted message. Enter the shared key to read.", error: true };
        const payload = JSON.parse(storedValue.slice(CHAT_CIPHERTEXT_PREFIX.length));
        if (!payload || payload.v !== 1 || payload.alg !== "AES-256-GCM") throw new Error("Unsupported format");
        const iv = base64UrlToBytes(payload.iv, 12);
        const ciphertext = base64UrlToBytes(payload.data);
        if (ciphertext.length < 16) throw new Error("Invalid ciphertext");
        const additionalData = new TextEncoder().encode(chatAdditionalData(chat, currentUserId));
        const plaintext = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv, additionalData, tagLength: 128 },
            chatCryptoKey, ciphertext
        );
        return { text: new TextDecoder("utf-8", { fatal: true }).decode(plaintext), encrypted: true };
    } catch (error) {
        return { text: "Unable to decrypt. Check the shared key or message integrity.", error: true };
    }
}

async function logAction(action) {

    const {
        data: { session }
    } =
    await supabaseClient
        .auth
        .getSession();

    if (!session) {
        return;
    }

    await fetch(
        "https://kgscurlvuevcpkaxdxur.supabase.co/functions/v1/log-action",
        {
            method: "POST",
            headers: {
                Authorization:
                    `Bearer ${session.access_token}`,
                "Content-Type":
                    "application/json"
            },
            body: JSON.stringify({
                action
            })
        }
    );

}

let profile = null;
let aiConversation = [];
let aiRequestInProgress = false;

if (document.getElementById("email")) {
    supabaseClient.auth.getSession().then(({ data: { session } }) => {
        if (session) window.location.replace("dashboard.html");
    });
}

async function login() {

const email =
    document.getElementById("email").value;

const password =
    document.getElementById("password").value;

document.getElementById("error")
    .textContent = "";


const result =
    await supabaseClient.auth.signInWithPassword({
        email,
        password
    });

if (result.error) {

    const message =
        result.error.message.toLowerCase();

    if (
        message.includes(
            "invalid login credentials"
        )
    ) {

        document.getElementById("error")
            .textContent =
            "Email or password is incorrect.";

    } else {

        document.getElementById("error")
            .textContent =
            result.error.message;

    }

    return;
}
await logAction("LOGIN");
window.location.href =
    "dashboard.html";

}

async function loadPage(pageKey) {
    resetChatPageLayout();

    const {
        data: { session }
    } =
    await supabaseClient
        .auth
        .getSession();

    const response =
        await fetch(
            "https://kgscurlvuevcpkaxdxur.supabase.co/functions/v1/get-page",
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json",

                    Authorization:
                        `Bearer ${session.access_token}`
                },

                body: JSON.stringify({
                    pageKey
                })
            }
        );

    const result =
        await response.json();

    if (!response.ok) {

        document
            .getElementById(
                "content"
            )
            .innerHTML =
            result.error ||
            "Access denied";

        return;

    }

    document
        .getElementById(
            "content"
        )
        .innerHTML =
        result.content;

}

function loadHome() {

if (profile.aplf_level === -1) {

    loadPage("home_special");

} else {

    loadPage("home_normal");

}

}

function loadAPLF() {

loadPage(
    "aplf_" + profile.aplf_level
);

}

function loadADIF() {

loadPage(
    "adif_" + profile.adif_level
);

}

function canUseAI() {
    const aplfLevel = profile?.aplf_level;
    if (!profile || aplfLevel === null || aplfLevel === undefined || String(aplfLevel).trim() === "") return false;
    const level = Number(aplfLevel);
    return Number.isFinite(level) && level > -1;
}
function ensureAIStyles() {
    if (document.getElementById("aiAssistantStyles")) return;
    const style = document.createElement("style");
    style.id = "aiAssistantStyles";
    style.textContent = [
        ".ai-panel { display:flex; max-width:900px; height:min(78dvh,760px); min-height:420px; flex-direction:column; gap:12px; margin:0 auto; padding:20px; border:1px solid #303940; border-radius:12px; background:#191f24; }",
        ".ai-panel h1 { margin:0; color:#e7eaec; font-size:1.5rem; }",
        ".ai-status { margin:0; color:#929da5; font-size:.82rem; }",
        ".ai-messages { display:flex; min-height:0; flex:1; flex-direction:column; gap:10px; overflow-y:auto; padding:12px; border:1px solid #303940; border-radius:8px; background:#101518; }",
        ".ai-message { max-width:85%; padding:9px 12px; border:1px solid #303940; border-radius:9px; color:#e7eaec; line-height:1.5; overflow-wrap:anywhere; white-space:pre-wrap; }",
        ".ai-message--user { align-self:flex-end; border-color:#3b535f; background:#263a46; }",
        ".ai-message--assistant { align-self:flex-start; background:#20272d; }",
        ".ai-composer { display:flex; gap:9px; }",
        ".ai-composer input { min-width:0; height:44px; flex:1; padding:0 12px; border:1px solid #343e45; border-radius:7px; background:#101518; color:#e7eaec; font:400 .95rem Arial,sans-serif; }",
        ".ai-composer button { min-width:78px; }",
        "@media (max-width:640px) { .ai-panel { height:calc(100dvh - 90px); min-height:360px; padding:12px; } .ai-message { max-width:94%; } .ai-composer input { font-size:16px; } }"
    ].join("\n");
    document.head.append(style);
}

function appendAIMessage(role, text) {
    const messages = document.getElementById("aiMessages");
    if (!messages) return null;
    const bubble = document.createElement("div");
    bubble.className = "ai-message ai-message--" + role;
    bubble.textContent = text;
    messages.append(bubble);
    messages.scrollTop = messages.scrollHeight;
    return bubble;
}

async function loadAI() {
    if (!canUseAI()) return;

    const { data: { user } } = await supabaseClient.auth.getUser();
    if (!user) {
        window.location.replace("index.html");
        return;
    }

    const { data: { session } } = await supabaseClient.auth.getSession();
    if (!session) {
        window.location.replace("index.html");
        return;
    }

    resetChatPageLayout();
    const dailyLimit = profile.premium_user === true ? 25 : 5;
    document.getElementById("content").innerHTML =
        '<section class="ai-panel" aria-labelledby="aiTitle">' +
            '<h1 id="aiTitle">AI assistant</h1>' +
            '<p id="aiStatus" class="ai-status"></p>' +
            '<div id="aiMessages" class="ai-messages" role="log" aria-live="polite"></div>' +
            '<form id="aiComposer" class="ai-composer">' +
                '<input id="aiInput" type="text" maxlength="2000" placeholder="Ask a question..." aria-label="Ask the AI assistant" autocomplete="off">' +
                '<button id="aiSendButton" type="submit">Send</button>' +
            '</form>' +
        '</section>';

    const status = document.getElementById("aiStatus");
    status.textContent = "You can send up to " + dailyLimit +
        " messages per day. Your chat is not saved to your site account; the limit resets at midnight UTC.";
    aiConversation.forEach(message => appendAIMessage(message.role, message.content));
    document.getElementById("aiComposer").addEventListener("submit", sendAIMessage);
}

async function sendAIMessage(event) {
    event.preventDefault();
    if (aiRequestInProgress || !canUseAI()) return;

    const input = document.getElementById("aiInput");
    const sendButton = document.getElementById("aiSendButton");
    const message = input.value.trim();
    if (!message) return;

    const { data: { user } } = await supabaseClient.auth.getUser();
    if (!user) {
        window.location.replace("index.html");
        return;
    }
    const { data: { session } } = await supabaseClient.auth.getSession();
    if (!session) {
        window.location.replace("index.html");
        return;
    }

    aiRequestInProgress = true;
    sendButton.disabled = true;
    appendAIMessage("user", message);
    input.value = "";
    const responseBubble = appendAIMessage("assistant", "Thinking...");

    try {
        const response = await fetch(SUPABASE_URL + "/functions/v1/ai-chat", {
            method: "POST",
            headers: {
                Authorization: "Bearer " + session.access_token,
                apikey: SUPABASE_ANON_KEY,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                message,
                history: aiConversation.slice(-10)
            })
        });
        const result = await response.json().catch(() => ({}));

        if (!response.ok) {
            if (response.status === 401) {
                window.location.replace("index.html");
                return;
            }
            if (response.status === 429 && result.reason === "daily_limit") {
                responseBubble.textContent = "You have used all " +
                    result.daily_limit + " AI messages for today. The limit resets at midnight UTC.";
                document.getElementById("aiStatus").textContent =
                    "0 of " + result.daily_limit + " messages remaining today.";
                return;
            }
            if (response.status === 403) {
                responseBubble.textContent = "AI access is not available for this account.";
                return;
            }
            responseBubble.textContent = "The AI could not reply. Your submitted message may have used a daily slot.";
            return;
        }

        if (typeof result.reply !== "string" || !result.reply) {
            throw new Error("Empty AI response");
        }
        responseBubble.textContent = result.reply;
        aiConversation.push(
            { role: "user", content: message },
            { role: "assistant", content: result.reply }
        );
        document.getElementById("aiStatus").textContent =
            result.remaining + " of " + result.daily_limit + " messages remaining today. Resets at midnight UTC.";
    } catch (error) {
        responseBubble.textContent = "The AI could not reply. Your submitted message may have used a daily slot.";
    } finally {
        aiRequestInProgress = false;
        if (sendButton.isConnected) sendButton.disabled = false;
        if (input.isConnected) input.focus();
    }
}
async function initDashboard() {

const {
    data: { user }
} =
await supabaseClient.auth.getUser();

if (!user) {

    window.location.href =
        "index.html";

    return;
}

const { data, error } =
    await supabaseClient
        .from("profiles")
        .select("*")
        .eq("id", user.id)
        .single();

if (error || !data) {

    document.getElementById("content")
        .innerHTML =
        "Profile not found";

    return;
}

profile = data;

if (profile.admin_priv === 1) {

    const adminButton =
        document.getElementById("adminButton");

    adminButton.style.display = "block";

adminButton.addEventListener(
    "click",
    async () => {

        await logAction(
            "OPEN_ADMIN_PANEL"
        );
        document.getElementById("content").innerHTML = `
            <h3>Admin Panel</h3>

            <p>Full Name</p>
            <input
                type="text"
                id="newUsername"
            >

            <p>Password</p>
            <input
                type="text"
                id="newPassword"
            >

            <button id="createUserButton">
                Create / Update Account
            </button>
        `;

        document
            .getElementById(
                "createUserButton"
            )
            .addEventListener(
                "click",
                createOrUpdateUser
            );

    });

}

if (profile.aplf_level >= 0) {

    const chatButton =
        document.getElementById(
            "chatButton"
        );

    chatButton.style.display =
        "block";

    chatButton.addEventListener(
        "click",
        loadChat
    );

}

const menuButton =
    document.getElementById(
        "menuButton"
    );

const menu =
    document.getElementById(
        "menu"
    );

if (menuButton && menu) {

    menu.style.display = window.getComputedStyle(menu).display;

    menuButton.addEventListener(
        "click",
        () => {

            if (
                menu.style.display ===
                "none"
            ) {

                menu.style.display =
                    "block";

            } else {

                menu.style.display =
                    "none";

            }

        }
    );
}

if (canUseAI()) {
    ensureAIStyles();
    const menu = document.getElementById("menu");
    if (menu && !document.getElementById("aiButton")) {
        const aiButton = document.createElement("button");
        aiButton.id = "aiButton";
        aiButton.type = "button";
        aiButton.textContent = "AI Assistant";
        aiButton.addEventListener("click", loadAI);
        menu.insertBefore(aiButton, document.getElementById("adminButton"));
    }
}
if (profile.aplf_level >= 1) {

    const aplfButton =
        document.getElementById(
            "aplfButton"
        );

    aplfButton.style.display =
        "block";

aplfButton.addEventListener(
    "click",
    async () => {

        await logAction(
            "OPEN_APLF"
        );

        loadAPLF();

    }
);
}

if (profile.adif_level >= 1) {

    const adifButton =
        document.getElementById(
            "adifButton"
        );

    adifButton.style.display =
        "block";

adifButton.addEventListener(
    "click",
    async () => {

        await logAction(
            "OPEN_ADIF"
        );

        loadADIF();

    }
);
}

if (profile.aplf_level > -1) {

    const leaderboardButton =
        document.getElementById(
            "leaderboardButton"
        );

    leaderboardButton.style.display =
        "block";

leaderboardButton.addEventListener(
    "click",
    async () => {

        await logAction(
            "OPEN_LEADERBOARD"
        );

        loadLeaderboard();

    }
);
}

loadHome();

}

if (
window.location.pathname
.includes("dashboard")
) {
initDashboard();
}

async function loadLeaderboard() {
    centerPage();
    const {
        data: { session }
    } =
    await supabaseClient
        .auth
        .getSession();

    const response =
        await fetch(
            "https://kgscurlvuevcpkaxdxur.supabase.co/functions/v1/get-leaderboard",
            {
                headers: {
                    Authorization:
                        `Bearer ${session.access_token}`
                }
            }
        );

    const result = await response.json();
    const leaderboard = Array.isArray(result) ? result : [];
    const escapeHTML = value =>
        String(value ?? "").replace(/[&<>"']/g, character => ({
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;"
        })[character]);
    const rankedPeople = leaderboard.map((person, index) => {
        const parsedPlace = Number(String(person.ranking ?? "").match(/\d+/)?.[0]);
        return {
            person,
            place: Number.isInteger(parsedPlace) && parsedPlace > 0
                ? parsedPlace
                : index + 1
        };
    });
    const podiumGroups = [1, 2, 3].map(place => ({
        place,
        people: rankedPeople.filter(entry => entry.place === place)
    })).filter(group => group.people.length);
    const hasTies = podiumGroups.some(group => group.people.length > 1);
    const placeLabels = ["", "1st place", "2nd place", "3rd place"];

    const podium = podiumGroups.map(({ place, people }) => `
        <div class="podium-group podium-group--${place}${people.length > 1 ? " is-tied" : ""}" style="--podium-count:${people.length}">
            ${people.map(({ person }) => {
                const name = String(person.name ?? "Unknown name");
                const initials = name.trim().split(/\s+/).filter(Boolean)
                    .slice(0, 2).map(part => part.charAt(0)).join("").toUpperCase() || "?";

                return `
                    <article class="podium-card podium-card--${place}">
                        <span class="podium-place">${escapeHTML(person.ranking ?? `#${place}`)}</span>
                        <span class="podium-label">${placeLabels[place]}</span>
                        <span class="podium-avatar" aria-hidden="true">${escapeHTML(initials)}</span>
                        <span class="podium-player">
                            <strong class="podium-name">${escapeHTML(name)}</strong>
                            <span class="podium-rank">${escapeHTML(person.rank ?? "Unranked")}</span>
                        </span>
                        <span class="podium-warnings"><strong>${escapeHTML(person.warnings ?? 0)}</strong> warnings</span>
                    </article>
                `;
            }).join("")}
        </div>
    `).join("");

    const remaining = rankedPeople.filter(({ place }) => place > 3);
    const rows = remaining.map(({ person, place }) => `
        <tr>
            <td class="standing-position">${escapeHTML(person.ranking ?? `#${place}`)}</td>
            <td class="standing-name">${escapeHTML(person.name ?? "Unknown name")}</td>
            <td>${escapeHTML(person.rank ?? "Unranked")}</td>
            <td>${escapeHTML(person.warnings ?? 0)}</td>
        </tr>
    `).join("");

    const html = `
        <main class="leaderboard-page">
            <header class="leaderboard-header">
                <h1>Leaderboard</h1>
                <div class="leaderboard-player-count">
                    <strong>${leaderboard.length}</strong>
                    <span>${leaderboard.length === 1 ? "person" : "people"}</span>
                </div>
            </header>
            ${leaderboard.length ? `
                <section class="leaderboard-podium${hasTies ? " leaderboard-podium--tied" : ""}" aria-label="Top three people">
                    ${podium}
                </section>
                ${remaining.length ? `
                    <section class="leaderboard-standings" aria-labelledby="standings-title">
                        <div class="standings-heading">
                            <div>
                                <p class="leaderboard-eyebrow">Full standings</p>
                                <h2 id="standings-title">The field</h2>
                            </div>
                            <span>${remaining.length} ${remaining.length === 1 ? "person" : "people"}</span>
                        </div>
                        <div class="standings-table-wrap">
                            <table class="standings-table">
                                <thead>
                                    <tr><th scope="col">Place</th><th scope="col">Name</th><th scope="col">Rank</th><th scope="col">Warnings</th></tr>
                                </thead>
                                <tbody>${rows}</tbody>
                            </table>
                        </div>
                    </section>
                ` : ""}
            ` : `
                <div class="leaderboard-empty">
                    <span aria-hidden="true">-</span>
                    <h2>No standings yet</h2>
                    <p>The leaderboard will appear here when people are ranked.</p>
                </div>
            `}
        </main>
    `;

    document.getElementById("content").innerHTML = html;
}
async function createOrUpdateUser() {

    const username =
        document.getElementById(
            "newUsername"
        ).value;

    const password =
        document.getElementById(
            "newPassword"
        ).value;

const {
    data: { session }
} = await supabaseClient.auth.getSession();

const response =
    await fetch(
        "https://kgscurlvuevcpkaxdxur.supabase.co/functions/v1/create-user",
        {
            method: "POST",
            headers: {
                "Content-Type":
                    "application/json",
                "Authorization":
                    "Bearer " +
                    session.access_token
            },
            body: JSON.stringify({
                username:
                    username,
                password:
                    password
            })
        }
    );    const result =
        await response.json();

    alert(result.message);

}

function getChatKey(chat) {
    return chat.type === "global" ? "global" : "user:" + String(chat.id);
}

function normalizeChat(chat) {
    if (!chat || (chat.type !== "global" && chat.type !== "user")) return null;
    if (chat.type === "user" && (chat.id === null || chat.id === undefined)) return null;
    return { type: chat.type, id: chat.type === "global" ? null : String(chat.id) };
}

function registerChatTargets(users) {
    const nextTargets = new Map();
    nextTargets.set("global", { type: "global", id: null });
    for (const user of users) {
        const chat = normalizeChat({ type: user.type, id: user.id });
        if (chat) nextTargets.set(getChatKey(chat), chat);
    }

    const discovered = Array.from(nextTargets.entries())
        .filter(([key]) => !chatTargets.has(key) &&
            !chatMessagesCache.has(key) &&
            !chatMessageRequests.has(key))
        .map(([, chat]) => chat);

    chatTargets.clear();
    nextTargets.forEach((chat, key) => chatTargets.set(key, chat));
    return discovered;
}

async function preloadChatMessages(chats) {
    const uniqueChats = Array.from(new Map(
        chats.map(chat => [getChatKey(chat), normalizeChat(chat)]).filter(([, chat]) => chat)
    ).values());
    let nextIndex = 0;
    const workerCount = Math.min(4, uniqueChats.length);

    await Promise.all(Array.from({ length: workerCount }, async () => {
        while (nextIndex < uniqueChats.length) {
            const chat = uniqueChats[nextIndex++];
            try {
                await loadMessages(chat);
            } catch (error) {
                console.error("Could not refresh conversation messages", error);
            }
        }
    }));
}

async function loadChat() {
    document.body.style.justifyContent = "flex-start";
    document.body.style.alignItems = "stretch";
    document.body.classList.add("chat-page");
    lastUsersHtml = "";
    renderedChatKey = "";
    selectedChat = { type: "global", id: null };
    document.getElementById("content").innerHTML =
        '<section id="chatContainer" aria-label="Chat">' +
            '<aside id="chatSidebar" aria-label="Conversations">' +
                '<div class="chat-sidebar-heading">Conversations</div>' +
                '<div class="chat-key-controls"><button type="button" id="chatResetKey">Replace saved key</button></div>' +
                '<div id="chatConversations">Loading...</div>' +
            '</aside>' +
            '<section class="chat-main" aria-label="Messages">' +
                '<header class="chat-header">' +
                    '<div class="chat-header-title">Messages</div>' +
                    '<div class="chat-header-subtitle">Choose a conversation to get started</div>' +
                '</header>' +
                '<div id="chatMessages" aria-live="polite"></div>' +
                '<form id="chatComposer" class="chat-composer">' +
                    '<input id="chatInput" placeholder="Type a message..." aria-label="Write a message" autocomplete="off">' +
                    '<button id="sendChatButton" type="submit">Send</button>' +
                '</form>' +
            '</section>' +
        '</section>';
    try {
        await ensureChatKey();
    } catch (error) {
        const area = document.getElementById("chatMessages");
        if (area) area.textContent = "Secure chat could not start. Use HTTPS and a browser with Web Crypto and IndexedDB support.";
        return;
    }
    document.getElementById("chatResetKey").addEventListener("click", async event => {
        if (!window.confirm("Remove the key saved in this browser? You will need the group's shared key again. Messages encrypted with a different key cannot be opened.")) return;
        event.currentTarget.disabled = true;
        try {
            await deleteStoredChatKey();
            chatCryptoKey = null;
            window.location.reload();
        } catch (error) {
            event.currentTarget.disabled = false;
            alert("The saved key could not be removed.");
        }
    });
    await Promise.all([loadChatUsers(), chatPing()]);
    document.getElementById("chatComposer").addEventListener("submit", async event => {
        event.preventDefault();
        await sendMessage();
    });

    void preloadChatMessages(Array.from(chatTargets.values()));
    try {
        await loadMessages(selectedChat);
    } catch (error) {
        console.error("Could not load the group conversation", error);
    }

    if (window.chatRefreshInterval) clearInterval(window.chatRefreshInterval);
    if (window.chatBackgroundRefreshInterval) clearInterval(window.chatBackgroundRefreshInterval);
    window.chatRefreshInterval = setInterval(async () => {
        if (!document.getElementById("chatContainer")) return;
        try {
            await Promise.all([
                loadMessages({ ...selectedChat }),
                loadChatUsers(),
                chatPing()
            ]);
        } catch (error) {
            console.error("Chat refresh failed", error);
        }
    }, 3000);
    window.chatBackgroundRefreshInterval = setInterval(async () => {
        if (!document.getElementById("chatContainer")) return;
        const activeKey = getChatKey(selectedChat);
        const unopenedChats = Array.from(chatTargets.entries())
            .filter(([key]) => key !== activeKey)
            .map(([, chat]) => chat);
        await preloadChatMessages(unopenedChats);
    }, 20000);
}

async function loadChatUsers() {
    const { data: { session } } = await supabaseClient.auth.getSession();
    if (!session) return [];
    const response = await fetch(
        "https://kgscurlvuevcpkaxdxur.supabase.co/functions/v1/get-chat-users",
        { headers: { Authorization: "Bearer " + session.access_token } }
    );
    if (!response.ok) throw new Error("Could not load conversations");
    const result = await response.json();
    const users = Array.isArray(result) ? result : [];
    const discoveredChats = registerChatTargets(users);
    const snapshot = JSON.stringify(users.map(user => [
        user.type, user.id, user.display_name, Boolean(user.online), Boolean(user.has_unread),
        String(selectedChat.id) === String(user.id)
    ]));
    if (snapshot !== lastUsersHtml) {
        const list = document.getElementById("chatConversations");
        if (list) {
            const fragment = document.createDocumentFragment();
            users.forEach(user => {
                const button = document.createElement("button");
                button.type = "button";
                button.className = "chat-user-button";
                if (user.has_unread) button.classList.add("has-unread");
                if (String(selectedChat.id) === String(user.id)) button.classList.add("is-selected");
                button.dataset.chatId = String(user.id ?? "");
                button.dataset.chatType = String(user.type ?? "");
                const indicator = document.createElement("span");
                indicator.className = "chat-user-indicator";
                if (user.online) indicator.classList.add("is-online");
                indicator.setAttribute("aria-hidden", "true");
                const name = document.createElement("span");
                name.className = "chat-user-name";
                name.textContent = String(user.display_name ?? "Unknown user");
                button.append(indicator, name);
                if (user.has_unread) {
                    const unread = document.createElement("span");
                    unread.className = "chat-unread-dot";
                    unread.setAttribute("aria-label", "Unread messages");
                    button.append(unread);
                }
                button.addEventListener("click", () => openChat(user.type, user.id));
                fragment.append(button);
            });
            list.replaceChildren(fragment);
            lastUsersHtml = snapshot;
        }
    }
    if (discoveredChats.length) void preloadChatMessages(discoveredChats);
    return users;
}

async function chatPing() {
    const { data: { session } } = await supabaseClient.auth.getSession();
    if (!session) return;
    await fetch(
        "https://kgscurlvuevcpkaxdxur.supabase.co/functions/v1/chat-ping",
        { method: "POST", headers: { Authorization: "Bearer " + session.access_token } }
    );
}

async function openChat(type, id) {
    const chat = normalizeChat({ type, id });
    if (!chat) return;
    selectedChat = chat;
    const key = getChatKey(chat);
    document.querySelectorAll(".chat-user-button").forEach(button => {
        button.classList.toggle("is-selected",
            button.dataset.chatType === String(type) && button.dataset.chatId === String(id ?? ""));
    });
    const selected = Array.from(document.querySelectorAll(".chat-user-button")).find(button =>
        button.dataset.chatType === String(type) && button.dataset.chatId === String(id ?? ""));
    const title = document.querySelector(".chat-header-title");
    const subtitle = document.querySelector(".chat-header-subtitle");
    const messages = document.getElementById("chatMessages");
    if (selected && title) title.textContent = selected.querySelector(".chat-user-name").textContent;
    if (subtitle) subtitle.textContent = type === "global" ? "Group conversation" : "Conversation";

    const cachedMessages = chatMessagesCache.get(key);
    if (cachedMessages) {
        await renderChatMessages(chat, cachedMessages, true);
    } else if (messages) {
        renderedChatKey = "";
        messages.textContent = "Loading messages...";
    }

    const tasks = [
        loadMessages(chat),
        loadChatUsers()
    ];
    if (type === "user") tasks.push(markMessagesRead(id));
    try {
        await Promise.all(tasks);
    } catch (error) {
        console.error("Could not open conversation", error);
    }
    if (messages && selectedChat.type === chat.type && String(selectedChat.id) === String(chat.id)) {
        messages.scrollTop = messages.scrollHeight;
    }
}

window.openChat = openChat;

async function loadMessages(chat = selectedChat) {
    const normalizedChat = normalizeChat(chat);
    if (!normalizedChat) return;
    const key = getChatKey(normalizedChat);
    if (chatMessageRequests.has(key)) return chatMessageRequests.get(key);

    const request = (async () => {
        const { data: { session } } = await supabaseClient.auth.getSession();
        const { data: { user } } = await supabaseClient.auth.getUser();
        if (!session || !user) return;
        const response = await fetch(
            "https://kgscurlvuevcpkaxdxur.supabase.co/functions/v1/get-messages",
            {
                method: "POST",
                headers: {
                    Authorization: "Bearer " + session.access_token,
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    recipient_id: normalizedChat.type === "global" ? null : normalizedChat.id
                })
            }
        );
        if (!response.ok) throw new Error("Could not load messages");
        const messages = await response.json();
        if (!Array.isArray(messages)) throw new Error("Unexpected messages response");

        const snapshot = JSON.stringify(messages.map(message => [
            message.id, message.message, message.sender_id, message.display_name
        ]));
        chatMessagesCache.set(key, messages);
        const previousSnapshot = chatMessagesSnapshots.get(key);
        chatMessagesSnapshots.set(key, snapshot);
        if (getChatKey(selectedChat) === key &&
            (snapshot !== previousSnapshot || renderedChatKey !== key)) {
            await renderChatMessages(normalizedChat, messages);
        }
        return messages;
    })();

    chatMessageRequests.set(key, request);
    try {
        return await request;
    } finally {
        if (chatMessageRequests.get(key) === request) chatMessageRequests.delete(key);
    }
}

async function renderChatMessages(chat, messages, force = false) {
    const key = getChatKey(chat);
    const snapshot = chatMessagesSnapshots.get(key);
    if (!force && renderedChatKey === key &&
        renderedChatSnapshots.get(key) === snapshot) return;

    const version = (chatRenderVersions.get(key) || 0) + 1;
    chatRenderVersions.set(key, version);
    const { data: { user } } = await supabaseClient.auth.getUser();
    if (!user) return;

    const fragment = document.createDocumentFragment();
    for (const message of messages) {
        const item = document.createElement("div");
        item.className = "chat-message";
        if (String(message.sender_id) === String(user.id)) item.classList.add("is-mine");
        const name = document.createElement("div");
        name.className = "chat-name";
        name.textContent = String(message.sender_id) === String(user.id)
            ? "You" : String(message.display_name ?? "Unknown user");
        const bubble = document.createElement("div");
        bubble.className = "chat-bubble";
        const decrypted = await decryptChatMessage(message.message, chat, user.id);
        bubble.textContent = decrypted.text;
        if (decrypted.legacy || decrypted.error) {
            item.classList.add(decrypted.legacy ? "chat-message--legacy" : "chat-message--error");
            const warning = document.createElement("div");
            warning.className = "chat-encryption-warning";
            warning.textContent = decrypted.legacy
                ? "Legacy message - not encrypted" : "Encrypted message could not be opened";
            item.append(name, warning, bubble);
        } else {
            item.append(name, bubble);
        }
        fragment.append(item);
    }

    const area = document.getElementById("chatMessages");
    if (!area || getChatKey(selectedChat) !== key || chatRenderVersions.get(key) !== version) return;
    area.replaceChildren(fragment);
    renderedChatKey = key;
    renderedChatSnapshots.set(key, snapshot);
}
async function sendMessage() {
    const input = document.getElementById("chatInput");
    const sendButton = document.getElementById("sendChatButton");
    const text = input.value.trim();
    if (!text || (chatEncryptionEnabled && !chatCryptoKey)) return;
    const { data: { session } } = await supabaseClient.auth.getSession();
    const { data: { user } } = await supabaseClient.auth.getUser();
    if (!session || !user) {
        alert("Please sign in again before sending a message.");
        return;
    }
    sendButton.disabled = true;
    try {
        const message = chatEncryptionEnabled
            ? await encryptChatMessage(text, selectedChat, user.id)
            : text;
        const response = await fetch(
            "https://kgscurlvuevcpkaxdxur.supabase.co/functions/v1/send-message",
            {
                method: "POST",
                headers: {
                    Authorization: "Bearer " + session.access_token,
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    recipient_id: selectedChat.type === "global" ? null : selectedChat.id,
                    message_text: message
                })
            }
        );
        const result = await response.json().catch(() => ({}));
        if (!response.ok) {
            alert(result.error || "Failed to send encrypted message");
            return;
        }
        input.value = "";
        await loadMessages();
    } catch (error) {
        alert("The encrypted message could not be sent.");
    } finally {
        sendButton.disabled = false;
    }
}

async function markMessagesRead(
    senderId
) {

    if (
        selectedChat.type ===
        "global"
    ) {
        return;
    }

    const {
        data: { session }
    } =
    await supabaseClient
        .auth
        .getSession();

    await fetch(
        "https://kgscurlvuevcpkaxdxur.supabase.co/functions/v1/mark-messages-read",
        {
            method: "POST",

            headers: {
                Authorization:
                    `Bearer ${session.access_token}`,
                "Content-Type":
                    "application/json"
            },

            body: JSON.stringify({
                sender_id:
                    senderId
            })
        }
    );

}
