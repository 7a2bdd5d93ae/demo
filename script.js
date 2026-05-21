(function () {
    "use strict";

    // ── DOM ──
    var $overlay  = document.getElementById("redirect-overlay");
    var $main     = document.getElementById("main-content");
    var $fallback = document.getElementById("fallback-content");
    var $form     = document.getElementById("lookup-form");
    var $title    = document.getElementById("title");
    var $error    = document.getElementById("error-msg");
    var $fbText   = document.getElementById("fallback-text");

    // ═══════════════════════════════════════════
    //  Crypto helpers  (SHA-256 + PBKDF2 + AES-GCM)
    // ═══════════════════════════════════════════

    function base64ToUint8(b64) {
        var s = atob(b64);
        var a = new Uint8Array(s.length);
        for (var i = 0; i < s.length; i++) a[i] = s.charCodeAt(i);
        return a;
    }

    async function sha256hex(str) {
        var buf = await crypto.subtle.digest(
            "SHA-256", new TextEncoder().encode(str)
        );
        var arr = new Uint8Array(buf);
        var hex = "";
        for (var i = 0; i < arr.length; i++)
            hex += arr[i].toString(16).padStart(2, "0");
        return hex;
    }

    async function deriveKey(password, salt) {
        var km = await crypto.subtle.importKey(
            "raw", new TextEncoder().encode(password),
            "PBKDF2", false, ["deriveKey"]
        );
        return crypto.subtle.deriveKey(
            { name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256" },
            km,
            { name: "AES-GCM", length: 256 },
            false, ["decrypt"]
        );
    }

    async function decryptURL(encoded, password) {
        try {
            var data = base64ToUint8(encoded);
            var salt = data.slice(0, 16);
            var iv   = data.slice(16, 28);
            var ct   = data.slice(28);
            var key  = await deriveKey(password, salt);
            var pt   = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: iv }, key, ct
            );
            return new TextDecoder().decode(pt);
        } catch (e) {
            console.warn("Failed to decrypt configured project URL.", e);
            return null;
        }
    }

    function normalizeTitle(title) {
        return title.toLowerCase()
            .replace(/[^a-z0-9 ]/g, "")
            .replace(/\s+/g, " ")
            .trim();
    }

    // ═══════════════════════════════════════════
    //  Lookup
    // ═══════════════════════════════════════════

    async function findByOpenReviewId(id) {
        var trimmed = id.trim();
        var hash = await sha256hex(trimmed);
        for (var i = 0; i < PAPERS.length; i++) {
            if (PAPERS[i].id_hash === hash) {
                return await decryptURL(PAPERS[i].id_enc, trimmed);
            }
        }
        return null;
    }

    async function findByTitle(title) {
        var raw  = normalizeTitle(title);
        var hash = await sha256hex(raw);
        for (var i = 0; i < PAPERS.length; i++) {
            if (PAPERS[i].title_hash === hash) {
                return await decryptURL(PAPERS[i].title_enc, raw);
            }
        }
        return null;
    }

    // ═══════════════════════════════════════════
    //  Detection
    // ═══════════════════════════════════════════

    function getIdFromURL() {
        var params = new URLSearchParams(window.location.search);
        return params.get("id") || params.get("openreview") || null;
    }

    function getIdFromReferrer() {
        var ref = document.referrer;
        if (!ref) return null;
        try {
            var url = new URL(ref);
            if (url.hostname.indexOf("openreview.net") !== -1) {
                return url.searchParams.get("id") || null;
            }
        } catch (e) {
            console.warn("Unable to parse document referrer.", e);
        }
        return null;
    }

    // ═══════════════════════════════════════════
    //  Redirect & UI
    // ═══════════════════════════════════════════

    function getSafeRedirectURL(url) {
        try {
            var parsed = new URL(url, window.location.href);
            if (parsed.protocol === "http:" || parsed.protocol === "https:") {
                return parsed.href;
            }
        } catch (e) {
            console.warn("Invalid configured project URL.", e);
        }
        return null;
    }

    function redirectTo(url) {
        var safeURL = getSafeRedirectURL(url);
        if (!safeURL) {
            console.error("Blocked redirect to an invalid project URL.");
            showError("The configured project URL is invalid.");
            return;
        }

        $main.classList.add("hidden");
        $fallback.classList.add("hidden");
        $overlay.classList.remove("hidden");
        setTimeout(function () {
            window.location.href = safeURL;
        }, SETTINGS.redirectDelay);
    }

    function stripNewlines(el) {
        el.addEventListener("input", function () {
            var pos = el.selectionStart;
            var cleaned = el.value.replace(/[\r\n]+/g, " ").replace(/\s+/g, " ");
            if (cleaned !== el.value) {
                el.value = cleaned;
                el.selectionStart = el.selectionEnd = Math.min(pos, cleaned.length);
            }
        });
    }

    function showError(msg) {
        $error.textContent = msg;
        $error.classList.remove("hidden");
    }

    function hideError() {
        $error.classList.add("hidden");
    }

    // ═══════════════════════════════════════════
    //  Form submit
    // ═══════════════════════════════════════════

    async function onSubmit(e) {
        e.preventDefault();
        hideError();

        var title = $title.value.trim();
        if (!title) {
            showError("Please enter the paper title.");
            return;
        }

        var url = await findByTitle(title);
        if (url) {
            redirectTo(url);
        } else {
            showError("Paper not found. Please verify the title is correct.");
        }
    }

    // ═══════════════════════════════════════════
    //  Init
    // ═══════════════════════════════════════════

    async function init() {
        if (typeof PAPERS === "undefined" || !Array.isArray(PAPERS)) {
            throw new Error("PAPERS configuration is missing or invalid.");
        }

        if (typeof SETTINGS === "undefined") {
            throw new Error("SETTINGS configuration is missing.");
        }

        if (!window.crypto || !window.crypto.subtle) {
            showError("This browser does not support secure Web Crypto on this page. Please use the hosted HTTPS page.");
            return;
        }

        var id = getIdFromURL();
        if (!id) id = getIdFromReferrer();

        if (id) {
            var url = await findByOpenReviewId(id);
            if (url) { redirectTo(url); return; }
        }

        if (SETTINGS.showManualForm) {
            $main.classList.remove("hidden");
            $form.addEventListener("submit", onSubmit);
            stripNewlines($title);
        } else {
            $fbText.textContent = SETTINGS.fallbackMessage;
            $fallback.classList.remove("hidden");
        }
    }

    init().catch(function (e) {
        console.error("Portal failed to initialize.", e);
        showError("The portal configuration could not be loaded.");
    });
})();
