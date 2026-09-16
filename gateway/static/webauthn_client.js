/**
 * Enterprise WebAuthn / FIDO2 Client Library
 * Handles Base64URL conversions and browser navigator.credentials ceremonies.
 */

class WebAuthnClient {
    constructor(apiBaseUrl = "") {
        this.apiBaseUrl = apiBaseUrl;
    }

    /**
     * Check if WebAuthn is supported in this browser.
     */
    isSupported() {
        return !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.create);
    }

    /**
     * Check if conditional mediation (autofill passkeys) is supported.
     */
    async isConditionalMediationSupported() {
        if (window.PublicKeyCredential && PublicKeyCredential.isConditionalMediationAvailable) {
            try {
                return await PublicKeyCredential.isConditionalMediationAvailable();
            } catch (e) {
                return false;
            }
        }
        return false;
    }

    /**
     * Convert ArrayBuffer or Uint8Array to Base64URL string.
     */
    bufferToBase64URL(buffer) {
        const bytes = new Uint8Array(buffer);
        let str = "";
        for (const charCode of bytes) {
            str += String.fromCharCode(charCode);
        }
        const base64 = btoa(str);
        return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    }

    /**
     * Convert Base64URL string to Uint8Array buffer.
     */
    base64URLToBuffer(base64URL) {
        let base64 = base64URL.replace(/-/g, "+").replace(/_/g, "/");
        while (base64.length % 4 !== 0) {
            base64 += "=";
        }
        const raw = atob(base64);
        const buffer = new Uint8Array(raw.length);
        for (let i = 0; i < raw.length; i++) {
            buffer[i] = raw.charCodeAt(i);
        }
        return buffer;
    }

    /**
     * Convert PublicKeyCredentialCreationOptions JSON from server to ArrayBuffer format.
     */
    _prepareCreationOptions(options) {
        const prepared = { ...options };
        prepared.challenge = this.base64URLToBuffer(options.challenge);
        if (prepared.user && prepared.user.id) {
            if (typeof prepared.user.id === "string") {
                prepared.user.id = this.base64URLToBuffer(prepared.user.id);
            }
        }
        if (prepared.excludeCredentials && Array.isArray(prepared.excludeCredentials)) {
            prepared.excludeCredentials = prepared.excludeCredentials.map(cred => ({
                ...cred,
                id: typeof cred.id === "string" ? this.base64URLToBuffer(cred.id) : cred.id,
            }));
        }
        return prepared;
    }

    /**
     * Convert PublicKeyCredentialRequestOptions JSON from server to ArrayBuffer format.
     */
    _prepareRequestOptions(options) {
        const prepared = { ...options };
        prepared.challenge = this.base64URLToBuffer(options.challenge);
        if (prepared.allowCredentials && Array.isArray(prepared.allowCredentials)) {
            prepared.allowCredentials = prepared.allowCredentials.map(cred => ({
                ...cred,
                id: typeof cred.id === "string" ? this.base64URLToBuffer(cred.id) : cred.id,
            }));
        }
        return prepared;
    }

    /**
     * Register a new Passkey credential.
     */
    async register(username, displayName = "") {
        if (!this.isSupported()) {
            throw new Error("WebAuthn is not supported on this browser or platform.");
        }

        // 1. Fetch registration options
        const optRes = await fetch(`${this.apiBaseUrl}/api/auth/register/options`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, displayName: displayName || username }),
        });

        if (!optRes.ok) {
            const err = await optRes.json().catch(() => ({ detail: "Failed fetching options" }));
            throw new Error(err.detail || err.message || "Failed to initiate registration");
        }

        const { options, challenge } = await optRes.json();
        const creationOptions = this._prepareCreationOptions(options);

        // 2. Invoke authenticator via browser WebAuthn API
        const credential = await navigator.credentials.create({
            publicKey: creationOptions,
        });

        if (!credential) {
            throw new Error("Passkey creation was cancelled or returned no credential.");
        }

        // 3. Serialize credential into JSON
        const transports = credential.response.getTransports ? credential.response.getTransports() : [];
        const registrationData = {
            id: credential.id,
            rawId: this.bufferToBase64URL(credential.rawId),
            type: credential.type,
            response: {
                clientDataJSON: this.bufferToBase64URL(credential.response.clientDataJSON),
                attestationObject: this.bufferToBase64URL(credential.response.attestationObject),
                transports: transports,
            },
        };

        // 4. Send to verification endpoint
        const verifyRes = await fetch(`${this.apiBaseUrl}/api/auth/register/verify`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                credential: registrationData,
                challenge: challenge,
                username: username,
            }),
        });

        const verifyResult = await verifyRes.json();
        if (!verifyRes.ok) {
            throw new Error(verifyResult.detail || verifyResult.message || "Passkey registration verification failed.");
        }

        return verifyResult;
    }

    /**
     * Authenticate using an existing Passkey credential.
     */
    async login(username = "") {
        if (!this.isSupported()) {
            throw new Error("WebAuthn is not supported on this browser or platform.");
        }

        // 1. Fetch login options
        const optRes = await fetch(`${this.apiBaseUrl}/api/auth/login/options`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: username || null }),
        });

        if (!optRes.ok) {
            const err = await optRes.json().catch(() => ({ detail: "Failed fetching login options" }));
            throw new Error(err.detail || err.message || "Failed to initiate authentication");
        }

        const { options, challenge } = await optRes.json();
        const requestOptions = this._prepareRequestOptions(options);

        // 2. Invoke authenticator
        const assertion = await navigator.credentials.get({
            publicKey: requestOptions,
        });

        if (!assertion) {
            throw new Error("Passkey assertion was cancelled or returned no response.");
        }

        // 3. Serialize assertion
        let userHandle = null;
        if (assertion.response.userHandle) {
            userHandle = this.bufferToBase64URL(assertion.response.userHandle);
        }

        const assertionData = {
            id: assertion.id,
            rawId: this.bufferToBase64URL(assertion.rawId),
            type: assertion.type,
            response: {
                clientDataJSON: this.bufferToBase64URL(assertion.response.clientDataJSON),
                authenticatorData: this.bufferToBase64URL(assertion.response.authenticatorData),
                signature: this.bufferToBase64URL(assertion.response.signature),
                userHandle: userHandle,
            },
        };

        // 4. Send to verification endpoint
        const verifyRes = await fetch(`${this.apiBaseUrl}/api/auth/login/verify`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                credential: assertionData,
                challenge: challenge,
            }),
        });

        const verifyResult = await verifyRes.json();
        if (!verifyRes.ok) {
            throw new Error(verifyResult.message || verifyResult.detail || "Authentication verification failed.");
        }

        return verifyResult;
    }
}

// Export singleton instance
window.webAuthnClient = new WebAuthnClient();
