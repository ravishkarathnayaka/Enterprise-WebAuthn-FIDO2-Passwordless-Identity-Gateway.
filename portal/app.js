/**
 * Enterprise WebAuthn / FIDO2 Identity Gateway - Showcase Application Logic
 * Powers both live browser WebAuthn ceremonies and the cloud-deployable Cryptographic Simulator.
 */

// Global State
const state = {
  backendUrl: "http://localhost:8000",
  mode: "simulator", // "simulator" or "live"
  user: {
    username: "alice.security@enterprise.corp",
    displayName: "Alice Security Architect",
  },
  storedCredential: {
    id: "aXJ1OWZzN2FzZGY4YWFzZGZhc2RmOTg3Y2JhcWVyMTE=",
    signCount: 10,
    aaguid: "ea9b8d66-4d01-1d21-3ce2-b6b47c66d10c",
    publicKeyAlgo: "ES256 (COSE -7: ECDSA with SHA-256)",
  },
  session: {
    authenticated: false,
    token: null,
    authTime: null,
    stepUpTimer: null,
    stepUpRemaining: 60,
  },
  registeredKeys: [
    {
      id: "aXJ1OWZzN2FzZGY4YWFzZGZhc2RmOTg3Y2JhcWVyMTE=",
      nickname: "Work MacBook Pro (Touch ID)",
      aaguid: "ea9b8d66-4d01-1d21-3ce2-b6b47c66d10c",
      vendor: "Apple Inc.",
      model: "Apple Secure Enclave (Touch ID / Face ID)",
      assurance: "L2 - Hardware Secure Enclave",
      formFactor: "platform",
      signCount: 10,
      transports: ["internal"],
      createdAt: "2026-09-20T14:32:00Z"
    },
    {
      id: "bW9iaWxlX2ZpZG8yX2tleV84ODNhYmNkZQ==",
      nickname: "Corporate YubiKey 5 NFC (Hardware Token)",
      aaguid: "ee5537a5-911a-4c91-881e-9883380b997f",
      vendor: "Yubico",
      model: "YubiKey 5 Series (NFC / USB-C)",
      assurance: "L3 - FIPS 140-2 Level 3 Hardware",
      formFactor: "roaming",
      signCount: 47,
      transports: ["usb", "nfc"],
      createdAt: "2026-09-18T09:15:00Z"
    },
    {
      id: "d2luZG93c19oZWxsb190cG1fOTg3MTIzNDU=",
      nickname: "Engineering ThinkPad (Windows Hello)",
      aaguid: "08987058-cadc-4b81-b6e1-30de50dcbe96",
      vendor: "Windows Hello",
      model: "Microsoft Windows Hello (TPM 2.0)",
      assurance: "L2 - Hardware TPM Protected",
      formFactor: "platform",
      signCount: 23,
      transports: ["internal"],
      createdAt: "2026-09-15T11:20:00Z"
    },
    {
      id: "Z29vZ2xlX3RpdGFuX3NlY3VyaXR5X2tleV8wMQ==",
      nickname: "Root Admin Titan FIDO2 Key",
      aaguid: "42358055-680c-4861-a08b-6f29da2d80d5",
      vendor: "Google",
      model: "Google Titan Security Key",
      assurance: "L3 - Common Criteria EAL6+ Chip",
      formFactor: "roaming",
      signCount: 8,
      transports: ["usb", "nfc"],
      createdAt: "2026-09-10T16:45:00Z"
    }
  ]
};

// Utilities
function logTerminal(message, type = "info") {
  const terminal = document.getElementById("terminalOutput");
  if (!terminal) return;

  const now = new Date();
  const timeStr = now.toTimeString().split(" ")[0] + "." + String(now.getMilliseconds()).padStart(3, "0");

  const entry = document.createElement("div");
  entry.className = `terminal-entry ${type}`;
  entry.innerHTML = `<span class="ts">[${timeStr}]</span> <span class="msg">${message}</span>`;

  terminal.appendChild(entry);
  terminal.scrollTop = terminal.scrollHeight;
}

function updateJsonViewer(elementId, data) {
  const el = document.getElementById(elementId);
  if (el) {
    el.textContent = typeof data === "string" ? data : JSON.stringify(data, null, 2);
  }
}

function generateRandomBase64URL(bytesCount = 32) {
  const array = new Uint8Array(bytesCount);
  window.crypto.getRandomValues(array);
  let binary = "";
  for (let i = 0; i < array.length; i++) {
    binary += String.fromCharCode(array[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

// -----------------------------------------------------------------------------
// Interactive Simulator Operations
// -----------------------------------------------------------------------------

function simulateRegistration() {
  const username = document.getElementById("simUsername")?.value || state.user.username;
  const displayName = document.getElementById("simDisplayName")?.value || state.user.displayName;
  
  logTerminal(`[CEREMONY] Initiating WebAuthn Registration for: ${username}...`, "info");
  
  // Step 1: Options Generation
  const challenge = generateRandomBase64URL(32);
  const options = {
    rp: {
      name: "Enterprise WebAuthn Gateway",
      id: "enterprise-gateway.internal"
    },
    user: {
      id: generateRandomBase64URL(16),
      name: username,
      displayName: displayName
    },
    challenge: challenge,
    pubKeyCredParams: [
      { alg: -7, type: "public-key" },  // ES256
      { alg: -257, type: "public-key" }, // RS256
      { alg: -8, type: "public-key" }   // Ed25519
    ],
    authenticatorSelection: {
      authenticatorAttachment: "platform",
      residentKey: "preferred",
      userVerification: "preferred"
    },
    timeout: 120000,
    attestation: "none"
  };

  updateJsonViewer("payloadViewer", options);
  logTerminal(`Generated PublicKeyCredentialCreationOptions. Nonce: ${challenge.slice(0, 16)}... (TTL=120s)`, "info");

  setTimeout(() => {
    // Step 2: Hardware Touch / Biometric
    logTerminal(`[HARDWARE] Touch ID / Windows Hello / YubiKey interaction simulated.`, "success");
    logTerminal(`[CRYPTOGRAPHY] Generating P-256 asymmetric key pair in hardware secure enclave...`, "info");
    
    // Step 3: Attestation Output
    const newCredId = generateRandomBase64URL(32);
    state.storedCredential.id = newCredId;
    state.storedCredential.signCount = 0;

    const attestationResult = {
      status: "ok",
      message: "Passkey registered successfully",
      credential: {
        id: newCredId,
        type: "public-key",
        aaguid: "08987058-cadc-4b81-b6e1-30de50dcbe96",
        algorithm: "ES256 (NIST P-256)",
        initialSignCount: 0,
        userVerified: true,
        transports: ["internal", "hybrid"]
      }
    };

    updateJsonViewer("payloadViewer", attestationResult);
    logTerminal(`[VERIFY] Attestation statement verified. Stored Credential ID=${newCredId.slice(0, 16)}...`, "success");
    
    document.getElementById("storedCounterDisplay").textContent = "0";
    document.getElementById("incomingCounterDisplay").textContent = "1";
    document.getElementById("activeCredId").textContent = newCredId.slice(0, 20) + "...";
  }, 400);
}

function simulateAuthentication(isReplayAttack = false) {
  logTerminal(`[CEREMONY] Initiating WebAuthn Assertion for: ${state.user.username}...`, "info");

  const challenge = generateRandomBase64URL(32);
  const authOptions = {
    challenge: challenge,
    timeout: 120000,
    rpId: "enterprise-gateway.internal",
    allowCredentials: [
      {
        id: state.storedCredential.id,
        type: "public-key",
        transports: ["internal", "hybrid"]
      }
    ],
    userVerification: "preferred"
  };

  updateJsonViewer("payloadViewer", authOptions);
  logTerminal(`Generated PublicKeyCredentialRequestOptions. Challenge: ${challenge.slice(0, 16)}...`, "info");

  setTimeout(() => {
    const currentStored = state.storedCredential.signCount;
    let incomingCounter = currentStored + 1;

    if (isReplayAttack) {
      // Replay or cloned token: counter is frozen or equal
      incomingCounter = currentStored;
      logTerminal(`[ATTACK SIMULATION] Captured assertion replayed with frozen sign_count = ${incomingCounter}`, "warning");
    } else {
      logTerminal(`[AUTHENTICATOR] User verification verified (Biometrics). Incremented hardware counter to ${incomingCounter}`, "info");
    }

    document.getElementById("storedCounterDisplay").textContent = String(currentStored);
    document.getElementById("incomingCounterDisplay").textContent = String(incomingCounter);

    // Gateway counter check
    if (incomingCounter <= currentStored && currentStored > 0) {
      // REPLAY DETECTED!
      const errorPayload = {
        error: "counter_replay_detected",
        status_code: 403,
        message: "Cloned authenticator or replay attack detected. Signature counter not incremented.",
        stored_counter: currentStored,
        received_counter: incomingCounter,
        alert_level: "CRITICAL"
      };

      updateJsonViewer("payloadViewer", errorPayload);
      logTerminal(`[CRITICAL SECURITY ALERT] Gateway rejected assertion! received_counter (${incomingCounter}) <= stored_counter (${currentStored})`, "danger");
      logTerminal(`[ALERT] HTTP 403 Forbidden dispatched. Incident logged to SIEM / audit ledger.`, "danger");
    } else {
      // SUCCESSFUL AUTHENTICATION
      state.storedCredential.signCount = incomingCounter;
      state.session.authenticated = true;
      state.session.authTime = Date.now();
      state.session.token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + generateRandomBase64URL(48);

      const successPayload = {
        status: "ok",
        message: "Passkey authenticated successfully",
        session: {
          user: state.user.username,
          credential_id: state.storedCredential.id.slice(0, 16) + "...",
          sign_count: incomingCounter,
          user_verified: true,
          auth_time: Math.floor(state.session.authTime / 1000),
          step_up_valid: true
        }
      };

      updateJsonViewer("payloadViewer", successPayload);
      logTerminal(`[SUCCESS] Signature verified (ES256). Stored counter updated: ${currentStored} -> ${incomingCounter}`, "success");
      logTerminal(`[SESSION] Minted HttpOnly short-lived JWT token with auth_time claim.`, "success");

      startStepUpCountdown();
      document.getElementById("storedCounterDisplay").textContent = String(incomingCounter);
      document.getElementById("incomingCounterDisplay").textContent = String(incomingCounter + 1);
    }
  }, 450);
}

// Step-Up Authentication Window Management
function startStepUpCountdown() {
  if (state.session.stepUpTimer) {
    clearInterval(state.session.stepUpTimer);
  }

  state.session.stepUpRemaining = 60;
  updateStepUpBadge();

  state.session.stepUpTimer = setInterval(() => {
    state.session.stepUpRemaining -= 1;
    updateStepUpBadge();
    if (state.session.stepUpRemaining <= 0) {
      clearInterval(state.session.stepUpTimer);
    }
  }, 1000);
}

function updateStepUpBadge() {
  const badge = document.getElementById("stepUpIndicator");
  const text = document.getElementById("stepUpTimeText");
  if (!badge || !text) return;

  if (state.session.stepUpRemaining > 0) {
    badge.className = "badge-defense";
    text.textContent = `Step-Up Active: ${state.session.stepUpRemaining}s remaining`;
  } else {
    badge.style.background = "rgba(245, 158, 11, 0.15)";
    badge.style.color = "#f59e0b";
    badge.style.borderColor = "rgba(245, 158, 11, 0.3)";
    text.textContent = "Step-Up Expired (Re-Auth Required for Transfer)";
  }
}

function simulateStepUpTransfer() {
  logTerminal(`[STEP-UP] Authorizing high-risk wire transfer of $50,000.00...`, "info");

  if (!state.session.authenticated) {
    logTerminal(`[DENIED] Unauthenticated. Must perform Passkey login first.`, "danger");
    updateJsonViewer("payloadViewer", {
      error: "unauthorized",
      message: "Please authenticate with your Passkey first."
    });
    return;
  }

  if (state.session.stepUpRemaining <= 0) {
    logTerminal(`[STEP-UP REQUIRED] Session authentication was executed > 60s ago!`, "warning");
    const stepUpRequiredResponse = {
      error: "step_up_required",
      status_code: 403,
      message: "Step-up authentication required: Re-authenticate with your WebAuthn passkey to authorize this transaction.",
      max_age_seconds: 60,
      auth_age_seconds: 60 + Math.abs(state.session.stepUpRemaining)
    };
    updateJsonViewer("payloadViewer", stepUpRequiredResponse);
    logTerminal(`[CHALLENGE] Prompting user for fresh biometric assertion...`, "warning");
  } else {
    logTerminal(`[STEP-UP VERIFIED] High-risk transfer authorized within ${state.session.stepUpRemaining}s window!`, "success");
    const transferSuccess = {
      status: "success",
      action: "wire_transfer",
      amount: 50000.00,
      currency: "USD",
      recipient: "Escrow Reserve Liquidity Account #9921",
      authorized_by: state.user.username,
      credential_id: state.storedCredential.id.slice(0, 16) + "...",
      auth_timestamp: Math.floor(state.session.authTime / 1000)
    };
    updateJsonViewer("payloadViewer", transferSuccess);
  }
}

function simulateUpstreamProxy() {
  logTerminal(`[PROXY] Forwarding request to Upstream Microservice (/upstream/api/confidential-records)...`, "info");

  if (!state.session.authenticated) {
    logTerminal(`[PROXY 401] Unauthorized access attempt blocked by reverse proxy.`, "danger");
    updateJsonViewer("payloadViewer", {
      error: "unauthorized",
      message: "Authentication required. Route requests through WebAuthn Gateway."
    });
    return;
  }

  const upstreamData = {
    service: "Internal Confidential Microservice (Port 8001)",
    routing: "Injected via Gateway Reverse Proxy Middleware",
    forwarded_headers: {
      "X-Authenticated-User": state.user.username,
      "X-Passkey-Credential-Id": state.storedCredential.id.slice(0, 16) + "...",
      "X-User-Verified": "true",
      "X-Auth-Time": String(Math.floor(state.session.authTime / 1000))
    },
    confidential_records: [
      {
        id: "SEC-2026-001",
        title: "SOC 2 Type II Cryptographic Attestation Report",
        status: "Compliant"
      },
      {
        id: "SEC-2026-002",
        title: "Quantum-Resistant HSM Hardware Key Inventory",
        status: "Rotated"
      }
    ]
  };

  updateJsonViewer("payloadViewer", upstreamData);
  logTerminal(`[PROXY 200 OK] Upstream confidential payload received and rendered.`, "success");
}

// -----------------------------------------------------------------------------
// Live Hardware Authenticator (WebAuthn API)
// -----------------------------------------------------------------------------

async function handleLiveRegistration() {
  if (!window.PublicKeyCredential) {
    alert("WebAuthn is not supported in this browser environment.");
    return;
  }

  const username = document.getElementById("simUsername")?.value || state.user.username;
  logTerminal(`[LIVE WEBAUTHN] Requesting registration options from Gateway at ${state.backendUrl}...`, "info");

  try {
    const res = await fetch(`${state.backendUrl}/api/auth/register/options`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: username }),
    });

    if (!res.ok) {
      throw new Error(`Failed to reach gateway at ${state.backendUrl}. Is the local gateway running?`);
    }

    const data = await res.json();
    logTerminal(`Received options from Gateway. Prompting device authenticator...`, "info");
    updateJsonViewer("payloadViewer", data.options);

    // Call browser WebAuthn API
    if (window.webAuthnClient) {
      const verifyRes = await window.webAuthnClient.register(username);
      logTerminal(`[LIVE WEBAUTHN] Registration verified by Gateway! Credential ID: ${verifyRes.credential_id}`, "success");
      updateJsonViewer("payloadViewer", verifyRes);
    }
  } catch (err) {
    logTerminal(`[LIVE ERROR] ${err.message}`, "danger");
    alert(`Could not connect to live gateway: ${err.message}\n(Falling back to Interactive Simulator mode).`);
  }
}

// -----------------------------------------------------------------------------
// Credential Management & AAGUID Badges
// -----------------------------------------------------------------------------

function renderCredentials() {
  const container = document.getElementById("credentialsListGrid");
  if (!container) return;

  container.innerHTML = "";

  if (state.registeredKeys.length === 0) {
    container.innerHTML = `
      <div class="glass-card" style="grid-column: 1 / -1; text-align: center; padding: 40px;">
        <p style="color: var(--text-muted); font-size: 1.1rem; margin-bottom: 16px;">No passkeys registered yet.</p>
        <button class="cyber-btn cyber-btn-emerald" onclick="enrollDemoKey()">Enroll First Hardware Key</button>
      </div>
    `;
    return;
  }

  state.registeredKeys.forEach(cred => {
    const card = document.createElement("div");
    card.className = "glass-card";
    card.style.display = "flex";
    card.style.flexDirection = "column";
    card.style.justifyContent = "space-between";

    const transportsHtml = cred.transports
      ? cred.transports.map(t => `<span class="threat-badge badge-defense" style="font-size: 0.72rem; padding: 2px 8px; margin-right: 4px;">${t.toUpperCase()}</span>`).join("")
      : "";

    card.innerHTML = `
      <div>
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px;">
          <div>
            <span class="threat-badge badge-defense" style="margin-bottom: 6px;">${cred.assurance}</span>
            <h4 style="font-size: 1.15rem; color: var(--text-primary); margin-top: 4px;">${cred.nickname}</h4>
          </div>
          <span style="font-size: 0.75rem; color: var(--accent-cyan); font-family: var(--font-mono);">${cred.vendor}</span>
        </div>

        <div style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 10px;">
          <strong>Model:</strong> ${cred.model}
        </div>

        <div style="font-size: 0.8rem; font-family: var(--font-mono); color: var(--text-muted); word-break: break-all; margin-bottom: 12px; background: rgba(0,0,0,0.3); padding: 8px; border-radius: 6px;">
          <div><strong>AAGUID:</strong> ${cred.aaguid}</div>
          <div style="margin-top: 4px;"><strong>Credential ID:</strong> ${cred.id.slice(0, 24)}...</div>
        </div>

        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
          <div style="font-size: 0.85rem; color: var(--text-secondary);">
            Counter: <span style="font-family: var(--font-mono); color: var(--accent-emerald); font-weight: 700;">${cred.signCount}</span>
          </div>
          <div>${transportsHtml}</div>
        </div>
      </div>

      <div style="display: flex; gap: 8px; border-top: 1px solid var(--border-subtle); padding-top: 14px; margin-top: 10px;">
        <button class="cyber-btn cyber-btn-outline" style="flex: 1; padding: 8px;" onclick="renameCredentialPrompt('${cred.id}')">
          Rename
        </button>
        <button class="cyber-btn" style="flex: 1; padding: 8px; background: rgba(244, 63, 94, 0.2); color: #fca5a5; border: 1px solid rgba(244, 63, 94, 0.3);" onclick="revokeCredential('${cred.id}')">
          Revoke
        </button>
      </div>
    `;

    container.appendChild(card);
  });
}

function renameCredentialPrompt(credId) {
  const cred = state.registeredKeys.find(c => c.id === credId);
  if (!cred) return;

  const newName = prompt(`Enter new friendly name for ${cred.vendor} passkey:`, cred.nickname);
  if (newName && newName.trim()) {
    cred.nickname = newName.trim();
    renderCredentials();
    logTerminal(`[CREDENTIAL_MANAGEMENT] Renamed passkey (${cred.id.slice(0, 12)}...) to '${cred.nickname}'`, "info");
  }
}

function revokeCredential(credId) {
  const cred = state.registeredKeys.find(c => c.id === credId);
  if (!cred) return;

  if (confirm(`Are you sure you want to permanently revoke '${cred.nickname}'? It will be removed from the authenticator registry.`)) {
    state.registeredKeys = state.registeredKeys.filter(c => c.id !== credId);
    renderCredentials();
    logTerminal(`[SECURITY_ALERT] Permanently revoked credential: ${cred.id.slice(0, 16)}... (${cred.model})`, "danger");
  }
}

function enrollDemoKey() {
  const vendors = [
    {
      vendor: "Yubico",
      model: "YubiKey Bio Series (Biometric Hardware)",
      assurance: "L3 - Biometric Hardware Sensor",
      aaguid: "fa2b99dc-9e39-4257-8f92-4a30d23c4118",
      formFactor: "roaming",
      transports: ["usb", "nfc"]
    },
    {
      vendor: "Apple Inc.",
      model: "Apple Secure Enclave (Touch ID / Face ID)",
      assurance: "L2 - Hardware Secure Enclave",
      aaguid: "ea9b8d66-4d01-1d21-3ce2-b6b47c66d10c",
      formFactor: "platform",
      transports: ["internal"]
    },
    {
      vendor: "Google",
      model: "Google Titan Security Key",
      assurance: "L3 - Common Criteria EAL6+ Chip",
      aaguid: "42358055-680c-4861-a08b-6f29da2d80d5",
      formFactor: "roaming",
      transports: ["usb", "nfc"]
    }
  ];

  const pick = vendors[Math.floor(Math.random() * vendors.length)];
  const newCred = {
    id: generateRandomBase64URL(32),
    nickname: `${pick.vendor} Enrolled Token #${state.registeredKeys.length + 1}`,
    aaguid: pick.aaguid,
    vendor: pick.vendor,
    model: pick.model,
    assurance: pick.assurance,
    formFactor: pick.formFactor,
    signCount: 0,
    transports: pick.transports,
    createdAt: new Date().toISOString()
  };

  state.registeredKeys.unshift(newCred);
  renderCredentials();
  logTerminal(`[CREDENTIAL_ENROLL] Registered new authenticator: ${newCred.nickname} (AAGUID: ${newCred.aaguid})`, "success");
}

// -----------------------------------------------------------------------------
// Live Prometheus Telemetry & Observability
// -----------------------------------------------------------------------------

const telemetryState = {
  httpTotal: 142,
  regTotal: 24,
  authSuccess: 68,
  replayViolations: 3,
  stepUpAuthorized: 19,
  p95LatencyMs: 18
};

function updateTelemetryView() {
  const elHttp = document.getElementById("metricHttpTotal");
  const elSuccess = document.getElementById("metricAuthSuccess");
  const elReplay = document.getElementById("metricReplayViolations");
  const elLatency = document.getElementById("metricLatencyP95");
  const elRegTotal = document.getElementById("metricRegTotal");
  const elAuthCount = document.getElementById("metricAuthSuccessCount");
  const elReplayCount = document.getElementById("metricReplayCount");
  const elStepUpCount = document.getElementById("metricStepUpCount");
  const rawText = document.getElementById("rawPrometheusMetrics");

  if (elHttp) elHttp.textContent = telemetryState.httpTotal;
  if (elSuccess) elSuccess.textContent = telemetryState.authSuccess;
  if (elReplay) elReplay.textContent = telemetryState.replayViolations;
  if (elLatency) elLatency.textContent = `${telemetryState.p95LatencyMs} ms`;
  if (elRegTotal) elRegTotal.textContent = telemetryState.regTotal;
  if (elAuthCount) elAuthCount.textContent = telemetryState.authSuccess;
  if (elReplayCount) elReplayCount.textContent = telemetryState.replayViolations;
  if (elStepUpCount) elStepUpCount.textContent = telemetryState.stepUpAuthorized;

  if (rawText) {
    rawText.textContent = `# HELP webauthn_registration_requests_total Total number of WebAuthn registration ceremonies.
# TYPE webauthn_registration_requests_total counter
webauthn_registration_requests_total ${telemetryState.regTotal}

# HELP webauthn_authentication_attempts_total Total WebAuthn authentication attempts by outcome.
# TYPE webauthn_authentication_attempts_total counter
webauthn_authentication_attempts_total{status="success"} ${telemetryState.authSuccess}
webauthn_authentication_attempts_total{status="replay_detected"} ${telemetryState.replayViolations}

# HELP webauthn_counter_replay_violations_total Number of detected cloned hardware key replay attempts.
# TYPE webauthn_counter_replay_violations_total counter
webauthn_counter_replay_violations_total ${telemetryState.replayViolations}

# HELP webauthn_step_up_challenges_total Total step-up authorization challenges by result.
# TYPE webauthn_step_up_challenges_total counter
webauthn_step_up_challenges_total{status="authorized"} ${telemetryState.stepUpAuthorized}
webauthn_step_up_challenges_total{status="expired"} 1

# HELP gateway_http_requests_total Total HTTP requests routed through Identity Gateway.
# TYPE gateway_http_requests_total counter
gateway_http_requests_total{method="POST",path="/api/auth/login/verify",status="200"} ${telemetryState.authSuccess}
gateway_http_requests_total{method="POST",path="/api/auth/login/verify",status="403"} ${telemetryState.replayViolations}
gateway_http_requests_total{method="POST",path="/api/auth/register/options",status="200"} ${telemetryState.regTotal}
gateway_http_requests_total{method="GET",path="/health",status="200"} 45
`;
  }
}

async function fetchPrometheusMetrics() {
  logTerminal("[OBSERVABILITY] Scraping /metrics from WebAuthn Gateway...", "info");
  try {
    const res = await fetch(`${state.backendUrl}/metrics`);
    if (res.ok) {
      const text = await res.text();
      const rawText = document.getElementById("rawPrometheusMetrics");
      if (rawText) rawText.textContent = text;
      logTerminal("[OBSERVABILITY] Successfully scraped live Prometheus metrics from gateway!", "success");
      return;
    }
  } catch {
    // Fall back to local simulator metrics
  }
  telemetryState.httpTotal += Math.floor(Math.random() * 3) + 1;
  updateTelemetryView();
  logTerminal("[OBSERVABILITY] Refreshed real-time telemetry metrics buffer.", "info");
}

// -----------------------------------------------------------------------------
// UI Tabs & Event Listeners
// -----------------------------------------------------------------------------

document.addEventListener("DOMContentLoaded", () => {
  // Check Browser WebAuthn capability
  const statusPill = document.getElementById("browserWebAuthnPill");
  if (window.PublicKeyCredential) {
    if (statusPill) statusPill.textContent = "FIDO2 / WebAuthn Hardware API Active";
    logTerminal("Browser WebAuthn API detected: navigator.credentials is active.", "success");
  } else {
    if (statusPill) statusPill.textContent = "Simulated Cryptographic Mode";
    logTerminal("Hardware WebAuthn API not detected in this context. Running in Cryptographic Simulator mode.", "warning");
  }

  // Bind Buttons
  document.getElementById("btnSimRegister")?.addEventListener("click", () => {
    telemetryState.httpTotal += 2;
    telemetryState.regTotal += 1;
    updateTelemetryView();
    simulateRegistration();
  });
  document.getElementById("btnSimAuth")?.addEventListener("click", () => {
    telemetryState.httpTotal += 2;
    telemetryState.authSuccess += 1;
    updateTelemetryView();
    simulateAuthentication(false);
  });
  document.getElementById("btnSimReplay")?.addEventListener("click", () => {
    telemetryState.httpTotal += 2;
    telemetryState.replayViolations += 1;
    updateTelemetryView();
    simulateAuthentication(true);
  });
  document.getElementById("btnSimTransfer")?.addEventListener("click", () => {
    telemetryState.httpTotal += 1;
    telemetryState.stepUpAuthorized += 1;
    updateTelemetryView();
    simulateStepUpTransfer();
  });
  document.getElementById("btnSimUpstream")?.addEventListener("click", () => {
    telemetryState.httpTotal += 1;
    updateTelemetryView();
    simulateUpstreamProxy();
  });
  document.getElementById("btnAddDemoKey")?.addEventListener("click", () => enrollDemoKey());
  document.getElementById("btnRefreshMetrics")?.addEventListener("click", () => fetchPrometheusMetrics());

  // Live Gateway Button
  document.getElementById("btnLiveRegister")?.addEventListener("click", () => handleLiveRegistration());

  // Tab switcher
  const tabBtns = document.querySelectorAll(".tab-btn");
  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      tabBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");

      const targetTab = btn.getAttribute("data-tab");
      document.querySelectorAll(".tab-content").forEach(c => c.style.display = "none");
      const activeContent = document.getElementById(`tab-${targetTab}`);
      if (activeContent) activeContent.style.display = "block";
    });
  });

  // Render Passkey Manager & Telemetry
  renderCredentials();
  updateTelemetryView();

  // Initial simulation greeting
  logTerminal("Enterprise WebAuthn Gateway Showcase Portal loaded.", "info");
  logTerminal("Interactive Passkey Playground ready. Try registering or simulating a replay attack.", "success");
});
