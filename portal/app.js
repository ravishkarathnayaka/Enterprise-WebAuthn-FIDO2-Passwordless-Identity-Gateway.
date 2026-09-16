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
  }
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
  document.getElementById("btnSimRegister")?.addEventListener("click", () => simulateRegistration());
  document.getElementById("btnSimAuth")?.addEventListener("click", () => simulateAuthentication(false));
  document.getElementById("btnSimReplay")?.addEventListener("click", () => simulateAuthentication(true));
  document.getElementById("btnSimTransfer")?.addEventListener("click", () => simulateStepUpTransfer());
  document.getElementById("btnSimUpstream")?.addEventListener("click", () => simulateUpstreamProxy());

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

  // Initial simulation greeting
  logTerminal("Enterprise WebAuthn Gateway Showcase Portal loaded.", "info");
  logTerminal("Interactive Passkey Playground ready. Try registering or simulating a replay attack.", "success");
});
