/* ==========================================================================
   KOSMOPOROS — ISLAND ZEN PALETTE & OPERATOR SESSION MANAGER
   ========================================================================== */

(function () {
  "use strict";

  const state = {
    sessionToken: localStorage.getItem("celestia_session_token") || null,
    currentUser: null,
    heartbeatIntervalId: null,
  };

  // --- 1. THEME TOGGLE (ISLAND ZEN SAND vs DARK) ---
  function initTheme() {
    const toggleBtn = document.getElementById("themeToggleBtn");
    const toggleLabel = document.getElementById("themeToggleLabel");

    function applyTheme(theme) {
      const active = (theme === "dark") ? "dark" : "island";
      document.documentElement.setAttribute("data-theme", active);
      try {
        localStorage.setItem("ulpf_theme", active);
      } catch (e) {}

      if (toggleLabel) {
        toggleLabel.textContent = (active === "dark") ? "Theme: Dark" : "Theme: Zen Sand";
      }
    }

    let saved = localStorage.getItem("ulpf_theme") || "island";
    applyTheme(saved);

    if (toggleBtn) {
      toggleBtn.addEventListener("click", () => {
        const current = document.documentElement.getAttribute("data-theme") || "island";
        const next = (current === "dark") ? "island" : "dark";
        applyTheme(next);
      });
    }
  }

  // --- 2. NAVBAR SCROLL EFFECT ---
  function initNavScroll() {
    const nav = document.getElementById("landingNavbar");
    window.addEventListener("scroll", () => {
      if (window.scrollY > 20) {
        nav.classList.add("scrolled");
      } else {
        nav.classList.remove("scrolled");
      }
    });
  }

  // --- 3. OPERATOR SESSION AUTH & PRESENCE ---
  async function checkInitialSession() {
    state.sessionToken = localStorage.getItem("celestia_session_token");
    if (!state.sessionToken) {
      renderUnauthenticatedUI();
      return;
    }

    try {
      const res = await fetch("/api/v1/auth/me", {
        headers: { "Authorization": `Bearer ${state.sessionToken}` }
      });
      if (res.ok) {
        const data = await res.json();
        state.currentUser = data.user;
        renderAuthenticatedUI();
        startPresenceHeartbeat();
      } else {
        localStorage.removeItem("celestia_session_token");
        state.sessionToken = null;
        state.currentUser = null;
        renderUnauthenticatedUI();
      }
    } catch (err) {
      console.warn("Session check error:", err);
      renderUnauthenticatedUI();
    }
  }

  function renderAuthenticatedUI() {
    const navAuth = document.getElementById("navAuthContainer");
    const heroBanner = document.getElementById("heroSessionBanner");
    const heroText = document.getElementById("heroSessionText");

    const username = state.currentUser ? (state.currentUser.full_name || state.currentUser.username) : "Operator";

    if (navAuth) {
      navAuth.innerHTML = `
        <div style="display:flex; align-items:center; gap:8px;">
          <span class="presence-indicator-dot" title="Presence Active - Twilio Voice Calls Paused"></span>
          <span style="font-size:13px; font-weight:700; color:var(--text-main);">${escapeHtml(username)}</span>
          <button onclick="window.logoutSession()" class="btn-outline-pill" style="padding:4px 10px; font-size:11px;">
            Sign Out
          </button>
        </div>
      `;
    }

    if (heroBanner) {
      heroBanner.style.display = "inline-flex";
      if (heroText) {
        heroText.innerHTML = `Logged in as <strong>${escapeHtml(username)}</strong> &bull; Presence Active (Telephony Paused)`;
      }
    }
  }

  function renderUnauthenticatedUI() {
    const navAuth = document.getElementById("navAuthContainer");
    const heroBanner = document.getElementById("heroSessionBanner");

    if (navAuth) {
      navAuth.innerHTML = `
        <button class="btn-outline-pill" onclick="window.openAuthModal('login')">
          Operator Session
        </button>
      `;
    }

    if (heroBanner) {
      heroBanner.style.display = "none";
    }

    if (state.heartbeatIntervalId) {
      clearInterval(state.heartbeatIntervalId);
      state.heartbeatIntervalId = null;
    }
  }

  let lastLandingPing = 0;
  function startPresenceHeartbeat() {
    sendPresencePing();
    if (!state.heartbeatIntervalId) {
      state.heartbeatIntervalId = setInterval(sendPresencePing, 8000);
      window.addEventListener("focus", sendPresencePing);
      window.addEventListener("click", sendPresencePing);
      window.addEventListener("keydown", sendPresencePing);
      window.addEventListener("mousemove", () => {
        if (Date.now() - lastLandingPing > 15000) sendPresencePing();
      });
    }
  }

  async function sendPresencePing() {
    const now = Date.now();
    if (now - lastLandingPing < 3000) return;
    lastLandingPing = now;
    try {
      const activeToken = state.sessionToken || "guest_web_session";
      const headers = { "Content-Type": "application/json" };
      if (state.sessionToken) {
        headers["Authorization"] = `Bearer ${state.sessionToken}`;
      }
      await fetch("/api/v1/auth/heartbeat", {
        method: "POST",
        headers: headers,
        body: JSON.stringify({
          token: activeToken,
          is_visible: document.visibilityState === "visible"
        })
      });
    } catch (e) {}
  }

  let postAuthRedirect = "/dashboard/";

  // --- 4. AUTH MODAL CONTROLLERS & LAUNCH CONSOLE LINKING ---
  window.launchConsoleWithAuth = function (e, targetUrl = "/dashboard/") {
    if (e && e.preventDefault) e.preventDefault();
    postAuthRedirect = targetUrl;
    if (state.currentUser && state.sessionToken) {
      window.location.href = targetUrl;
    } else {
      window.openAuthModal("login", targetUrl);
    }
  };

  window.openAuthModal = function (tab = "login", redirectTarget = "/dashboard/") {
    postAuthRedirect = redirectTarget;
    const modal = document.getElementById("authModal");
    if (modal) {
      modal.classList.add("active");
      window.switchModalTab(tab);

      const loginSubmitBtn = document.getElementById("modalLoginSubmit");
      const signupSubmitBtn = document.getElementById("modalSignupSubmit");
      if (redirectTarget === "/dashboard/") {
        if (loginSubmitBtn) loginSubmitBtn.textContent = "Authenticate & Enter SOC Console \u2192";
        if (signupSubmitBtn) signupSubmitBtn.textContent = "Register & Enter SOC Console \u2192";
      } else {
        if (loginSubmitBtn) loginSubmitBtn.textContent = "Authenticate & Start Session";
        if (signupSubmitBtn) signupSubmitBtn.textContent = "Register & Create Session";
      }
    }
  };

  window.closeAuthModal = function () {
    const modal = document.getElementById("authModal");
    if (modal) {
      modal.classList.remove("active");
    }
  };

  window.switchModalTab = function (tab) {
    const loginBtn = document.getElementById("tabLoginBtn");
    const signupBtn = document.getElementById("tabSignupBtn");
    const loginForm = document.getElementById("modalLoginForm");
    const signupForm = document.getElementById("modalSignupForm");

    if (tab === "signup") {
      if (loginBtn) loginBtn.classList.remove("active");
      if (signupBtn) signupBtn.classList.add("active");
      if (loginForm) loginForm.style.display = "none";
      if (signupForm) signupForm.style.display = "block";
    } else {
      if (signupBtn) signupBtn.classList.remove("active");
      if (loginBtn) loginBtn.classList.add("active");
      if (signupForm) signupForm.style.display = "none";
      if (loginForm) loginForm.style.display = "block";
    }
  };

  window.handleModalLogin = async function (e) {
    if (e && e.preventDefault) e.preventDefault();
    const userInput = document.getElementById("modalLoginUser");
    const passInput = document.getElementById("modalLoginPass");
    const submitBtn = document.getElementById("modalLoginSubmit");

    if (!userInput || !passInput) return;
    const username = userInput.value.trim();
    const password = passInput.value;

    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.textContent = "Authenticating & Entering Console...";
    }

    try {
      const res = await fetch("/api/v1/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || "Invalid operator credentials.");
      }

      state.sessionToken = data.token;
      state.currentUser = data.user;
      localStorage.setItem("celestia_session_token", data.token);

      window.closeAuthModal();
      renderAuthenticatedUI();
      startPresenceHeartbeat();

      if (postAuthRedirect) {
        window.location.href = postAuthRedirect;
      }
    } catch (err) {
      alert("Authentication Failed: " + err.message);
    } finally {
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.textContent = "Authenticate & Enter SOC Console \u2192";
      }
    }
  };

  window.handleModalSignup = async function (e) {
    if (e && e.preventDefault) e.preventDefault();
    const nameInput = document.getElementById("modalSignupName");
    const userInput = document.getElementById("modalSignupUser");
    const emailInput = document.getElementById("modalSignupEmail");
    const passInput = document.getElementById("modalSignupPass");
    const roleInput = document.getElementById("modalSignupRole");
    const submitBtn = document.getElementById("modalSignupSubmit");

    if (!userInput || !emailInput || !passInput) return;
    const fullName = nameInput ? nameInput.value.trim() : "";
    const username = userInput.value.trim();
    const email = emailInput.value.trim();
    const password = passInput.value;
    const role = roleInput ? roleInput.value : "operator";

    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.textContent = "Creating Session & Entering Console...";
    }

    try {
      const res = await fetch("/api/v1/auth/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username,
          email,
          password,
          full_name: fullName,
          role
        })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || "Registration failed.");
      }

      state.sessionToken = data.token;
      state.currentUser = data.user;
      localStorage.setItem("celestia_session_token", data.token);

      window.closeAuthModal();
      renderAuthenticatedUI();
      startPresenceHeartbeat();

      if (postAuthRedirect) {
        window.location.href = postAuthRedirect;
      }
    } catch (err) {
      alert("Registration Error: " + err.message);
    } finally {
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.textContent = "Register & Enter SOC Console \u2192";
      }
    }
  };

  window.logoutSession = async function () {
    if (state.sessionToken) {
      try {
        await fetch("/api/v1/auth/logout", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${state.sessionToken}`
          },
          body: JSON.stringify({ token: state.sessionToken })
        });
      } catch (e) {}
    }

    localStorage.removeItem("celestia_session_token");
    state.sessionToken = null;
    state.currentUser = null;
    renderUnauthenticatedUI();
  };

  // Close modal when clicking outside
  window.addEventListener("click", (e) => {
    const modal = document.getElementById("authModal");
    if (modal && e.target === modal) {
      window.closeAuthModal();
    }
  });

  // --- 5. TERMINAL STREAM SIMULATION ---
  function initTerminalStream() {
    const term = document.getElementById("terminalStream");
    const hashEl = document.getElementById("liveMerkleHash");
    if (!term) return;

    const sampleLogs = [
      { tag: "[eBPF-TC]", color: "var(--primary-emerald)", msg: "Intercepted SYN scan on port 445 from 45.33.32.156" },
      { tag: "[OCSF]", color: "#38BDF8", msg: "Normalized Cisco ASA syslog &rarr; class_uid: 4001 (Network Activity)" },
      { tag: "[MERKLE]", color: "var(--primary-emerald)", msg: "Calculated SHA-256 leaf. Tree height 14 verified." },
      { tag: "[PRESENCE]", color: "#F59E0B", msg: "Active operator presence confirmed. Telephony call paused." },
      { tag: "[REDPANDA]", color: "#8B5CF6", msg: "Batch committed to topic ulpf-events-normalized (partition 0)" }
    ];

    let idx = 0;
    setInterval(() => {
      const item = sampleLogs[idx % sampleLogs.length];
      idx++;

      const now = new Date();
      const timeStr = `[${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}]`;

      const row = document.createElement("div");
      row.className = "terminal-log-row";
      row.innerHTML = `<span style="color:#78716C;">${timeStr}</span> <span style="color:${item.color};">${item.tag}</span> ${item.msg}`;

      term.appendChild(row);
      while (term.children.length > 5) {
        term.removeChild(term.children[0]);
      }

      if (hashEl && Math.random() > 0.4) {
        const hex = "0123456789abcdef";
        let h = "sha256:";
        for (let i = 0; i < 64; i++) h += hex[Math.floor(Math.random() * hex.length)];
        hashEl.textContent = h;
      }
    }, 2600);
  }

  window.simulateAttack = function () {
    const term = document.getElementById("terminalStream");
    if (!term) return;
    const now = new Date();
    const timeStr = `[${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}]`;
    const row = document.createElement("div");
    row.className = "terminal-log-row";
    row.innerHTML = `<span style="color:#78716C;">${timeStr}</span> <span style="color:#EF4444; font-weight:700;">[CRITICAL THREAT]</span> MITRE T1059: Kernel bytecode blocked execution!`;
    term.appendChild(row);
    while (term.children.length > 5) {
      term.removeChild(term.children[0]);
    }
  };

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // Check URL hash for modal opening (e.g. /#login, /#auth, /#signup)
  function handleUrlHash() {
    const hash = (window.location.hash || "").toLowerCase();
    if (hash === "#login" || hash === "#auth") {
      window.openAuthModal("login", "/dashboard/");
    } else if (hash === "#signup" || hash === "#register") {
      window.openAuthModal("signup", "/dashboard/");
    }
  }

  // Initialize
  function init() {
    initTheme();
    initNavScroll();
    checkInitialSession();
    startPresenceHeartbeat();
    initTerminalStream();
    handleUrlHash();
    window.addEventListener("hashchange", handleUrlHash);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
