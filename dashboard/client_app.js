document.addEventListener('DOMContentLoaded', () => {
  const cntDispatched = document.getElementById('cnt-dispatched');
  const statusAuto = document.getElementById('status-auto');
  const btnToggleAuto = document.getElementById('btn-toggle-auto');
  const ticker = document.getElementById('client-log-ticker');

  const modalClientPayload = document.getElementById('modal-client-payload');
  const modalClientBody = document.getElementById('modal-client-payload-body');
  const btnCloseClientModal = document.getElementById('btn-close-client-modal');

  let dispatchedCount = 0;
  let autoTimer = null;

  async function dispatchToUlpf(logString, sourceName, category = 'info') {
    dispatchedCount++;
    cntDispatched.innerText = dispatchedCount.toLocaleString();

    const timestamp = new Date().toLocaleTimeString();
    const item = document.createElement('div');
    item.className = `log-ticker-item ${category}`;
    item.innerHTML = `<div>[${timestamp}] [${sourceName}] Sending -> <code>${logString.substring(0, 60)}...</code></div>`;
    
    ticker.prepend(item);
    if (ticker.children.length > 25) {
      ticker.removeChild(ticker.lastChild);
    }

    try {
      const resp = await fetch('/api/v1/ingest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          source: sourceName,
          log: logString
        })
      });
      const data = await resp.json();

      item.innerHTML += `
        <div style="font-size: 10.5px; color: var(--accent-indigo); margin-top: 4px;">
          [OK] ULPF Response Received: Status: <strong>${data.status.toUpperCase()}</strong> | Format: <strong>${data.detected_format}</strong> | Hash: <code>${data.raw_sha256.substring(0, 16)}...</code> (Click to View Full Response)
        </div>
      `;

      item.addEventListener('click', () => openClientModal(data, logString, sourceName));
    } catch (err) {
      item.innerHTML += `<div style="font-size: 10.5px; color: var(--accent-rose); margin-top: 4px;">[ERR] ULPF Server Response Error</div>`;
    }
  }

  function openClientModal(data, rawLog, sourceName) {
    if (!data) return;

    modalClientBody.innerHTML = `
      <div class="step-card-box" style="border-left: 4px solid var(--accent-emerald);">
        <div class="step-card-title" style="color: var(--accent-emerald);">[OK] ULPF Server Response Package</div>
        <div style="font-size: 12px; color: var(--text-main); margin-bottom: 6px;">
          Message: ${data.message || 'Log successfully ingested, normalized, and forwarded onward.'}
        </div>
        <div style="font-family: var(--font-mono); font-size: 11.5px; line-height: 1.6;">
          <div>• <strong>Assigned Event ID:</strong> <code>${data.event_id}</code></div>
          <div>• <strong>Detected Log Format:</strong> <strong>${data.detected_format}</strong></div>
          <div>• <strong>SHA-256 Digest:</strong> <code>${data.raw_sha256}</code></div>
          <div>• <strong>Downstream Forwarded:</strong> <span style="color: var(--accent-emerald); font-weight: bold;">TRUE</span></div>
        </div>
      </div>

      <div class="step-card-box">
        <div class="step-card-title"> Original Raw Message Dispatched</div>
        <pre><code style="font-size: 11px;">${rawLog}</code></pre>
      </div>

      <div class="step-card-box">
        <div class="step-card-title"> Returned Canonical Event (ULPF-IR v0.1)</div>
        <pre><code style="font-size: 11px;">${JSON.stringify(data.canonical_event, null, 2)}</code></pre>
      </div>

      <div class="step-card-box">
        <div class="step-card-title"> Returned OCSF v1.1 Standardized Schema Package</div>
        <pre><code style="font-size: 11px;">${JSON.stringify(data.ocsf_export, null, 2)}</code></pre>
      </div>
    `;

    modalClientPayload.style.display = 'flex';
  }

  btnCloseClientModal?.addEventListener('click', () => {
    modalClientPayload.style.display = 'none';
  });

  modalClientPayload?.addEventListener('click', (e) => {
    if (e.target === modalClientPayload) modalClientPayload.style.display = 'none';
  });

  // Module A: Authentication Handlers
  document.getElementById('btn-auth-success')?.addEventListener('click', () => {
    const user = document.getElementById('auth-user').value || 'admin@cybershield.gov.in';
    const ip = document.getElementById('auth-ip').value || '192.168.1.100';
    const logStr = `<134>1 ${new Date().toISOString()} cybershield-auth-service NginxAccess - - - Client IP=${ip} user=${user} action=login_success status=200 response_time_ms=8`;
    dispatchToUlpf(logStr, 'cybershield-auth-service', 'success');
  });

  document.getElementById('btn-auth-fail')?.addEventListener('click', () => {
    const user = document.getElementById('auth-user').value || 'unknown_user';
    const ip = document.getElementById('auth-ip').value || '185.220.101.5';
    const logStr = `<134>1 ${new Date().toISOString()} cybershield-auth-service NginxAccess - - - Client IP=${ip} user=${user} action=login_failed status=401 response_time_ms=15 reason="invalid_password"`;
    dispatchToUlpf(logStr, 'cybershield-auth-service', 'error');
  });

  document.getElementById('btn-auth-brute')?.addEventListener('click', () => {
    const ip = `185.220.${Math.floor(Math.random()*254+1)}.${Math.floor(Math.random()*254+1)}`;
    const logStr = `LEEF:2.0|CyberShield|AuthGateway|3.0|BRUTE_FORCE_ALERT|^\tsrc=${ip}\tdst=10.0.0.100\tspt=54122\tdpt=443\tproto=tcp\tact=DENY\tattempts=45`;
    dispatchToUlpf(logStr, 'cybershield-auth-gateway', 'error');
  });

  // Module B: E-Commerce Store Checkout
  document.getElementById('btn-cart-checkout')?.addEventListener('click', () => {
    const item = document.getElementById('cart-item').value;
    const gateway = document.getElementById('cart-gateway').value;
    const logObj = {
      timestamp: new Date().toISOString(),
      service: "cybershield-store-payment",
      event: "checkout_transaction",
      product_sku: item,
      gateway_node: gateway,
      client_ip: `10.0.${Math.floor(Math.random()*254+1)}.${Math.floor(Math.random()*254+1)}`,
      action: "ALLOW",
      amount_usd: Math.floor(Math.random()*5000 + 500),
      currency: "USD"
    };
    dispatchToUlpf(JSON.stringify(logObj), 'cybershield-store-payment', 'success');
  });

  // Module C: WAF Security Trigger
  document.getElementById('btn-sec-sqli')?.addEventListener('click', () => {
    const srcIp = `198.51.100.${Math.floor(Math.random()*250+1)}`;
    const logStr = `CEF:0|AWS_WAF|WAF_Engine|2.1|942100|SQL Injection Blocked|High|src=${srcIp} dst=10.0.1.50 spt=49152 dpt=443 proto=tcp act=block request=/api/v1/users?id=1'OR'1'='1`;
    dispatchToUlpf(logStr, 'AWS-WAF-Gateway', 'waf');
  });

  document.getElementById('btn-sec-xss')?.addEventListener('click', () => {
    const srcIp = `203.0.113.${Math.floor(Math.random()*250+1)}`;
    const logStr = JSON.stringify({
      timestamp: new Date().toISOString(),
      vendor: "Imperva WAF",
      rule_name: "XSS_Script_Injection_Filter",
      action: "BLOCK",
      client_ip: srcIp,
      dest_ip: "10.0.1.10",
      uri: "/comment?msg=<script>alert('xss')</script>",
      status: 403
    });
    dispatchToUlpf(logStr, 'Imperva-WAF-Node', 'waf');
  });

  document.getElementById('btn-sec-ddos')?.addEventListener('click', () => {
    const srcIp = `192.0.2.${Math.floor(Math.random()*250+1)}`;
    const logStr = `<134>1 ${new Date().toISOString()} edge-proxy RateLimiter - - - Client IP=${srcIp} request=/search action=rate_limit_exceeded status=429 rate=150req/sec`;
    dispatchToUlpf(logStr, 'Edge-Proxy-RateLimiter', 'error');
  });

  // Module D: Automated Simulator Toggle
  btnToggleAuto?.addEventListener('click', () => {
    if (autoTimer) {
      clearInterval(autoTimer);
      autoTimer = null;
      statusAuto.innerText = "STOPPED";
      statusAuto.style.color = "var(--accent-rose)";
      btnToggleAuto.innerText = "Start Live Auto-Feed";
      btnToggleAuto.style.background = "var(--bg-input)";
    } else {
      statusAuto.innerText = "RUNNING";
      statusAuto.style.color = "var(--accent-emerald)";
      btnToggleAuto.innerText = "Pause Auto-Feed";
      btnToggleAuto.style.background = "rgba(5, 150, 105, 0.15)";

      autoTimer = setInterval(() => {
        const types = ['auth_success', 'auth_fail', 'cart', 'sqli', 'waf'];
        const chosen = types[Math.floor(Math.random() * types.length)];
        
        if (chosen === 'auth_success') {
          const ip = `192.168.1.${Math.floor(Math.random()*200+10)}`;
          dispatchToUlpf(`<134>1 ${new Date().toISOString()} cybershield-web NginxAccess - - - Client IP=${ip} action=login_success status=200`, 'cybershield-web', 'success');
        } else if (chosen === 'cart') {
          dispatchToUlpf(JSON.stringify({ timestamp: new Date().toISOString(), event: "store_browse", client_ip: "10.0.1.45", action: "allow" }), 'cybershield-store', 'success');
        } else if (chosen === 'sqli') {
          const srcIp = `198.51.100.${Math.floor(Math.random()*250+1)}`;
          dispatchToUlpf(`CEF:0|CheckPoint|FW|1.0|100|Event|Low|src=${srcIp} dst=8.8.8.8 spt=51200 dpt=443 act=allow`, 'CheckPoint-FW', 'info');
        } else {
          const srcIp = `185.220.10.${Math.floor(Math.random()*250+1)}`;
          dispatchToUlpf(`LEEF:2.0|IBM|QRadar|7.3|VPN_LOGIN|^\tsrc=${srcIp}\tdst=10.0.0.5\tact=SUCCESS`, 'QRadar-VPN', 'info');
        }
      }, 1500);
    }
  });
});
