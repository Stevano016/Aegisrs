(() => {
  const TOKEN_KEY = "aegisrs_token";
  let token = sessionStorage.getItem(TOKEN_KEY) || "";
  let ws = null;
  let paused = false;

  const authOverlay = document.getElementById("auth-overlay");
  const appShell = document.getElementById("app");
  const loginForm = document.getElementById("login-form");
  const authError = document.getElementById("auth-error");

  async function apiFetch(path, opts = {}) {
    const headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
    if (token) headers["Authorization"] = `Bearer ${token}`;
    const res = await fetch(path, { ...opts, headers });
    if (res.status === 401) {
      logout();
      throw new Error("Unauthorized");
    }
    return res;
  }

  function logout() {
    token = "";
    sessionStorage.removeItem(TOKEN_KEY);
    if (ws) ws.close();
    appShell.hidden = true;
    authOverlay.hidden = false;
  }

  loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    authError.hidden = true;
    const password = document.getElementById("password-input").value;
    try {
      const res = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password }),
      });
      if (!res.ok) {
        authError.textContent = "Invalid password or token.";
        authError.hidden = false;
        return;
      }
      const data = await res.json();
      token = data.token;
      sessionStorage.setItem(TOKEN_KEY, token);
      document.getElementById("password-input").value = "";
      enterApp();
    } catch (err) {
      authError.textContent = "Connection failed.";
      authError.hidden = false;
    }
  });

  document.getElementById("btn-logout").addEventListener("click", logout);

  document.getElementById("btn-pause-fim").addEventListener("click", async () => {
    if (paused) {
      await apiFetch("/api/fim/resume", { method: "POST" });
    } else {
      await apiFetch("/api/fim/pause", {
        method: "POST",
        body: JSON.stringify({ duration_secs: 900 }),
      });
    }
    refreshAll();
  });

  function renderEventRow(ev) {
    const tr = document.createElement("tr");
    const ts = new Date(ev.timestamp).toLocaleTimeString();
    const ip = ev.source_ip || "-";
    const banBtn = ev.source_ip
      ? `<button class="btn btn-danger btn-sm" data-ban-ip="${ev.source_ip}">Ban IP</button>`
      : `<span class="muted">-</span>`;

    tr.innerHTML = `
      <td class="mono">${ts}</td>
      <td><span class="badge badge-${ev.severity}">${ev.severity}</span></td>
      <td class="mono">${ev.category}</td>
      <td class="mono">${ip}</td>
      <td><strong>${escapeHtml(ev.title)}</strong><br><span class="muted">${escapeHtml(ev.description)}</span></td>
      <td>${banBtn}</td>
    `;
    const btn = tr.querySelector("[data-ban-ip]");
    if (btn) {
      btn.addEventListener("click", async () => {
        await apiFetch("/api/bans", {
          method: "POST",
          body: JSON.stringify({ ip: ev.source_ip, reason: ev.title, duration_secs: 86400 }),
        });
        refreshAll();
      });
    }
    return tr;
  }

  function escapeHtml(str) {
    return String(str || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  async function refreshAll() {
    try {
      const [statusRes, eventsRes, bansRes] = await Promise.all([
        apiFetch("/api/status"),
        apiFetch("/api/events"),
        apiFetch("/api/bans"),
      ]);
      const st = await statusRes.json();
      document.getElementById("host-badge").textContent = `${st.hostname} v${st.version}`;
      document.getElementById("kpi-events").textContent = st.events_processed;
      document.getElementById("kpi-alerts").textContent = st.alerts_total;
      document.getElementById("kpi-bans").textContent = st.active_bans;
      document.getElementById("kpi-uptime").textContent = `${st.uptime_secs}s`;

      paused = Boolean(st.paused_until);
      document.getElementById("btn-pause-fim").textContent = paused ? "Resume FIM" : "Pause FIM (15m)";

      const svcEl = document.getElementById("services-list");
      svcEl.innerHTML = "";
      (st.web_servers || []).forEach((ws) => {
        const div = document.createElement("div");
        div.className = "stack-item";
        div.innerHTML = `<span><strong>${ws.name}</strong> <span class="muted">${ws.installed ? "installed" : "not found"}</span></span>
          <button class="btn btn-secondary btn-sm" ${ws.installed ? "" : "disabled"}>Reload</button>`;
        div.querySelector("button").addEventListener("click", async () => {
          await apiFetch(`/api/services/${ws.name}/reload`, { method: "POST" });
        });
        svcEl.appendChild(div);
      });

      const docEl = document.getElementById("docker-list");
      docEl.innerHTML = "";
      (st.docker_containers || []).forEach((c) => {
        const div = document.createElement("div");
        div.className = "stack-item";
        div.innerHTML = `<span class="mono">${escapeHtml(c.name)}</span><span class="badge badge-neutral">${c.status}</span>`;
        docEl.appendChild(div);
      });

      const evData = await eventsRes.json();
      const tbody = document.getElementById("alerts-tbody");
      tbody.innerHTML = "";
      const events = evData.events || [];
      if (events.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty-cell">No security alerts recorded yet.</td></tr>';
      } else {
        events.forEach((ev) => tbody.appendChild(renderEventRow(ev)));
      }

      const banData = await bansRes.json();
      const bansEl = document.getElementById("bans-list");
      bansEl.innerHTML = "";
      (banData.ips || []).forEach((b) => {
        const div = document.createElement("div");
        div.className = "stack-item";
        div.innerHTML = `<span class="mono">${escapeHtml(b.ip)}</span><button class="btn btn-ghost btn-sm">Unban</button>`;
        div.querySelector("button").addEventListener("click", async () => {
          await apiFetch(`/api/bans/${encodeURIComponent(b.ip)}`, { method: "DELETE" });
          refreshAll();
        });
        bansEl.appendChild(div);
      });
    } catch (_) {}
  }

  function connectWs() {
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    ws = new WebSocket(`${proto}//${location.host}/ws?token=${encodeURIComponent(token)}`);
    const pill = document.getElementById("ws-status");
    ws.onopen = () => {
      pill.classList.remove("status-offline");
      pill.classList.add("status-online");
    };
    ws.onclose = () => {
      pill.classList.remove("status-online");
      pill.classList.add("status-offline");
    };
    ws.onmessage = (msg) => {
      const ev = JSON.parse(msg.data);
      const tbody = document.getElementById("alerts-tbody");
      if (tbody.querySelector(".empty-cell")) tbody.innerHTML = "";
      tbody.prepend(renderEventRow(ev));
    };
  }

  function enterApp() {
    authOverlay.hidden = true;
    appShell.hidden = false;
    refreshAll();
    connectWs();
    setInterval(refreshAll, 5000);
  }

  if (token) {
    enterApp();
  }
})();
