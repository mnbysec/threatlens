/* ==========================================================================
   ThreatLens — standalone UI
   ========================================================================== */

(function () {
  "use strict";

  var API = window.location.origin + "/api";

  var activeFilter = "all";
  var assetsOnly = false;
  var lastFeed = null;
  var bookmarks = [];
  var assets = [];

  var el = {
    statusChip: document.getElementById("statusChip"),
    svrState: document.getElementById("svrState"),
    svrText: document.getElementById("svrText"),
    date: document.getElementById("tlDate"),
    refresh: document.getElementById("tlRefresh"),
    filters: document.getElementById("tlFilters"),
    search: document.getElementById("tlSearch"),
    assetsOnly: document.getElementById("tlAssetsOnly"),
    dash: document.getElementById("tlDash"),
    feedMeta: document.getElementById("tlFeedMeta"),
    feed: document.getElementById("tlFeed"),
    donut: document.getElementById("tlDonut"),
    donutCenter: document.getElementById("tlDonutCenter"),
    donutLegend: document.getElementById("tlDonutLegend"),
    sourceBars: document.getElementById("tlSourceBars"),
    trend: document.getElementById("tlTrend"),
    news: document.getElementById("tlNews"),
    sources: document.getElementById("tlSources"),
    addTabs: document.getElementById("tlAddTabs"),
    addSbom: document.getElementById("tlAddSbom"),
    addManual: document.getElementById("tlAddManual"),
    addApi: document.getElementById("tlAddApi"),
    sbomDrop: document.getElementById("tlSbomDrop"),
    sbomFile: document.getElementById("tlSbomFile"),
    listName: document.getElementById("tlListName"),
    pasteNames: document.getElementById("tlPasteNames"),
    manualAdd: document.getElementById("tlManualAdd"),
    apiProvider: document.getElementById("tlApiProvider"),
    apiName: document.getElementById("tlApiName"),
    apiBase: document.getElementById("tlApiBase"),
    apiEndpoint: document.getElementById("tlApiEndpoint"),
    apiClientId: document.getElementById("tlApiClientId"),
    apiSecret: document.getElementById("tlApiSecret"),
    apiKey: document.getElementById("tlApiKey"),
    apiPath: document.getElementById("tlApiPath"),
    apiTenant: document.getElementById("tlApiTenant"),
    apiUser: document.getElementById("tlApiUser"),
    apiPass: document.getElementById("tlApiPass"),
    apiSearch: document.getElementById("tlApiSearch"),
    apiAccess: document.getElementById("tlApiAccess"),
    apiSKey: document.getElementById("tlApiSKey"),
    apiVerify: document.getElementById("tlApiVerify"),
    apiConnect: document.getElementById("tlApiConnect"),
    bmChips: document.getElementById("tlBookmarks"),
    bmInput: document.getElementById("tlBmInput"),
    bmAdd: document.getElementById("tlBmAdd"),
    webhook: document.getElementById("tlWebhook"),
    testBtn: document.getElementById("tlTestBtn")
  };

  var SEV_COLOR = { critical: "#fb7185", high: "#fb923c", medium: "#fbbf24", low: "#22d3ee", none: "#64748b" };
  var SEV_TITLE = { critical: "Critical", high: "High", medium: "Medium", low: "Low", none: "Unrated" };

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  function toast(m, t) {
    var c = document.getElementById("toastContainer");
    if (!c) return;
    var d = document.createElement("div");
    d.className = "toast" + (t === "error" ? " error" : "");
    d.textContent = m;
    c.appendChild(d);
    setTimeout(function () { d.remove(); }, 4000);
  }

  /* ---------------- health ---------------- */
  function pingHealth() {
    fetch(API + "/health").then(function (r) {
      if (!r.ok) throw new Error("down");
      return r.json();
    }).then(function () {
      el.svrState.classList.add("online");
      el.svrText.textContent = "online";
    }).catch(function () {
      el.svrState.classList.remove("online");
      el.svrText.textContent = "offline";
    });
  }
  pingHealth();
  setInterval(pingHealth, 25000);

  /* ---------------- date ---------------- */
  function todayISO() {
    var d = new Date();
    return d.getFullYear() + "-" + String(d.getMonth() + 1).padStart(2, "0") + "-" + String(d.getDate()).padStart(2, "0");
  }
  el.date.value = todayISO();
  el.date.max = todayISO();

  function setChip(status) {
    el.statusChip.className = "status-chip " + status;
    el.statusChip.textContent = { queued: "LOADING", running: "FETCHING", done: "READY", error: "ERROR" }[status] || status.toUpperCase();
  }

  /* ---------------- feed ---------------- */
  function loadFeed(refresh) {
    var date = el.date.value || todayISO();
    setChip("running");
    el.feed.innerHTML = '<div class="empty"><b>Fetching advisories for ' + esc(date) + '…</b></div>';
    el.refresh.disabled = true;
    fetch(API + "/feed?date=" + encodeURIComponent(date) + (refresh ? "&refresh=1" : ""))
      .then(function (r) { return r.json(); })
      .then(function (feed) {
        if (feed.error) throw new Error(feed.error);
        lastFeed = feed;
        setChip("done");
        el.refresh.disabled = false;
        renderDash(feed);
        renderFeed();
        loadStats();
      })
      .catch(function (e) {
        setChip("error");
        el.refresh.disabled = false;
        el.feed.innerHTML = '<div class="empty"><b>Could not load the feed.</b><br>' + esc(e.message || "network error") + '</div>';
        toast("Failed to load advisories: " + e.message, "error");
      });
  }

  function loadStats() {
    fetch(API + "/stats").then(function (r) { return r.json(); }).then(function (s) {
      renderDonut(s.by_severity || (lastFeed ? lastFeed.by_severity : {}));
      renderSourceBars(s.by_source || (lastFeed ? lastFeed.by_source : {}));
      renderTrend(s.trend || []);
    }).catch(function () {
      if (lastFeed) { renderDonut(lastFeed.by_severity); renderSourceBars(lastFeed.by_source); }
    });
  }

  function dashCard(cls, value, label) {
    return '<div class="dash-card ' + cls + '"><div class="dc-value">' + value + '</div><div class="dc-label">' + label + '</div></div>';
  }

  function renderDash(feed) {
    var by = feed.by_severity || {};
    el.dash.innerHTML =
      dashCard("cyan", feed.count, "advisories") +
      dashCard("rose", by.critical || 0, "critical") +
      dashCard("amber", by.high || 0, "high") +
      dashCard("green", by.medium || 0, "medium") +
      dashCard("violet", by.low || 0, "low");
    el.feedMeta.textContent = (feed.sources || []).join(" · ") + " · " + feed.date;
  }

  /* ---------------- charts ---------------- */
  function renderDonut(bySev) {
    var total = (bySev.critical || 0) + (bySev.high || 0) + (bySev.medium || 0) + (bySev.low || 0) + (bySev.none || 0);
    var order = ["critical", "high", "medium", "low", "none"];
    var svg = '<circle cx="70" cy="70" r="55" fill="none" stroke="#1e293b" stroke-width="14"/>';
    var r = 55, C = 2 * Math.PI * r, offset = 0;
    if (total > 0) {
      order.forEach(function (sev) {
        var n = bySev[sev] || 0;
        if (!n) return;
        var len = (n / total) * C;
        svg += '<circle cx="70" cy="70" r="55" fill="none" stroke="' + SEV_COLOR[sev] + '" stroke-width="14" stroke-dasharray="' + len + ' ' + (C - len) + '" stroke-dashoffset="' + (-offset) + '"/>';
        offset += len;
      });
    }
    el.donut.innerHTML = svg;
    el.donutCenter.innerHTML = '<div class="n">' + total + '</div><div class="l">advisories</div>';
    el.donutLegend.innerHTML = order.map(function (sev) {
      return '<div class="lg"><i style="background:' + SEV_COLOR[sev] + '"></i>' + SEV_TITLE[sev] + '<b>' + (bySev[sev] || 0) + '</b></div>';
    }).join("");
  }

  function renderSourceBars(bySource) {
    var entries = Object.keys(bySource || {}).map(function (k) { return [k, bySource[k]]; });
    if (!entries.length) { el.sourceBars.innerHTML = '<div class="empty">No data</div>'; return; }
    var max = Math.max.apply(null, entries.map(function (e) { return e[1]; })) || 1;
    el.sourceBars.innerHTML = entries.map(function (e) {
      return '<div class="src-bar"><div class="lbl"><span>' + esc(e[0]) + '</span><b>' + e[1] + '</b></div>' +
        '<div class="track"><div class="fill" style="width:' + (e[1] / max * 100) + '%"></div></div></div>';
    }).join("");
  }

  function renderTrend(trend) {
    if (!trend || !trend.length) { el.trend.innerHTML = '<div class="empty">No data</div>'; return; }
    var counts = trend.map(function (t) { return t.count == null ? 0 : t.count; });
    var max = Math.max.apply(null, counts) || 1;
    el.trend.innerHTML = trend.map(function (t) {
      var h = t.count == null ? 0 : Math.max(t.count / max * 100, 2);
      return '<div class="bar"><div class="track"><div class="col" style="height:' + h + '%" title="' + esc(t.date) + ': ' + (t.count == null ? "not cached" : t.count) + '"></div></div>' +
        '<div class="dt">' + esc(t.date.slice(5)) + '</div></div>';
    }).join("");
  }

  /* ---------------- grouped feed ---------------- */
  function sevBadge(sev) {
    return '<span class="tl-sev ' + esc(sev) + '">' + esc(sev === "none" ? "unrated" : sev) + '</span>';
  }
  function srcPill(source) {
    var cls = source === "CISA KEV" ? "kev" : source === "GitHub" ? "github" : source === "Ubuntu" ? "ubuntu" : "";
    return '<span class="tl-src ' + cls + '">' + esc(source) + '</span>';
  }

  function advisoryRow(a) {
    var bm = a._bookmarked ? '<span class="tl-bm-flag">📌 bookmarked</span>' : "";
    var am = a._asset_match ? '<span class="tl-asset-match-flag">◉ in your assets</span>' : "";
    var cvss = a.cvss != null ? '<span class="tl-cvss" style="color:' + (SEV_COLOR[a.severity] || "#64748b") + '">CVSS ' + a.cvss + '</span>' : "";
    var exploited = a.exploited ? '<span class="tl-sev critical">exploited</span>' : "";
    var title = a.url
      ? '<a href="' + esc(a.url) + '" target="_blank" rel="noopener">' + esc(a.title || a.id) + '</a>'
      : esc(a.title || a.id);
    return '<div class="tl-row' + (a._asset_match ? " bm" : "") + '">' +
      '<div><div class="tl-title">' + title + '</div>' +
      '<div class="tl-sub">' + srcPill(a.source) + '<span class="tl-id">' + esc(a.id) + '</span>' + cvss + exploited + bm + am + '</div>' +
      '</div></div>';
  }

  function renderFeed() {
    if (!lastFeed) return;
    var q = (el.search.value || "").toLowerCase();
    var groups = { critical: [], high: [], medium: [], low: [], none: [] };
    var counts = { all: 0, critical: 0, high: 0, medium: 0, low: 0, none: 0 };
    lastFeed.advisories.forEach(function (a) {
      counts.all++;
      counts[a.severity] = (counts[a.severity] || 0) + 1;
      if (activeFilter !== "all" && a.severity !== activeFilter) return;
      if (assetsOnly && !a._asset_match) return;
      if (q && (a.id + " " + a.title + " " + (a.products || []).join(" ")).toLowerCase().indexOf(q) === -1) return;
      (groups[a.severity] || groups.none).push(a);
    });

    var order = ["critical", "high", "medium", "low", "none"];
    var html = "";
    order.forEach(function (sev) {
      var list = groups[sev];
      if (!list.length) return;
      html += '<details class="tl-group"' + (sev === "critical" ? " open" : "") + '>' +
        '<summary>' + sevBadge(sev) + '<span>' + SEV_TITLE[sev] + '</span><span class="g-count">' + list.length + '</span></summary>' +
        '<div class="tl-group-body">' + list.map(advisoryRow).join("") + '</div></details>';
    });
    el.feed.innerHTML = html || '<div class="empty"><b>No advisories match this filter.</b></div>';

    el.filters.querySelectorAll(".fchip").forEach(function (chip) {
      var f = chip.getAttribute("data-filter");
      var n = counts[f];
      if (n !== undefined) {
        var cnt = chip.querySelector(".cnt");
        if (!cnt) { cnt = document.createElement("span"); cnt.className = "cnt"; chip.appendChild(cnt); }
        cnt.textContent = n;
      }
    });
  }

  el.filters.addEventListener("click", function (e) {
    var chip = e.target.closest(".fchip");
    if (!chip) return;
    el.filters.querySelectorAll(".fchip").forEach(function (c) { c.classList.remove("active"); });
    chip.classList.add("active");
    activeFilter = chip.getAttribute("data-filter");
    renderFeed();
  });
  el.search.addEventListener("input", renderFeed);
  el.assetsOnly.addEventListener("change", function () { assetsOnly = el.assetsOnly.checked; renderFeed(); });
  el.date.addEventListener("change", function () { loadFeed(false); });
  el.refresh.addEventListener("click", function () { loadFeed(true); });

  /* ---------------- news ---------------- */
  function loadNews() {
    el.news.innerHTML = '<div class="empty">Loading security news…</div>';
    fetch(API + "/news").then(function (r) { return r.json(); }).then(function (d) {
      var items = d.items || [];
      el.news.innerHTML = items.map(function (n) {
        var pts = n.points ? '<span class="n-pts">▲ ' + n.points + '</span>' : "";
        var srcCls = n.source === "Hacker News" ? "hn" : "";
        var when = n.published ? new Date(n.published).toLocaleDateString() : "";
        return '<div class="news-card"><div class="n-title">' +
          (n.url ? '<a href="' + esc(n.url) + '" target="_blank" rel="noopener">' + esc(n.title) + '</a>' : esc(n.title)) +
          '</div><div class="n-meta"><span class="n-src ' + srcCls + '">' + esc(n.source) + '</span>' + pts +
          '<span class="n-time">' + esc(when) + '</span></div></div>';
      }).join("") || '<div class="empty">No news available.</div>';
    }).catch(function () { el.news.innerHTML = '<div class="empty">Could not load news.</div>'; });
  }

  /* ---------------- assets / SBOM (multi-source) ---------------- */
  var sourceList = [];

  function renderSources() {
    if (!sourceList.length) {
      el.sources.innerHTML = '<span style="color:#475569;font-size:12.5px">No asset lists yet — upload an SBOM, paste names, or connect an API.</span>';
      return;
    }
    el.sources.innerHTML = sourceList.map(function (s) {
      var n = (s.assets || []).length;
      var typeLbl = s.type === "api" ? ("api · " + (s.provider || "generic")) : (s.type === "sbom" ? "sbom" : "manual");
      var status = s.status === "error"
        ? '<span class="s-status error" title="' + esc(s.last_error || "") + '">error</span>'
        : (s.status === "pending" ? '<span class="s-status pending">syncing…</span>' : '<span class="s-status ok">ok</span>');
      var versions = (s.assets || []).slice(0, 5).map(function (a) {
        return '<span class="asset-chip">' + esc(a.name) + (a.version ? ' <span class="s-ver">' + esc(a.version) + '</span>' : '') + '</span>';
      }).join("");
      if (n > 5) versions += '<span class="asset-chip">+' + (n - 5) + '</span>';
      var updated = s.updated_at ? new Date(s.updated_at * 1000).toLocaleString() : "";
      var resyncBtn = s.type === "api" ? '<button class="s-btn" data-resync="' + esc(s.id) + '">sync</button>' : "";
      return '<div class="tl-source">' +
        '<div><div class="s-name">' + esc(s.name) + ' <span class="s-type ' + esc(s.type) + '">' + esc(typeLbl) + '</span></div>' +
        '<div class="s-meta">' + n + ' asset(s)' + (updated ? ' · ' + esc(updated) : '') + '</div>' + status + '</div>' +
        '<div class="s-assets">' + versions + '</div>' +
        '<div class="s-actions">' + resyncBtn +
        '<button class="s-btn del" data-del="' + esc(s.id) + '">remove</button></div>' +
        '</div>';
    }).join("");
  }

  function applySources(d) {
    sourceList = d.sources || [];
    assets = d.assets || [];
    renderSources();
    el.assetsOnly.disabled = !assets.length;
    if (lastFeed) loadFeed(false);
  }

  function loadAssets() {
    fetch(API + "/assets").then(function (r) { return r.json(); }).then(applySources).catch(function () {});
  }

  /* add-mode tabs */
  function setAddMode(mode) {
    el.addTabs.querySelectorAll("button").forEach(function (b) { b.classList.toggle("active", b.getAttribute("data-add") === mode); });
    el.addSbom.style.display = mode === "sbom" ? "block" : "none";
    el.addManual.style.display = mode === "manual" ? "block" : "none";
    el.addApi.style.display = mode === "api" ? "block" : "none";
  }
  el.addTabs.addEventListener("click", function (e) {
    var b = e.target.closest("button[data-add]");
    if (b) setAddMode(b.getAttribute("data-add"));
  });

  /* SBOM drop/upload */
  ["dragenter", "dragover"].forEach(function (ev) {
    el.sbomDrop.addEventListener(ev, function (e) { e.preventDefault(); el.sbomDrop.classList.add("drag"); });
  });
  ["dragleave", "drop"].forEach(function (ev) {
    el.sbomDrop.addEventListener(ev, function (e) { e.preventDefault(); el.sbomDrop.classList.remove("drag"); });
  });
  el.sbomDrop.addEventListener("drop", function (e) {
    var f = e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) uploadSbom(f);
  });
  el.sbomDrop.addEventListener("click", function () { el.sbomFile.click(); });
  el.sbomFile.addEventListener("change", function () {
    var f = el.sbomFile.files && el.sbomFile.files[0];
    if (f) uploadSbom(f);
  });
  var sampleBtn = document.getElementById("tlSampleLoad");
  if (sampleBtn) sampleBtn.addEventListener("click", function () {
    sampleBtn.disabled = true;
    fetch("/demo/sbom/sample-sbom.csv")
      .then(function (r) { if (!r.ok) throw new Error("fetch failed"); return r.blob(); })
      .then(function (blob) {
        var f;
        try { f = new File([blob], "sample-sbom.csv", { type: "text/csv" }); }
        catch (e) { blob.name = "sample-sbom.csv"; f = blob; }
        uploadSbom(f);
      })
      .catch(function () { toast("Could not load the sample.", "error"); })
      .finally(function () { sampleBtn.disabled = false; });
  });

  function uploadSbom(file) {
    var fd = new FormData();
    fd.append("file", file);
    toast("Parsing SBOM: " + file.name + "…");
    fetch(API + "/assets", { method: "POST", body: fd })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (d.error) { toast(d.error, "error"); return; }
        applySources(d);
        toast("Imported " + d.count + " asset(s) from " + file.name);
      }).catch(function () { toast("SBOM upload failed.", "error"); });
  }

  /* manual list */
  el.manualAdd.addEventListener("click", function () {
    var text = el.pasteNames.value.trim();
    if (!text) { toast("Paste at least one package name.", "error"); return; }
    var list = text.split(/\r?\n/).map(function (l) { return l.trim(); }).filter(Boolean).map(function (l) { return { name: l }; });
    fetch(API + "/assets", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: (el.listName.value.trim() || "Manual list"), assets: list })
    }).then(function (r) { return r.json(); }).then(function (d) {
      if (d.error) { toast(d.error, "error"); return; }
      el.pasteNames.value = "";
      applySources(d);
      toast("Added list with " + list.length + " asset(s)");
    }).catch(function () {});
  });

  /* API connect */
  var API_DEFAULT_BASE = {
    crowdstrike: "https://api.crowdstrike.com", splunk: "https://splunk:8089",
    defender: "", elastic: "https://kibana:5601", wazuh: "https://wazuh:55000",
    sentinelone: "https://usea1.sentinelone.net", tenable: "https://cloud.tenable.com", generic: ""
  };
  var API_DEFAULT_NAME = {
    crowdstrike: "CrowdStrike", splunk: "Splunk", defender: "Defender",
    elastic: "Elastic", wazuh: "Wazuh", sentinelone: "SentinelOne",
    tenable: "Tenable.io", generic: "API source"
  };
  var API_GROUPS = {
    crowdstrike: ["cs", "custom"], generic: ["token", "custom"],
    splunk: ["token", "search", "verify"], defender: ["tenant", "cs"],
    elastic: ["token"], wazuh: ["userpass", "verify"],
    sentinelone: ["token"], tenable: ["keys"]
  };
  var API_GROUP_CLASS = {
    cs: ".tl-api-cs", custom: ".tl-api-custom", token: ".tl-api-token",
    tenant: ".tl-api-tenant", userpass: ".tl-api-userpass",
    keys: ".tl-api-keys", search: ".tl-api-search", verify: ".tl-api-verify"
  };
  function syncApiFields() {
    var p = el.apiProvider.value;
    var show = API_GROUPS[p] || [];
    Object.keys(API_GROUP_CLASS).forEach(function (g) {
      var on = show.indexOf(g) !== -1;
      document.querySelectorAll(API_GROUP_CLASS[g]).forEach(function (l) { l.style.display = on ? "flex" : "none"; });
    });
    if (el.apiVerify) el.apiVerify.checked = !(p === "splunk" || p === "wazuh");
    var knownDefaults = Object.keys(API_DEFAULT_BASE).map(function (k) { return API_DEFAULT_BASE[k]; });
    if (!el.apiBase.value || knownDefaults.indexOf(el.apiBase.value) !== -1) el.apiBase.value = API_DEFAULT_BASE[p] || "";
  }
  el.apiProvider.addEventListener("change", syncApiFields);
  syncApiFields();

  el.apiConnect.addEventListener("click", function () {
    var provider = el.apiProvider.value;
    var config = { provider: provider, base_url: el.apiBase.value.trim() };
    if (provider === "crowdstrike" || provider === "generic") {
      config.endpoint = el.apiEndpoint.value.trim();
      config.assets_path = el.apiPath.value.trim();
    }
    if (provider === "crowdstrike" || provider === "defender") {
      config.client_id = el.apiClientId.value.trim();
      config.client_secret = el.apiSecret.value.trim();
    }
    if (provider === "defender") config.tenant_id = el.apiTenant.value.trim();
    if (["generic", "splunk", "elastic", "sentinelone"].indexOf(provider) !== -1) config.api_key = el.apiKey.value.trim();
    if (provider === "splunk") { config.search = el.apiSearch.value.trim(); config.verify_tls = el.apiVerify.checked; }
    if (provider === "wazuh") { config.username = el.apiUser.value.trim(); config.password = el.apiPass.value; config.verify_tls = el.apiVerify.checked; }
    if (provider === "tenable") { config.access_key = el.apiAccess.value.trim(); config.secret_key = el.apiSKey.value; }
    if (!config.base_url && provider !== "defender" && provider !== "tenable") { toast("Enter a base URL.", "error"); return; }
    el.apiConnect.disabled = true;
    fetch(API + "/assets", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ source: { name: (el.apiName.value.trim() || API_DEFAULT_NAME[provider] || "API source"), type: "api", provider: provider, config: config } })
    }).then(function (r) { return r.json(); }).then(function (d) {
      el.apiConnect.disabled = false;
      if (d.error) { toast(d.error, "error"); return; }
      applySources(d);
      var synced = (d.sources || []).some(function (s) { return s.type === "api" && s.status === "error"; });
      toast(synced ? "Connected, but the first sync failed — check your credentials." : "Connected and synced.");
    }).catch(function () { el.apiConnect.disabled = false; toast("Connection failed.", "error"); });
  });

  /* resync / remove */
  el.sources.addEventListener("click", function (e) {
    var resync = e.target.closest("[data-resync]");
    var del = e.target.closest("[data-del]");
    if (resync) {
      toast("Syncing…");
      fetch(API + "/assets/" + encodeURIComponent(resync.getAttribute("data-resync")) + "/resync", { method: "POST" })
        .then(function (r) { return r.json(); }).then(applySources).catch(function () {});
      return;
    }
    if (del) {
      fetch(API + "/assets/" + encodeURIComponent(del.getAttribute("data-del")), { method: "DELETE" })
        .then(function (r) { return r.json(); }).then(applySources).catch(function () {});
    }
  });

  /* ---------------- bookmarks ---------------- */
  function renderBookmarks() {
    el.bmChips.innerHTML = bookmarks.map(function (t) {
      return '<span class="bm-chip">' + esc(t) + '<button type="button" data-rm="' + esc(t) + '" title="Remove">&times;</button></span>';
    }).join("") || '<span style="color:#475569;font-size:12.5px">No bookmarks yet.</span>';
  }
  function loadBookmarks() {
    fetch(API + "/bookmarks").then(function (r) { return r.json(); }).then(function (d) {
      bookmarks = d.bookmarks || [];
      renderBookmarks();
      var dot = el.webhook.querySelector(".wh-dot");
      var txt = el.webhook.querySelector(".wh-txt");
      if (d.slack_configured) { dot.classList.add("on"); txt.textContent = "Slack webhook configured."; }
      else { dot.classList.remove("on"); txt.textContent = "No Slack webhook — configure one in Settings below."; }
    }).catch(function () {});
  }
  function bmAdd() {
    var tech = el.bmInput.value.trim();
    if (!tech) { toast("Enter a technology name.", "error"); return; }
    fetch(API + "/bookmarks", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ tech: tech })
    }).then(function (r) { return r.json(); }).then(function (d) {
      bookmarks = d.bookmarks || [];
      el.bmInput.value = "";
      renderBookmarks();
      if (lastFeed) loadFeed(false);
      toast("Bookmarked " + tech);
    }).catch(function () {});
  }
  el.bmAdd.addEventListener("click", bmAdd);
  el.bmInput.addEventListener("keydown", function (e) { if (e.key === "Enter") { e.preventDefault(); bmAdd(); } });
  el.bmChips.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-rm]");
    if (!btn) return;
    fetch(API + "/bookmarks", {
      method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ tech: btn.getAttribute("data-rm") })
    }).then(function (r) { return r.json(); }).then(function (d) {
      bookmarks = d.bookmarks || [];
      renderBookmarks();
      if (lastFeed) loadFeed(false);
    }).catch(function () {});
  });

  el.testBtn.addEventListener("click", function () {
    el.testBtn.disabled = true;
    fetch(API + "/test-webhook", { method: "POST" })
      .then(function (r) { return r.json(); }).then(function (d) {
        el.testBtn.disabled = false;
        toast(d.ok ? "Test notification sent." : (d.detail || "Test failed."), d.ok ? undefined : "error");
      }).catch(function () { el.testBtn.disabled = false; });
  });

  /* ---------------- settings ---------------- */
  var slackInput = document.getElementById("tlSlackUrl");
  var saveBtn = document.getElementById("tlSaveSettings");
  var settingsHint = document.getElementById("tlSettingsHint");

  function loadSettings() {
    fetch(API + "/settings").then(function (r) { return r.json(); }).then(function (d) {
      slackInput.value = d.slack_webhook || "";
    }).catch(function () {});
  }

  saveBtn.addEventListener("click", function () {
    var url = slackInput.value.trim();
    saveBtn.disabled = true;
    fetch(API + "/settings", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ slack_webhook: url })
    }).then(function (r) { return r.json(); }).then(function (d) {
      saveBtn.disabled = false;
      if (d.error) { toast(d.error, "error"); return; }
      toast(url ? "Slack webhook saved." : "Slack webhook cleared.");
      loadBookmarks();
    }).catch(function () { saveBtn.disabled = false; toast("Failed to save settings.", "error"); });
  });

  /* ---------------- boot ---------------- */
  loadSettings();
  loadBookmarks();
  loadAssets();
  loadNews();
  loadFeed(false);
})();
