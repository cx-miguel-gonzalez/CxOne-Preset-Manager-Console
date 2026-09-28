document.addEventListener("DOMContentLoaded", () => {
  initCompareSelection();
  initSyncProgress();
  initPresetsTable();
  initPresetPanel();
  initCombineSelection();
  initUpdateSelection();
  initUpdateCounts();
  initDeleteSelection();
  initBackButtons();
});

function initBackButtons() {
  document.querySelectorAll(".cx-back-button").forEach((btn) => {
    btn.addEventListener("click", () => window.history.back());
  });
}

function initCompareSelection() {
  const checkboxes = Array.from(document.querySelectorAll(".compare-checkbox"));
  const button = document.getElementById("compare-button");
  const inputA = document.getElementById("compare-input-a");
  const inputB = document.getElementById("compare-input-b");
  if (!checkboxes.length || !button || !inputA || !inputB) return;

  function selectedIds() {
    return checkboxes.filter((c) => c.checked).map((c) => c.dataset.id);
  }

  function refresh() {
    const ids = selectedIds();
    checkboxes.forEach((c) => {
      c.disabled = !c.checked && ids.length >= 2;
    });
    button.disabled = ids.length !== 2;
    button.textContent = `Compare selected (${ids.length}/2)`;
    button.classList.toggle("cx-compare-sticky", ids.length === 2);
    inputA.value = ids[0] || "";
    inputB.value = ids[1] || "";
  }

  checkboxes.forEach((c) => c.addEventListener("change", refresh));
  refresh();
}

function initSyncProgress() {
  const buttons = Array.from(document.querySelectorAll("[data-sync-trigger]"));
  const panel = document.getElementById("sync-progress");
  const bar = document.getElementById("sync-progress-bar");
  const label = document.getElementById("sync-progress-label");
  if (!buttons.length || !panel || !bar || !label) return;

  let pollHandle = null;

  function setButtonsDisabled(disabled) {
    buttons.forEach((b) => (b.disabled = disabled));
  }

  function renderStatus(status) {
    panel.hidden = false;
    const total = status.total || 0;
    const current = status.current || 0;
    const pct = total > 0 ? Math.min(100, Math.round((current / total) * 100)) : 0;
    bar.style.width = `${pct}%`;

    if (status.state === "running") {
      label.textContent = total > 0
        ? `${status.message || "Syncing…"} (${current} of ${total})`
        : (status.message || "Starting…");
    } else if (status.state === "done") {
      bar.style.width = "100%";
      label.textContent = status.message || `Synced ${total} preset(s).`;
    } else if (status.state === "error") {
      label.textContent = status.message || "Sync failed.";
      panel.classList.add("cx-sync-progress-error");
    }
  }

  function stopPolling() {
    if (pollHandle) {
      clearInterval(pollHandle);
      pollHandle = null;
    }
  }

  async function poll(statusUrl) {
    try {
      const resp = await fetch(statusUrl);
      const status = await resp.json();
      renderStatus(status);
      if (status.state === "done") {
        stopPolling();
        setTimeout(() => window.location.reload(), 600);
      } else if (status.state === "error") {
        stopPolling();
        setButtonsDisabled(false);
      }
    } catch (err) {
      stopPolling();
      label.textContent = "Lost contact with the server while syncing.";
      setButtonsDisabled(false);
    }
  }

  buttons.forEach((button) => {
    button.addEventListener("click", async () => {
      setButtonsDisabled(true);
      panel.hidden = false;
      panel.classList.remove("cx-sync-progress-error");
      bar.style.width = "0%";
      label.textContent = "Starting…";
      const startUrl = button.dataset.refreshCatalog
        ? `${button.dataset.startUrl}?refresh_catalog=1`
        : button.dataset.startUrl;
      try {
        const resp = await fetch(startUrl, { method: "POST" });
        const status = await resp.json();
        renderStatus(status);
        pollHandle = setInterval(() => poll(button.dataset.statusUrl), 700);
      } catch (err) {
        label.textContent = "Could not start sync.";
        setButtonsDisabled(false);
      }
    });
  });
}

function initPresetPanel() {
  const panel = document.getElementById("preset-panel");
  const backdrop = document.getElementById("preset-panel-backdrop");
  const closeBtn = document.getElementById("preset-panel-close");
  const title = document.getElementById("preset-panel-title");
  const meta = document.getElementById("preset-panel-meta");
  const body = document.getElementById("preset-panel-body");
  const triggers = document.querySelectorAll(".cx-preset-name");
  if (!panel || !backdrop || !closeBtn || !title || !meta || !body || !triggers.length) return;

  function openPanel() {
    backdrop.hidden = false;
    panel.classList.add("cx-panel-open");
    panel.setAttribute("aria-hidden", "false");
  }

  function closePanel() {
    panel.classList.remove("cx-panel-open");
    panel.setAttribute("aria-hidden", "true");
    backdrop.hidden = true;
  }

  function clearBody() {
    while (body.firstChild) body.removeChild(body.firstChild);
  }

  function renderMessage(message) {
    clearBody();
    const p = document.createElement("p");
    p.className = "cx-hint";
    p.textContent = message;
    body.appendChild(p);
  }

  function renderPreset(data) {
    title.textContent = data.name || `Preset ${data.id}`;
    meta.textContent = `${data.is_custom ? "Custom" : "Built-in"} · ${data.total_queries} queries`;
    clearBody();

    const languages = Object.keys(data.groups || {});
    if (!languages.length) {
      renderMessage("No queries in this preset.");
      return;
    }

    languages.forEach((language) => {
      const langSection = document.createElement("div");
      langSection.className = "cx-panel-language";

      const langHeading = document.createElement("h3");
      langHeading.textContent = language;
      langSection.appendChild(langHeading);

      const categories = data.groups[language];
      Object.keys(categories).forEach((category) => {
        const catBlock = document.createElement("div");
        catBlock.className = "cx-panel-category";

        const catHeading = document.createElement("h4");
        catHeading.textContent = category;
        catBlock.appendChild(catHeading);

        const list = document.createElement("ul");
        categories[category].forEach((name) => {
          const li = document.createElement("li");
          li.textContent = name;
          list.appendChild(li);
        });
        catBlock.appendChild(list);
        langSection.appendChild(catBlock);
      });

      body.appendChild(langSection);
    });
  }

  triggers.forEach((el) => {
    el.addEventListener("click", async () => {
      const id = el.dataset.presetId;
      title.textContent = "Loading…";
      meta.textContent = "";
      clearBody();
      openPanel();
      try {
        const resp = await fetch(`/preset/${encodeURIComponent(id)}/detail`);
        const data = await resp.json();
        if (!resp.ok) {
          renderMessage((data && data.error) || "Could not load preset.");
          return;
        }
        renderPreset(data);
      } catch (err) {
        renderMessage("Could not load preset.");
      }
    });
  });

  closeBtn.addEventListener("click", closePanel);
  backdrop.addEventListener("click", closePanel);
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closePanel();
  });
}

function wireSelectAll(selectAllId, checkboxClass) {
  const selectAll = document.getElementById(selectAllId);
  const checkboxes = Array.from(document.querySelectorAll(`.${checkboxClass}`));
  if (!selectAll || !checkboxes.length) return;

  function refreshSelectAllState() {
    selectAll.checked = checkboxes.every((c) => c.checked);
  }

  selectAll.addEventListener("change", () => {
    checkboxes.forEach((c) => (c.checked = selectAll.checked));
  });
  checkboxes.forEach((c) => c.addEventListener("change", refreshSelectAllState));
  refreshSelectAllState();
}

function initCombineSelection() {
  wireSelectAll("combine-select-all", "cx-diff-checkbox");
}

function initUpdateSelection() {
  wireSelectAll("update-select-all", "cx-update-checkbox");
}

function initDeleteSelection() {
  const selectAll = document.getElementById("delete-select-all");
  const button = document.getElementById("delete-selected-button");
  const checkboxes = Array.from(document.querySelectorAll(".cx-delete-checkbox:not(:disabled)"));
  if (!button || !checkboxes.length) return;

  function isRowVisible(checkbox) {
    const row = checkbox.closest("tr");
    return !row || row.style.display !== "none";
  }

  function visibleCheckboxes() {
    return checkboxes.filter(isRowVisible);
  }

  function refresh() {
    const count = checkboxes.filter((c) => c.checked).length;
    button.disabled = count === 0;
    button.textContent = `Delete selected (${count})`;
    if (selectAll) {
      const visible = visibleCheckboxes();
      selectAll.checked = visible.length > 0 && visible.every((c) => c.checked);
    }
  }

  if (selectAll) {
    selectAll.addEventListener("change", () => {
      // Only the currently filtered-in (visible) rows should be affected --
      // otherwise "select all" silently selects presets hidden by the
      // search/type filter too.
      visibleCheckboxes().forEach((c) => (c.checked = selectAll.checked));
      refresh();
    });
  }
  checkboxes.forEach((c) => c.addEventListener("change", refresh));
  document.addEventListener("cx-presets-filtered", refresh);
  refresh();
}

function initUpdateCounts() {
  const groups = Array.from(document.querySelectorAll(".cx-collapsible"));
  const checkboxes = Array.from(document.querySelectorAll(".cx-update-checkbox"));
  const selectAll = document.getElementById("update-select-all");
  if (!groups.length || !checkboxes.length) return;

  function refreshCount(group) {
    const countEl = group.querySelector(":scope > summary .cx-count");
    if (!countEl) return;
    const scoped = group.querySelectorAll(".cx-update-checkbox");
    const checked = Array.from(scoped).filter((c) => c.checked).length;
    countEl.textContent = `${checked}/${scoped.length} enabled`;
  }

  function refreshAll() {
    groups.forEach(refreshCount);
  }

  checkboxes.forEach((cb) => cb.addEventListener("change", refreshAll));
  if (selectAll) selectAll.addEventListener("change", refreshAll);
  refreshAll();
}

function initPresetsTable() {
  const table = document.getElementById("presets-table");
  if (!table) return;
  const tbody = table.tBodies[0];
  const rows = Array.from(tbody.rows);
  const searchInput = document.getElementById("preset-search");
  const typeFilter = document.getElementById("type-filter");

  function applyFilters() {
    const term = (searchInput && searchInput.value || "").toLowerCase();
    const type = (typeFilter && typeFilter.value) || "all";
    rows.forEach((row) => {
      const name = (row.dataset.name || "").toLowerCase();
      const description = (row.dataset.description || "").toLowerCase();
      const rowType = row.dataset.type;
      const matchesTerm = !term || name.includes(term) || description.includes(term);
      const matchesType = type === "all" || rowType === type;
      row.style.display = matchesTerm && matchesType ? "" : "none";
    });
    document.dispatchEvent(new Event("cx-presets-filtered"));
  }

  if (searchInput) searchInput.addEventListener("input", applyFilters);
  if (typeFilter) typeFilter.addEventListener("change", applyFilters);

  const headers = Array.from(table.querySelectorAll("th[data-sort-key]"));
  let sortKey = null;
  let sortDir = 1;

  headers.forEach((th) => {
    th.addEventListener("click", () => {
      const key = th.dataset.sortKey;
      sortDir = sortKey === key ? -sortDir : 1;
      sortKey = key;

      headers.forEach((h) => h.classList.remove("cx-sort-asc", "cx-sort-desc"));
      th.classList.add(sortDir === 1 ? "cx-sort-asc" : "cx-sort-desc");

      const sorted = rows.slice().sort((a, b) => {
        const va = (a.dataset[key] || "").toLowerCase();
        const vb = (b.dataset[key] || "").toLowerCase();
        if (va < vb) return -1 * sortDir;
        if (va > vb) return 1 * sortDir;
        return 0;
      });
      sorted.forEach((row) => tbody.appendChild(row));
    });
  });
}
