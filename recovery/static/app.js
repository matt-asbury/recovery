const els = {
  volumeList: document.getElementById("volume-list"),
  volumeSelect: document.getElementById("volume-select"),
  partitionSelect: document.getElementById("partition-select"),
  includeInternal: document.getElementById("include-internal"),
  imagePath: document.getElementById("image-path"),
  loadImage: document.getElementById("load-image"),
  refreshVolumes: document.getElementById("refresh-volumes"),
  startScan: document.getElementById("start-scan"),
  stopScan: document.getElementById("stop-scan"),
  statusText: document.getElementById("status-text"),
  progressFill: document.getElementById("progress-fill"),
  progressText: document.getElementById("progress-text"),
  filesBody: document.getElementById("files-body"),
  filesSummary: document.getElementById("files-summary"),
  largeSetNotice: document.getElementById("large-set-notice"),
  filter: document.getElementById("filter"),
  extensionFilter: document.getElementById("extension-filter"),
  confidenceFilter: document.getElementById("confidence-filter"),
  fileSearch: document.getElementById("file-search"),
  pagePrev: document.getElementById("page-prev"),
  pageNext: document.getElementById("page-next"),
  pageLabel: document.getElementById("page-label"),
  pageSize: document.getElementById("page-size"),
  selectAll: document.getElementById("select-all"),
  selectNone: document.getElementById("select-none"),
  recoveryDir: document.getElementById("recovery-dir"),
  recoverySize: document.getElementById("recovery-size"),
  chooseRecoveryDir: document.getElementById("choose-recovery-dir"),
  recoverSelected: document.getElementById("recover-selected"),
  recoveryModal: document.getElementById("recovery-modal"),
  recoveryModalTitle: document.getElementById("recovery-modal-title"),
  recoveryModalText: document.getElementById("recovery-modal-text"),
  recoveryModalFill: document.getElementById("recovery-modal-fill"),
  recoveryModalDetail: document.getElementById("recovery-modal-detail"),
  recoveryModalClose: document.getElementById("recovery-modal-close"),
  previewBox: document.getElementById("preview-box"),
  previewMeta: document.getElementById("preview-meta"),
  sudoBanner: document.getElementById("sudo-banner"),
  encryptionBanner: document.getElementById("encryption-banner"),
  topMessage: document.getElementById("top-message"),
  headerStats: document.getElementById("header-stats"),
  statFound: document.getElementById("stat-found"),
  statSelected: document.getElementById("stat-selected"),
  statSize: document.getElementById("stat-size"),
  stepSource: document.getElementById("step-source"),
  stepScan: document.getElementById("step-scan"),
  stepReview: document.getElementById("step-review"),
  stepRecover: document.getElementById("step-recover"),
  toastStack: document.getElementById("toast-stack"),
};

let scanning = false;
let volumeData = [];
let totalFilesFound = 0;
let previewIndex = null;
let previewObjectUrl = null;
let previewRequestId = 0;
let previewAbortController = null;
let lastFilesFound = -1;
let currentPage = 0;
let totalPages = 1;
let refreshTimer = null;
let searchTimer = null;
const REFRESH_INTERVAL_MS = 2500;
let recoveryModalOpen = false;
let recoveryModalDismissed = false;

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function showToast(message, type = "info") {
  const toast = document.createElement("div");
  toast.className = `toast${type === "error" ? " toast-error" : type === "success" ? " toast-success" : ""}`;
  toast.textContent = message;
  els.toastStack.appendChild(toast);
  setTimeout(() => toast.remove(), type === "error" ? 6000 : 4000);
}

function confidenceBadge(level) {
  const cls = level === "high" ? "badge-high" : level === "medium" ? "badge-medium" : "badge-low";
  return `<span class="badge ${cls}">${escapeHtml(level)}</span>`;
}

function sourceBadge(kind) {
  if (kind === "filesystem") {
    return `<span class="badge badge-fs">Live</span>`;
  }
  return `<span class="badge badge-carved">Carved</span>`;
}

function volumeSubtitle(volume) {
  if (volume.is_disk_image) return "Disk image";
  if (volume.mount_point) return `Mounted · ${volume.mount_point}`;
  return "Unmounted";
}

function renderVolumeList() {
  const selected = els.volumeSelect.value;
  if (!volumeData.length) {
    els.volumeList.innerHTML =
      '<div class="empty-state compact"><p>No volumes found. Load a disk image or connect a drive.</p></div>';
    return;
  }

  els.volumeList.innerHTML = volumeData
    .map(volume => {
      const isSelected = String(volume.index) === selected;
      const badges = [];
      if (volume.encryption && volume.encryption.is_encrypted) {
        badges.push(`<span class="badge badge-warn">${escapeHtml(volume.encryption.summary || "Encrypted")}</span>`);
      }
      if (volume.is_disk_image) {
        badges.push('<span class="badge badge-carved">Image</span>');
      }
      return `
        <button type="button" class="volume-card${isSelected ? " selected" : ""}" data-index="${volume.index}">
          <div class="volume-card-title">${escapeHtml(volume.display_name)}</div>
          <div class="volume-card-meta">${escapeHtml(volumeSubtitle(volume))}</div>
          ${badges.length ? `<div class="volume-card-badges">${badges.join("")}</div>` : ""}
        </button>`;
    })
    .join("");

  els.volumeList.querySelectorAll(".volume-card").forEach(card => {
    card.addEventListener("click", () => {
      els.volumeSelect.value = card.dataset.index;
      renderVolumeList();
      updatePartitionSelect();
      updateEncryptionBanner();
      updateScanControls();
      updateWorkflowSteps();
    });
  });
}

function updateHeaderStats(summary) {
  if (!summary || !summary.total) {
    els.headerStats.hidden = true;
    return;
  }
  els.headerStats.hidden = false;
  els.statFound.textContent = Number(summary.total).toLocaleString();
  els.statSelected.textContent = Number(summary.selected_all || 0).toLocaleString();
  els.statSize.textContent = summary.selected_size_human || "0 B";
  totalFilesFound = Number(summary.total) || 0;
  updateWorkflowSteps();
}

function updateWorkflowSteps() {
  const hasVolume = hasVolumeSelected();
  const hasFiles = totalFilesFound > 0;
  const steps = [els.stepSource, els.stepScan, els.stepReview, els.stepRecover];

  steps.forEach(step => step.classList.remove("active", "done"));

  if (!hasVolume) {
    els.stepSource.classList.add("active");
    return;
  }

  els.stepSource.classList.add("done");

  if (scanning) {
    els.stepScan.classList.add("active");
    return;
  }

  els.stepScan.classList.add("done");

  if (hasFiles) {
    els.stepReview.classList.add("active");
    if (Number(els.statSelected.textContent.replace(/,/g, "")) > 0) {
      els.stepReview.classList.add("done");
      els.stepRecover.classList.add("active");
    }
  } else {
    els.stepScan.classList.add("active");
  }
}

function openRecoveryModal(total, destination) {
  recoveryModalDismissed = false;
  recoveryModalOpen = true;
  els.recoveryModal.hidden = false;
  els.recoveryModalTitle.textContent = "Recovering Files";
  els.recoveryModalText.textContent =
    `Recovering ${total.toLocaleString()} file(s) to ${destination}`;
  els.recoveryModalDetail.textContent = "Starting…";
  els.recoveryModalFill.style.width = "0%";
  els.recoveryModalClose.hidden = true;
  els.recoverSelected.disabled = true;
}

async function closeRecoveryModal() {
  recoveryModalOpen = false;
  recoveryModalDismissed = true;
  els.recoveryModal.hidden = true;
  try {
    await api("/api/recover/dismiss", { method: "POST", body: "{}" });
  } catch (_error) {
    // Ignore dismiss errors; modal is already closed locally.
  }
}

function updateRecoveryModal(recovery) {
  if (!recovery || recovery.status === "idle") return;
  if (recoveryModalDismissed) return;

  const percent = Number.isFinite(recovery.percent) ? recovery.percent : 0;
  if (recoveryModalOpen) {
    els.recoveryModalFill.style.width = `${percent}%`;
  }

  if (recovery.status === "running") {
    if (!recoveryModalOpen) {
      openRecoveryModal(recovery.total, recovery.destination);
    }
    els.recoveryModalTitle.textContent = "Recovering Files";
    els.recoveryModalText.textContent =
      `Recovering ${recovery.total.toLocaleString()} file(s) to ${recovery.destination}`;
    const parts = [
      `${recovery.completed.toLocaleString()} of ${recovery.total.toLocaleString()} processed`,
      `${recovery.succeeded.toLocaleString()} succeeded`,
    ];
    if (recovery.failed > 0) {
      parts.push(`${recovery.failed.toLocaleString()} failed`);
    }
    let detail = parts.join(" · ");
    if (recovery.current_file) {
      detail += `\nCurrent: ${recovery.current_file}`;
    }
    els.recoveryModalDetail.textContent = detail;
    els.recoveryModalClose.hidden = true;
    els.recoverSelected.disabled = true;
    return;
  }

  if (recovery.status === "complete") {
    els.recoveryModalTitle.textContent = "Recovery Complete";
    els.recoveryModalText.textContent =
      `Successfully recovered ${recovery.succeeded.toLocaleString()} file(s).`;
    if (recovery.failed > 0) {
      els.recoveryModalText.textContent +=
        ` ${recovery.failed.toLocaleString()} file(s) could not be recovered.`;
    }
    els.recoveryModalDetail.textContent = recovery.destination
      ? `Saved to ${recovery.destination}`
      : "";
    els.recoveryModalFill.style.width = "100%";
    els.recoveryModalClose.hidden = false;
    els.recoverSelected.disabled = false;
    return;
  }

  if (recovery.status === "error") {
    els.recoveryModalTitle.textContent = "Recovery Failed";
    els.recoveryModalText.textContent = recovery.error || "An error occurred during recovery.";
    els.recoveryModalDetail.textContent = recovery.destination
      ? `Destination: ${recovery.destination}`
      : "";
    els.recoveryModalClose.hidden = false;
    els.recoverSelected.disabled = false;
  }
}

function updateRecoveryControls(recovery) {
  els.recoverSelected.disabled = recovery && recovery.status === "running";
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || response.statusText);
  return data;
}

function selectedCategories() {
  return [...document.querySelectorAll(".cat:checked")].map(el => el.value);
}

function scanMode() {
  return document.querySelector('input[name="mode"]:checked').value;
}

function hasVolumeSelected() {
  return els.volumeSelect.value !== "";
}

function updatePartitionSelect() {
  const selected = els.volumeSelect.value;
  els.partitionSelect.innerHTML = "";
  const whole = document.createElement("option");
  whole.value = "-1";
  whole.textContent = "Whole disk";
  els.partitionSelect.appendChild(whole);

  const volume = volumeData.find(item => String(item.index) === selected);
  if (!volume || !volume.partitions || volume.partitions.length === 0) {
    els.partitionSelect.disabled = true;
    els.partitionSelect.value = "-1";
    return;
  }

  els.partitionSelect.disabled = false;
  for (const partition of volume.partitions) {
    const option = document.createElement("option");
    option.value = partition.index;
    option.textContent = partition.display_label;
    els.partitionSelect.appendChild(option);
  }
}

function updateEncryptionBanner() {
  const selected = els.volumeSelect.value;
  const volume = volumeData.find(item => String(item.index) === selected);
  if (!volume || !volume.encryption || volume.encryption.status === "none") {
    els.encryptionBanner.hidden = true;
    els.encryptionBanner.textContent = "";
    return;
  }

  const enc = volume.encryption;
  els.encryptionBanner.hidden = false;
  let text = enc.summary || "Encrypted volume";
  if (enc.workflow) {
    text += `. ${enc.workflow}`;
  }
  els.encryptionBanner.textContent = text;
}

function updateScanModeOptions() {
  const selected = els.volumeSelect.value;
  const volume = volumeData.find(item => String(item.index) === selected);
  const enc = volume && volume.encryption ? volume.encryption : null;
  const deepRadio = document.querySelector('input[name="mode"][value="deep"]');
  const hybridRadio = document.querySelector('input[name="mode"][value="hybrid"]');
  const quickRadio = document.querySelector('input[name="mode"][value="quick"]');

  if (enc && enc.is_locked) {
    deepRadio.disabled = true;
    hybridRadio.disabled = true;
    quickRadio.disabled = true;
    return;
  }

  deepRadio.disabled = Boolean(enc && enc.blocks_raw_carve);
  if (deepRadio.disabled && deepRadio.checked) {
    hybridRadio.checked = true;
  }

  if (enc && enc.is_encrypted && volume && !volume.mount_point) {
    hybridRadio.disabled = true;
    quickRadio.disabled = true;
    if (hybridRadio.checked || quickRadio.checked) {
      deepRadio.checked = false;
    }
  } else {
    hybridRadio.disabled = false;
    quickRadio.disabled = false;
  }
}

function updateScanControls() {
  els.startScan.disabled = scanning || !hasVolumeSelected();
  els.stopScan.disabled = !scanning;
  updateScanModeOptions();
  updateWorkflowSteps();
}

async function loadVolumes() {
  const data = await api("/api/volumes");
  volumeData = data.volumes || [];
  const previous = els.volumeSelect.value;
  els.volumeSelect.innerHTML = "";
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = "Select a volume…";
  els.volumeSelect.appendChild(placeholder);
  data.volumes.forEach(v => {
    const option = document.createElement("option");
    option.value = v.index;
    option.textContent = v.display_name;
    els.volumeSelect.appendChild(option);
  });
  const values = [...els.volumeSelect.options].map(option => option.value);
  els.volumeSelect.value = values.includes(previous) ? previous : "";
  els.recoveryDir.value = data.recovery_dir;
  els.includeInternal.checked = data.include_internal;
  els.sudoBanner.hidden = !data.needs_sudo;
  renderVolumeList();
  updatePartitionSelect();
  updateEncryptionBanner();
  updateScanControls();
  updateWorkflowSteps();
}

function filesQuery() {
  const params = new URLSearchParams({
    filter: els.filter.value,
    extension: els.extensionFilter.value,
    min_confidence: els.confidenceFilter.value,
    page: String(currentPage),
    page_size: els.pageSize.value,
  });
  const search = els.fileSearch.value.trim();
  if (search) params.set("search", search);
  return params.toString();
}

function updateExtensionOptions(extensions) {
  const current = els.extensionFilter.value;
  els.extensionFilter.innerHTML = '<option value="all">All types</option>';
  for (const item of extensions) {
    const option = document.createElement("option");
    option.value = item.ext;
    option.textContent = `.${item.ext} (${(Number(item.count) || 0).toLocaleString()})`;
    els.extensionFilter.appendChild(option);
  }
  const values = [...els.extensionFilter.options].map(option => option.value);
  els.extensionFilter.value = values.includes(current) ? current : "all";
}

async function refreshSummary() {
  const params = new URLSearchParams({
    filter: els.filter.value,
    extension: els.extensionFilter.value,
    min_confidence: els.confidenceFilter.value,
  });
  const search = els.fileSearch.value.trim();
  if (search) params.set("search", search);
  const data = await api(`/api/files/summary?${params.toString()}`);
  updateExtensionOptions(data.extensions || []);
  const filteredTotal = Number(data.filtered_total) || 0;
  const visibleTotal = Number(data.visible_total) || filteredTotal;
  const selectedAll = Number(data.selected_all) || 0;
  const total = Number(data.total) || 0;
  const selectedSize = data.selected_size_human || "0 B";
  const filteredSize = data.filtered_size_human || "0 B";
  const hiddenCount = Math.max(0, total - visibleTotal);
  els.filesSummary.innerHTML =
    `<strong>${filteredTotal.toLocaleString()}</strong> matching · ` +
    `<strong>${selectedAll.toLocaleString()}</strong> selected · ` +
    `<strong>${selectedSize}</strong> to recover · ` +
    `<strong>${total.toLocaleString()}</strong> total found` +
    (hiddenCount
      ? ` · <strong>${hiddenCount.toLocaleString()}</strong> hidden by confidence filter`
      : "");
  els.recoverySize.textContent =
    selectedAll > 0
      ? `${selectedAll.toLocaleString()} file(s) selected · ${selectedSize} total`
      : "Nothing selected yet";
  els.largeSetNotice.hidden = !data.large_result_set;
  updateHeaderStats(data);
  return data;
}

async function refreshFiles(options = {}) {
  const { resetPage = false } = options;
  if (resetPage) currentPage = 0;

  const data = await api(`/api/files?${filesQuery()}`);
  totalPages = Math.max(1, data.total_pages || 1);
  currentPage = Math.min(currentPage, totalPages - 1);

  els.filesBody.innerHTML = "";
  if (!data.files.length) {
    const emptyHtml = data.total
      ? `<tr class="empty-row"><td colspan="7"><div class="empty-state compact"><p class="empty-title">No matches</p><p class="empty-sub">Try relaxing filters or search terms.</p></div></td></tr>`
      : `<tr class="empty-row"><td colspan="7"><div class="empty-state"><div class="empty-icon">◇</div><p class="empty-title">No files yet</p><p class="empty-sub">Pick a volume and start a scan.</p></div></td></tr>`;
    els.filesBody.innerHTML = emptyHtml;
  }

  data.files.forEach(file => {
    const row = document.createElement("tr");
    if (file.selected) row.classList.add("selected-row");
    if (previewIndex === file.index) row.classList.add("preview-row");
    const dateTitle = file.timestamp_source === "modified"
      ? "No creation date found; showing last modified"
      : "";
    row.innerHTML = `
      <td class="col-check"><input type="checkbox" data-index="${file.index}" ${file.selected ? "checked" : ""}></td>
      <td class="filename-cell" title="${escapeHtml(file.filename)}">${escapeHtml(file.filename)}</td>
      <td>${escapeHtml(file.category)} <span class="badge badge-carved">.${escapeHtml(file.extension)}</span></td>
      <td>${escapeHtml(file.size_human)}</td>
      <td title="${escapeHtml(dateTitle)}">${escapeHtml(file.timestamp)}</td>
      <td>${confidenceBadge(file.confidence)} ${sourceBadge(file.source_kind || "carved")}</td>
      <td class="location-cell" title="${escapeHtml(file.offset_display)}">${escapeHtml(file.offset_display)}</td>`;
    row.dataset.index = String(file.index);
    row.addEventListener("click", (event) => {
      if (event.target.tagName === "INPUT") return;
      showPreview(file);
    });
    els.filesBody.appendChild(row);
  });

  els.filesBody.querySelectorAll("input[type=checkbox]").forEach(box => {
    box.addEventListener("change", async () => {
      await api("/api/files/select", {
        method: "POST",
        body: JSON.stringify({
          indices: [Number(box.dataset.index)],
          selected: box.checked,
        }),
      });
      const row = box.closest("tr");
      if (row) row.classList.toggle("selected-row", box.checked);
      await refreshSummary();
    });
  });

  els.pageLabel.textContent = data.total
    ? `Page ${currentPage + 1} of ${totalPages} · showing ${data.showing_from}-${data.showing_to}`
    : "Page 1 of 1";
  els.pagePrev.disabled = currentPage <= 0;
  els.pageNext.disabled = currentPage >= totalPages - 1;
  await refreshSummary();
}

function scheduleRefreshFiles(force = false) {
  if (refreshTimer) {
    clearTimeout(refreshTimer);
    refreshTimer = null;
  }
  if (force || !scanning) {
    refreshFiles();
    return;
  }
  refreshTimer = setTimeout(() => {
    refreshTimer = null;
    refreshFiles();
  }, REFRESH_INTERVAL_MS);
}

async function showPreview(file) {
  const requestId = ++previewRequestId;
  previewIndex = file.index;
  highlightPreviewRows();

  if (previewAbortController) {
    previewAbortController.abort();
  }
  previewAbortController = new AbortController();

  try {
    const detail = await api(`/api/files/${file.index}`);
    if (requestId !== previewRequestId) return;
    els.previewMeta.textContent = detail.description;
  } catch (_error) {
    if (requestId !== previewRequestId) return;
    els.previewMeta.textContent = file.filename;
  }

  if (!file.can_preview) {
    clearPreviewObjectUrl();
    els.previewBox.textContent = "Preview not available for this file type";
    return;
  }

  els.previewBox.textContent = "Loading preview…";
  clearPreviewObjectUrl();
  try {
    const response = await fetch(`/api/preview/${file.index}?t=${Date.now()}`, {
      signal: previewAbortController.signal,
    });
    if (requestId !== previewRequestId) return;

    const contentType = response.headers.get("Content-Type") || "";
    if (!response.ok) {
      if (contentType.includes("application/json")) {
        const err = await response.json().catch(() => ({}));
        els.previewBox.textContent = err.detail || err.error || "Could not load preview";
      } else {
        els.previewBox.textContent = "Could not load preview";
      }
      return;
    }

    if (!contentType.startsWith("image/")) {
      els.previewBox.textContent = "Preview response was not a valid image";
      return;
    }

    const blob = await response.blob();
    if (requestId !== previewRequestId) return;
    if (!blob.size) {
      els.previewBox.textContent = "Preview data is empty";
      return;
    }

    const header = new Uint8Array(await blob.slice(0, 8).arrayBuffer());
    const isPng = header[0] === 0x89 && header[1] === 0x50 && header[2] === 0x4E && header[3] === 0x47;
    const isJpeg = header[0] === 0xFF && header[1] === 0xD8;
    if (!isPng && !isJpeg) {
      els.previewBox.textContent = "Preview data is not a decodable image";
      return;
    }

    previewObjectUrl = URL.createObjectURL(blob);
    const img = document.createElement("img");
    img.alt = "preview";
    img.onload = () => {
      if (requestId !== previewRequestId) return;
      els.previewBox.innerHTML = "";
      els.previewBox.appendChild(img);
    };
    img.onerror = () => {
      if (requestId !== previewRequestId) return;
      clearPreviewObjectUrl();
      els.previewBox.textContent = "Browser could not render this image (likely corrupt)";
    };
    img.src = previewObjectUrl;
  } catch (error) {
    if (requestId !== previewRequestId) return;
    if (error.name === "AbortError") return;
    els.previewBox.textContent = "Could not load preview";
  }
}

function clearPreviewObjectUrl() {
  if (previewObjectUrl) {
    URL.revokeObjectURL(previewObjectUrl);
    previewObjectUrl = null;
  }
}

function highlightPreviewRows() {
  els.filesBody.querySelectorAll("tr").forEach(row => {
    row.classList.toggle("preview-row", row.dataset.index === String(previewIndex));
  });
}

let wasScanning = false;

async function pollStatus() {
  try {
    const response = await fetch("/api/scan/status");
    const data = await response.json();
    scanning = data.scanning;
    document.body.classList.toggle("is-scanning", scanning);
    updateScanControls();
    updateWorkflowSteps();
    const percent = Number.isFinite(data.progress.percent) ? data.progress.percent : 0;
    els.progressFill.style.width = `${percent}%`;
    const summary = data.progress.summary || "0%";
    els.progressText.textContent = summary.toLowerCase().includes("nan") ? `${percent.toFixed(1)}%` : summary;
    els.statusText.textContent = data.progress.message || data.progress.status;
    if (data.progress.error) {
      els.statusText.textContent = data.progress.error;
    }
    updateRecoveryModal(data.recovery);
    updateRecoveryControls(data.recovery);
    const filesFound = data.progress.files_found ?? 0;
    if (filesFound !== lastFilesFound) {
      lastFilesFound = filesFound;
      if (scanning) {
        await refreshSummary();
        scheduleRefreshFiles(false);
      } else {
        scheduleRefreshFiles(true);
      }
    }
    if (wasScanning && !scanning) {
      scheduleRefreshFiles(true);
      if (!data.progress.error) {
        showToast(data.progress.message || "Scan complete", "success");
      }
    }
    wasScanning = scanning;
  } catch (error) {
    console.error(error);
  }
}

els.refreshVolumes.addEventListener("click", async () => {
  await api("/api/volumes/refresh", {
    method: "POST",
    body: JSON.stringify({ include_internal: els.includeInternal.checked }),
  });
  await loadVolumes();
});

els.includeInternal.addEventListener("change", () => els.refreshVolumes.click());

els.volumeSelect.addEventListener("change", () => {
  updatePartitionSelect();
  updateEncryptionBanner();
  updateScanControls();
});

els.chooseRecoveryDir.addEventListener("click", async () => {
  try {
    const data = await api("/api/recover/choose-dir", {
      method: "POST",
      body: JSON.stringify({ initial: els.recoveryDir.value.trim() }),
    });
    if (data.cancelled) return;
    els.recoveryDir.value = data.path;
    showToast(`Recovery folder: ${data.path}`, "success");
  } catch (error) {
    showToast(error.message, "error");
  }
});

els.loadImage.addEventListener("click", async () => {
  try {
    await api("/api/volumes/image", {
      method: "POST",
      body: JSON.stringify({ path: els.imagePath.value }),
    });
    await loadVolumes();
    els.volumeSelect.value = "0";
    renderVolumeList();
    updatePartitionSelect();
    updateEncryptionBanner();
    updateScanControls();
    document.querySelector('input[name="mode"][value="deep"]').checked = true;
    showToast("Disk image loaded — ready to scan", "success");
  } catch (error) {
    showToast(error.message, "error");
  }
});

els.startScan.addEventListener("click", async () => {
  if (!hasVolumeSelected()) {
    showToast("Select a volume to scan first.", "error");
    return;
  }
  try {
    previewIndex = null;
    clearPreviewObjectUrl();
    els.previewBox.innerHTML =
      '<div class="empty-state compact"><p>Select a file to preview</p></div>';
    els.previewMeta.textContent = "";
    await api("/api/scan/start", {
      method: "POST",
      body: JSON.stringify({
        volume_index: Number(els.volumeSelect.value),
        partition_index: Number(els.partitionSelect.value),
        mode: scanMode(),
        categories: selectedCategories(),
      }),
    });
    scanning = true;
    lastFilesFound = -1;
    currentPage = 0;
    updateScanControls();
    updateWorkflowSteps();
    showToast("Scan started", "success");
  } catch (error) {
    showToast(error.message, "error");
  }
});

els.stopScan.addEventListener("click", async () => {
  await api("/api/scan/stop", { method: "POST", body: "{}" });
});

els.filter.addEventListener("change", () => refreshFiles({ resetPage: true }));
els.extensionFilter.addEventListener("change", () => refreshFiles({ resetPage: true }));
els.confidenceFilter.addEventListener("change", () => refreshFiles({ resetPage: true }));

els.pageSize.addEventListener("change", () => refreshFiles({ resetPage: true }));
els.pagePrev.addEventListener("click", () => {
  if (currentPage > 0) {
    currentPage -= 1;
    refreshFiles();
  }
});
els.pageNext.addEventListener("click", () => {
  if (currentPage < totalPages - 1) {
    currentPage += 1;
    refreshFiles();
  }
});
els.fileSearch.addEventListener("input", () => {
  if (searchTimer) clearTimeout(searchTimer);
  searchTimer = setTimeout(() => refreshFiles({ resetPage: true }), 300);
});

els.selectAll.addEventListener("click", async () => {
  const summary = await refreshSummary();
  if (summary.filtered_total > 1000) {
    const ok = confirm(
      `Select all ${summary.filtered_total.toLocaleString()} matching files? ` +
      "Recovering very large selections can take a long time."
    );
    if (!ok) return;
  }
  await api("/api/files/select-all", {
    method: "POST",
    body: JSON.stringify({
      filter: els.filter.value,
      extension: els.extensionFilter.value,
      min_confidence: els.confidenceFilter.value,
      search: els.fileSearch.value.trim(),
      selected: true,
    }),
  });
  refreshFiles();
});

els.selectNone.addEventListener("click", async () => {
  await api("/api/files/select-all", {
    method: "POST",
    body: JSON.stringify({
      filter: els.filter.value,
      extension: els.extensionFilter.value,
      min_confidence: els.confidenceFilter.value,
      search: els.fileSearch.value.trim(),
      selected: false,
    }),
  });
  refreshFiles();
});

async function syncVisibleSelections() {
  const boxes = [...els.filesBody.querySelectorAll("input[type=checkbox]")];
  await Promise.all(
    boxes.map(box =>
      api("/api/files/select", {
        method: "POST",
        body: JSON.stringify({
          indices: [Number(box.dataset.index)],
          selected: box.checked,
        }),
      })
    )
  );
}

async function recoverSelected() {
  try {
    const destination = els.recoveryDir.value.trim();
    if (!destination) {
      showToast("Choose a destination folder first.", "error");
      return;
    }
    await syncVisibleSelections();
    const summary = await refreshSummary();
    const count = Number(summary.selected_all) || 0;
    const size = summary.selected_size_human || "0 B";
    if (count <= 0) {
      showToast("No files selected for recovery.", "error");
      return;
    }
    if (count > 500) {
      const ok = confirm(
        `Recover ${count.toLocaleString()} selected file(s) (${size})? ` +
        "This may take a long time and use significant disk space."
      );
      if (!ok) return;
    }
    const data = await api("/api/recover", {
      method: "POST",
      body: JSON.stringify({ destination }),
    });
    openRecoveryModal(data.count, data.destination || destination);
  } catch (error) {
    showToast(error.message, "error");
  }
}

els.recoverSelected.addEventListener("click", recoverSelected);

els.recoveryModalClose.addEventListener("click", closeRecoveryModal);

loadVolumes().then(async () => {
  await refreshFiles();
  lastFilesFound = 0;
});
setInterval(pollStatus, 1000);

document.addEventListener("keydown", event => {
  if (event.key === "/" && document.activeElement !== els.fileSearch) {
    event.preventDefault();
    els.fileSearch.focus();
  }
});
