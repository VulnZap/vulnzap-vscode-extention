// Get the VS Code API
const vscode = acquireVsCodeApi();

// Global state
let currentData = {
  issues: [],
  dependencyVulnerabilities: [],
  dependencyScanResults: [],
  isLoggedIn: false,
};

// Initialize when DOM is loaded
document.addEventListener("DOMContentLoaded", function () {
  initializeEventListeners();
  showLoadingState();
  checkSidebarWidth();
});

// Check if sidebar is too narrow and show helpful tips
function checkSidebarWidth() {
  // Width hint removed - this function is now a placeholder
  // for any future width-related functionality
}

// Handle messages from the extension
window.addEventListener("message", (event) => {
  const message = event.data;

  switch (message.type) {
    case "updateData":
      currentData = message.data;
      updateUI();
      break;
    case "scanStarted":
      showScanningState();
      break;
    case "scanCompleted":
      hideScanningState();
      // Refresh UI to clear any loading states in content sections
      updateUI();
      break;
    case "scanCancelled":
      hideScanningState();
      // Refresh UI to clear any loading states in content sections
      updateUI();
      break;
    case "dependencyScanStarted":
      showDependencyScanLoading();
      break;
    case "dependencyScanCompleted":
      hideDependencyScanLoading();
      break;
  }
});

function initializeEventListeners() {
  // Header action buttons
  const refreshBtn = document.getElementById("refresh-btn");
  const scanDepsBtn = document.getElementById("scan-deps-btn");
  const scanFileBtn = document.getElementById("scan-file-btn");
  const showLogsBtn = document.getElementById("show-logs-btn");
  const fixAllDepsBtn = document.getElementById("fix-all-deps");

  if (refreshBtn) {
    refreshBtn.addEventListener("click", () => {
      showLoadingState();
      vscode.postMessage({ type: "refresh" });

      // Set a timeout to clear loading state in case refresh doesn't complete
      setTimeout(() => {
        hideLoadingState();
      }, 5000); // Clear loading after 5 seconds max
    });
  }

  if (scanDepsBtn) {
    scanDepsBtn.addEventListener("click", () => {
      // Show immediate feedback
      scanDepsBtn.disabled = true;
      scanDepsBtn.innerHTML =
        '<span class="icon loading-spinner"></span> Scanning...';

      vscode.postMessage({ type: "scanDependencies" });

      // Reset button after timeout in case scan doesn't provide feedback
      setTimeout(() => {
        if (scanDepsBtn.disabled) {
          scanDepsBtn.disabled = false;
          scanDepsBtn.innerHTML =
            '<span class="icon">📦</span> Scan Dependencies';
        }
      }, 15000); // 15 second timeout for dependency scans (they can take longer)
    });
  }

  if (scanFileBtn) {
    scanFileBtn.addEventListener("click", () => {
      // Show immediate feedback
      scanFileBtn.disabled = true;
      scanFileBtn.innerHTML =
        '<span class="icon loading-spinner"></span> Scanning...';

      vscode.postMessage({ type: "scanCurrentFile" });

      // Reset button after timeout in case scan doesn't provide feedback
      setTimeout(() => {
        if (scanFileBtn.disabled) {
          scanFileBtn.disabled = false;
          scanFileBtn.innerHTML =
            '<span class="icon">📄</span> Scan Current File';
        }
      }, 5000); // 5 second timeout for single file scan
    });
  }

  if (showLogsBtn) {
    showLogsBtn.addEventListener("click", () => {
      vscode.postMessage({ type: "showOutputLogs" });
    });
  }

  if (fixAllDepsBtn) {
    fixAllDepsBtn.addEventListener("click", () => {
      vscode.postMessage({ type: "fixAllDependencies" });
    });
  }

  // Filter controls
  const severityFilter = document.getElementById("severity-filter");
  const fileFilter = document.getElementById("file-filter");

  if (severityFilter) {
    severityFilter.addEventListener("change", filterIssues);
  }

  if (fileFilter) {
    fileFilter.addEventListener("change", filterIssues);
  }
}

function showLoadingState() {
  const sections = ["dependencies-list", "issues-list", "scans-list"];

  sections.forEach((sectionId) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.innerHTML = `
        <div class="loading">
          <div class="loading-spinner"></div>
          Loading...
        </div>
      `;
    }
  });
}

function hideLoadingState() {
  // Force UI update to clear loading states
  updateUI();
}

function updateUI() {
  updateStatistics();
  updateDependencyVulnerabilities();
  updateCodeIssues();
  updateRecentScans();
  updateFileFilter();
}

function updateStatistics() {
  const issues = currentData.issues || [];

  // Count issues by severity
  const stats = {
    total: issues.length,
    critical: issues.filter((i) => i.severity === 1).length, // Error
    high: issues.filter((i) => i.severity === 2).length, // Warning
    medium: issues.filter((i) => i.severity === 3).length, // Information
    low: issues.filter((i) => i.severity === 4).length, // Hint
  };

  // Add dependency vulnerabilities to stats
  const depVulns = currentData.dependencyVulnerabilities || [];
  depVulns.forEach(([packageName, vulnerabilities]) => {
    vulnerabilities.forEach((vuln) => {
      stats.total++;
      if (vuln.severity === "critical") stats.critical++;
      else if (vuln.severity === "high") stats.high++;
      else if (vuln.severity === "medium") stats.medium++;
      else stats.low++;
    });
  });

  // Update DOM
  document.getElementById("total-issues").textContent = stats.total;
  document.getElementById("critical-issues").textContent = stats.critical;
  document.getElementById("high-issues").textContent = stats.high;
  document.getElementById("medium-issues").textContent = stats.medium;
  document.getElementById("low-issues").textContent = stats.low;
}

function updateDependencyVulnerabilities() {
  const container = document.getElementById("dependencies-list");
  const vulnerabilities = currentData.dependencyVulnerabilities || [];

  if (vulnerabilities.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon">✅</div>
        <div class="empty-state-message">No dependency vulnerabilities found</div>
        <div class="empty-state-description">Your dependencies appear to be secure</div>
      </div>
    `;
    return;
  }

  let html = "";
  vulnerabilities.forEach(([packageName, vulns]) => {
    vulns.forEach((vuln) => {
      html += `
        <div class="vulnerability-item">
          <div class="vulnerability-header">
            <div>
              <div class="vulnerability-title">${vuln.title || vuln.id}</div>
              <div class="vulnerability-package">${packageName}@${
        vuln.vulnerable_versions || "unknown"
      }</div>
            </div>
            <div class="vulnerability-actions">
              <span class="severity-badge severity-${
                vuln.severity || "medium"
              }">${vuln.severity || "medium"}</span>
              <button class="fix-btn" onclick="fixVulnerability('${
                vuln.id
              }')">Fix</button>
            </div>
          </div>
          <div class="vulnerability-details">
            ${vuln.overview || vuln.description || "No description available"}
            ${
              vuln.patched_versions
                ? `<br><strong>Fix:</strong> Update to ${vuln.patched_versions}`
                : ""
            }
          </div>
        </div>
      `;
    });
  });

  container.innerHTML = html;
}

function updateCodeIssues() {
  const container = document.getElementById("issues-list");
  const issues = currentData.issues || [];

  if (issues.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon">✅</div>
        <div class="empty-state-message">No code security issues found</div>
        <div class="empty-state-description">Your code appears to be secure</div>
      </div>
    `;
    return;
  }

  let html = "";
  issues.forEach((issue) => {
    const severityClass = getSeverityClass(issue.severity);
    const severityText = getSeverityText(issue.severity);

    html += `
      <div class="issue-item" data-severity="${issue.severity}" data-file="${
      issue.file
    }">
        <div class="issue-header">
          <div>
            <div class="issue-message">${escapeHtml(issue.message)}</div>
            <div class="issue-location" onclick="openFile('${issue.file}', ${
      issue.line
    })">
              ${getRelativePath(issue.file)}:${issue.line}:${issue.column}
            </div>
          </div>
          <span class="severity-badge ${severityClass}">${severityText}</span>
        </div>
        ${
          issue.code
            ? `<div class="issue-details">Code: ${issue.code}</div>`
            : ""
        }
        ${
          issue.source
            ? `<div class="issue-details">Source: ${issue.source}</div>`
            : ""
        }
      </div>
    `;
  });

  container.innerHTML = html;
}

function updateRecentScans() {
  const container = document.getElementById("scans-list");
  const scans = currentData.dependencyScanResults || [];

  if (scans.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon">📋</div>
        <div class="empty-state-message">No recent scans</div>
        <div class="empty-state-description">Run a scan to see results here</div>
      </div>
    `;
    return;
  }

  let html = "";
  scans.slice(0, 10).forEach((scan) => {
    // Show only last 10 scans
    const scanTime = new Date(scan.timestamp).toLocaleString();
    html += `
      <div class="scan-item">
        <div class="scan-header">
          <div class="scan-type">${
            scan.ecosystem || "Unknown"
          } Dependency Scan</div>
          <div class="scan-time">${scanTime}</div>
        </div>
        <div class="scan-results">
          Found ${scan.vulnerabilities?.length || 0} vulnerabilities in ${
      scan.dependencies?.length || 0
    } dependencies
        </div>
      </div>
    `;
  });

  container.innerHTML = html;
}

function updateFileFilter() {
  const fileFilter = document.getElementById("file-filter");
  const issues = currentData.issues || [];

  // Get unique files
  const files = [...new Set(issues.map((issue) => issue.file))].sort();

  let options = '<option value="all">All Files</option>';
  files.forEach((file) => {
    const relativePath = getRelativePath(file);
    options += `<option value="${file}">${relativePath}</option>`;
  });

  fileFilter.innerHTML = options;
}

function filterIssues() {
  const severityFilter = document.getElementById("severity-filter").value;
  const fileFilter = document.getElementById("file-filter").value;
  const issueItems = document.querySelectorAll(".issue-item");

  issueItems.forEach((item) => {
    const severity = item.dataset.severity;
    const file = item.dataset.file;

    let showItem = true;

    if (severityFilter !== "all" && severity !== severityFilter) {
      showItem = false;
    }

    if (fileFilter !== "all" && file !== fileFilter) {
      showItem = false;
    }

    item.style.display = showItem ? "block" : "none";
  });
}

function getSeverityClass(severity) {
  switch (severity) {
    case 1:
      return "severity-critical"; // Error
    case 2:
      return "severity-high"; // Warning
    case 3:
      return "severity-medium"; // Information
    case 4:
      return "severity-low"; // Hint
    default:
      return "severity-medium";
  }
}

function getSeverityText(severity) {
  switch (severity) {
    case 1:
      return "Critical"; // Error
    case 2:
      return "High"; // Warning
    case 3:
      return "Medium"; // Information
    case 4:
      return "Low"; // Hint
    default:
      return "Medium";
  }
}

function getRelativePath(fullPath) {
  // Simple relative path extraction
  const parts = fullPath.split(/[/\\]/);
  return parts.length > 3
    ? `.../${parts.slice(-2).join("/")}`
    : parts.join("/");
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

// Global functions for onclick handlers
function openFile(file, line) {
  vscode.postMessage({
    type: "openFile",
    file: file,
    line: line,
  });
}

function fixVulnerability(vulnerabilityId) {
  vscode.postMessage({
    type: "fixVulnerability",
    vulnerability: { id: vulnerabilityId },
  });
}

function updateDependency(dependency) {
  vscode.postMessage({
    type: "updateDependency",
    dependency: dependency,
  });
}

// Global scanning state functions for when scans are triggered externally
function showScanningState() {
  const scanFileBtn = document.getElementById("scan-file-btn");

  if (scanFileBtn && !scanFileBtn.disabled) {
    scanFileBtn.disabled = true;
    scanFileBtn.innerHTML =
      '<span class="icon loading-spinner"></span> Scanning...';
  }
}

function hideScanningState() {
  const refreshBtn = document.getElementById("refresh-btn");
  const scanDepsBtn = document.getElementById("scan-deps-btn");
  const scanFileBtn = document.getElementById("scan-file-btn");

  // Only reset buttons that are actually disabled (in loading state)
  if (refreshBtn && refreshBtn.disabled) {
    refreshBtn.disabled = false;
    refreshBtn.innerHTML = '<span class="icon">🔄</span> Refresh';
  }
  if (scanDepsBtn && scanDepsBtn.disabled) {
    scanDepsBtn.disabled = false;
    scanDepsBtn.innerHTML = '<span class="icon">📦</span> Scan Dependencies';
  }
  if (scanFileBtn && scanFileBtn.disabled) {
    scanFileBtn.disabled = false;
    scanFileBtn.innerHTML = '<span class="icon">📄</span> Scan Current File';
  }
}

function showDependencyScanLoading() {
  const scanDepsBtn = document.getElementById("scan-deps-btn");
  if (scanDepsBtn && !scanDepsBtn.disabled) {
    scanDepsBtn.disabled = true;
    scanDepsBtn.innerHTML =
      '<span class="icon loading-spinner"></span> Scanning...';
  }
}

function hideDependencyScanLoading() {
  const scanDepsBtn = document.getElementById("scan-deps-btn");
  if (scanDepsBtn && scanDepsBtn.disabled) {
    scanDepsBtn.disabled = false;
    scanDepsBtn.innerHTML = '<span class="icon">📦</span> Scan Dependencies';
  }
  // Also refresh UI to show new dependency results
  updateUI();
}
