// VulnZap Usage Bar JavaScript

(function () {
  const vscode = acquireVsCodeApi();

  // DOM elements
  let refreshBtn;
  let detailsBtn;
  let totalScansStat;
  let vulnerabilitiesStat;
  let loadingOverlay;

  // Progress bar elements
  let tierBadge;
  let lineScansUsed;
  let lineScansLimit;
  let progressFill;
  let progressPercentage;
  let remainingText;

  // Initialize when DOM is loaded
  document.addEventListener("DOMContentLoaded", function () {
    initializeElements();
    setupEventListeners();

    // Request initial data
    vscode.postMessage({ type: "requestInitialData" });
  });

  function initializeElements() {
    refreshBtn = document.getElementById("refresh-btn");
    detailsBtn = document.getElementById("details-btn");
    totalScansStat = document.getElementById("total-scans");
    vulnerabilitiesStat = document.getElementById("vulnerabilities");
    loadingOverlay = document.getElementById("loading-overlay");

    // Progress bar elements
    tierBadge = document.getElementById("tier-badge");
    lineScansUsed = document.getElementById("line-scans-used");
    lineScansLimit = document.getElementById("line-scans-limit");
    progressFill = document.getElementById("progress-fill");
    progressPercentage = document.getElementById("progress-percentage");
    remainingText = document.getElementById("remaining-text");

    // Ensure progress bar starts at 0% width
    if (progressFill) {
      progressFill.style.width = "0%";
    }
  }

  function setupEventListeners() {
    if (refreshBtn) {
      refreshBtn.addEventListener("click", function () {
        vscode.postMessage({ type: "refresh" });
      });
    }

    if (detailsBtn) {
      detailsBtn.addEventListener("click", function () {
        vscode.postMessage({ type: "viewDetails" });
      });
    }
  }

  // Handle messages from the extension
  window.addEventListener("message", function (event) {
    const message = event.data;

    switch (message.type) {
      case "updateUsage":
        updateUsageDisplay(message.usage);
        break;
      case "loading":
        setLoadingState(message.loading);
        break;
    }
  });

  function updateUsageDisplay(usage) {
    if (!usage) {
      // Show placeholder values when no data
      updateProgressBar(null);
      updateStatValue(totalScansStat, "--");
      updateStatValue(vulnerabilitiesStat, "--");
      return;
    }

    // Update progress bar
    updateProgressBar(usage);

    // Update compact stats
    updateStatValue(totalScansStat, formatNumber(usage.totalScans));
    updateStatValue(
      vulnerabilitiesStat,
      formatNumber(usage.totalVulnerabilities)
    );

    // Update tooltips with more detailed info
    if (totalScansStat && totalScansStat.parentElement) {
      const completedScans = getCompletedScans(usage.scanStats);
      totalScansStat.parentElement.title = `Total Scans: ${usage.totalScans.toLocaleString()}\nCompleted: ${completedScans}`;
    }

    if (vulnerabilitiesStat && vulnerabilitiesStat.parentElement) {
      const breakdown = usage.severityBreakdown;
      vulnerabilitiesStat.parentElement.title =
        `Total Issues: ${usage.totalVulnerabilities.toLocaleString()}\n` +
        `Critical: ${breakdown.critical}\n` +
        `High: ${breakdown.high}\n` +
        `Medium: ${breakdown.medium}\n` +
        `Low: ${breakdown.low}`;
    }
  }

  function updateProgressBar(usage) {
    if (!usage || !usage.usageLimits) {
      // Show placeholder values
      updateElement(tierBadge, "Free", "free");
      updateElement(lineScansUsed, "--");
      updateElement(lineScansLimit, "--");
      updateElement(progressPercentage, "0%");
      updateElement(remainingText, "-- lines remaining");
      if (progressFill) {
        progressFill.style.width = "0%";
        progressFill.className = "progress-fill";
      }

      return;
    }

    const { lineScans, usageLimits, subscription } = usage;
    const { tier, line_scans_limit: lineScansLimitValue } = subscription;

    // Update tier badge
    if (tierBadge) {
      const displayTier = tier.charAt(0).toUpperCase() + tier.slice(1);
      tierBadge.textContent = displayTier;
      tierBadge.className = `tier-badge ${tier.toLowerCase()}`;
    }

    // Update usage numbers
    updateElement(lineScansUsed, lineScans);

    if (lineScansLimitValue === -1 || lineScansLimitValue <= 0) {
      updateElement(lineScansLimit, "∞");
      updateElement(remainingText, "Unlimited", "unlimited");
      updateElement(progressPercentage, "∞");
      if (progressFill) {
        progressFill.style.width = "100%";
        progressFill.className = "progress-fill";
      }
    } else {
      updateElement(lineScansLimit, formatNumber(lineScansLimitValue));
      console.log("Line scans limit before:", lineScansLimitValue);
      const percentage = Math.min(100, (lineScans / lineScansLimitValue) * 100);
      const remaining = Math.max(0, lineScansLimitValue - lineScans);
      console.log("Line scans limit after:", lineScansLimitValue);
      updateElement(progressPercentage, `${Math.round(percentage)}%`);
      updateElement(remainingText, `${remaining} lines remaining`);

      if (progressFill) {
        console.log("Setting progress bar width to:", `${percentage}%`);

        // Reset any existing width and force a reflow
        progressFill.style.width = "0%";
        progressFill.offsetHeight;

        // Set the actual width with minimum visible width for low percentages
        let displayWidth = percentage;
        if (percentage > 0 && percentage < 5) {
          displayWidth = 5; // Minimum 5% width for visibility
        }

        progressFill.style.width = `${displayWidth}%`;
        console.log(
          "Progress bar width after setting:",
          progressFill.style.width
        );

        // Check computed width after a brief delay
        setTimeout(() => {
          const computedWidth = window.getComputedStyle(progressFill).width;
          const containerWidth = window.getComputedStyle(
            progressFill.parentElement
          ).width;
          console.log("Computed progress bar width:", computedWidth);
          console.log("Progress bar container width:", containerWidth);
          console.log("Progress bar element:", progressFill);
          console.log("Progress bar parent:", progressFill.parentElement);
        }, 100);

        // Change color based on usage percentage
        if (percentage >= 90) {
          progressFill.className = "progress-fill danger";
          console.log("Applied danger color (red)");
        } else if (percentage >= 75) {
          progressFill.className = "progress-fill warning";
          console.log("Applied warning color (yellow)");
        } else {
          progressFill.className = "progress-fill success";
          console.log("Applied success color (blue)");
        }

        // Debug the actual computed color
        setTimeout(() => {
          const computedColor =
            window.getComputedStyle(progressFill).backgroundColor;
          console.log("Computed background color:", computedColor);
        }, 50);

        // Force another reflow to ensure the width change is applied
        progressFill.offsetHeight;
      }
    }
  }

  function updateStatValue(element, value) {
    if (element) {
      console.log("Updating stat value:", element, value);
      // Animate the value change
      element.style.opacity = "0.5";
      element.style.transform = "scale(0.9)";

      setTimeout(() => {
        element.textContent = value;
        element.style.opacity = "1";
        element.style.transform = "scale(1)";
        element.style.transition = "all 0.2s ease";
      }, 100);
    }
  }

  function updateElement(element, value, className) {
    console.log("Updating element:", element, value, className);
    if (element) {
      element.textContent = value;
      console.log("Element text content:", element.textContent);
      if (className) {
        element.className = element.className.split(" ")[0] + " " + className;
      }
    }
  }

  function formatNumber(num) {
    const intNum = parseInt(num);

    if (num >= 1000000) {
      return (num / 1000000).toFixed(1) + "M";
    } else if (num >= 1000) {
      return (num / 1000).toFixed(1) + "K";
    }
    return num.toLocaleString();
  }

  function getCompletedScans(scanStats) {
    if (!scanStats || !Array.isArray(scanStats)) {
      return 0;
    }

    const completedStat = scanStats.find((stat) => stat.status === "COMPLETED");
    return completedStat ? completedStat._count.id : 0;
  }

  function setLoadingState(loading) {
    if (loadingOverlay) {
      loadingOverlay.style.display = loading ? "flex" : "none";
    }

    if (refreshBtn) {
      refreshBtn.disabled = loading;
      if (loading) {
        refreshBtn.style.opacity = "0.6";
      } else {
        refreshBtn.style.opacity = "1";
      }
    }
  }

  // Add some visual feedback for interactions
  function addRippleEffect(element, event) {
    const rect = element.getBoundingClientRect();
    const ripple = document.createElement("span");
    const size = Math.max(rect.width, rect.height);
    const x = event.clientX - rect.left - size / 2;
    const y = event.clientY - rect.top - size / 2;

    ripple.style.width = ripple.style.height = size + "px";
    ripple.style.left = x + "px";
    ripple.style.top = y + "px";
    ripple.classList.add("ripple");

    element.appendChild(ripple);

    setTimeout(() => {
      ripple.remove();
    }, 600);
  }

  // Add ripple effect to buttons
  document.addEventListener("click", function (e) {
    if (e.target.classList.contains("action-btn")) {
      addRippleEffect(e.target, e);
    }
  });
})();
