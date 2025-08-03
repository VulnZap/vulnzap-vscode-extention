// Get the VS Code API
const vscode = acquireVsCodeApi();

document.addEventListener("DOMContentLoaded", function () {
  // Handle sign in button click
  const signInBtn = document.getElementById("signin-btn");
  if (signInBtn) {
    signInBtn.addEventListener("click", function () {
      // Add loading state
      signInBtn.disabled = true;
      signInBtn.innerHTML = '<span class="button-icon">⏳</span> Signing In...';

      // Send message to extension
      vscode.postMessage({
        type: "login",
      });

      // Reset button after a short delay (in case login fails)
      setTimeout(() => {
        signInBtn.disabled = false;
        signInBtn.innerHTML = '<span class="button-icon">🔑</span> Sign In';
      }, 5000);
    });
  }

  // Handle create account link click
  const createAccountLink = document.getElementById("create-account");
  if (createAccountLink) {
    createAccountLink.addEventListener("click", function (e) {
      e.preventDefault();
      vscode.postMessage({
        type: "createAccount",
      });
    });
  }

  // Add hover effects for feature items
  const featureItems = document.querySelectorAll(".features-list li");
  featureItems.forEach((item) => {
    item.addEventListener("mouseenter", function () {
      this.style.backgroundColor = "var(--vscode-list-hoverBackground)";
    });

    item.addEventListener("mouseleave", function () {
      this.style.backgroundColor = "";
    });
  });
});
