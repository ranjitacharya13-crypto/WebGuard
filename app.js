"use strict";

const checklistInputs = Array.from(document.querySelectorAll(".check-input"));
const progressFill = document.querySelector("#progress-fill");
const progressTrack = document.querySelector("#progress-track");
const completedCount = document.querySelector("#completed-count");
const progressPercent = document.querySelector("#progress-percent");
const sectionCount = document.querySelector("#section-count");
const todayLabel = document.querySelector("#today-label");
const linkForm = document.querySelector("#link-form");
const linkInput = document.querySelector("#link-input");
const linkResult = document.querySelector("#link-result");
const passwordForm = document.querySelector("#password-form");
const passwordInput = document.querySelector("#password-input");
const passwordResult = document.querySelector("#password-result");

todayLabel.textContent = new Intl.DateTimeFormat(undefined, {
  weekday: "short",
  month: "short",
  day: "numeric"
}).format(new Date());

function updateChecklistProgress() {
  const completed = checklistInputs.filter((input) => input.checked).length;
  const total = checklistInputs.length;
  const percent = total === 0 ? 0 : Math.round((completed / total) * 100);

  completedCount.textContent = `${completed} of ${total}`;
  progressPercent.textContent = `${percent}%`;
  sectionCount.textContent = `${completed} / ${total} done`;
  progressTrack.setAttribute("aria-valuenow", String(completed));
  progressFill.style.width = `${percent}%`;
}

checklistInputs.forEach((input) => {
  input.addEventListener("change", updateChecklistProgress);
});

function showResult(element, heading, details, tone) {
  element.replaceChildren();
  element.dataset.tone = tone;

  const title = document.createElement("strong");
  title.textContent = heading;
  element.append(title);

  const list = document.createElement("ul");
  details.forEach((detail) => {
    const item = document.createElement("li");
    item.textContent = detail;
    list.append(item);
  });
  element.append(list);
  element.hidden = false;
}

linkForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const rawValue = linkInput.value.trim();

  if (!rawValue) {
    showResult(linkResult, "Enter a link to review.", ["This check only looks at its visible format."], "warning");
    return;
  }

  let url;
  try {
    url = new URL(/^[a-z][a-z\d+.-]*:/i.test(rawValue) ? rawValue : `https://${rawValue}`);
  } catch {
    showResult(linkResult, "This doesn't look like a valid web address.", ["Check for typos and try again."], "warning");
    return;
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    showResult(linkResult, "This link uses an unusual protocol.", ["Don't open it unless you expected this type of link and trust its source."], "warning");
    return;
  }

  const observations = [];
  let tone = "good";

  if (url.protocol !== "https:") {
    observations.push("It does not use HTTPS, so the connection is not encrypted.");
    tone = "warning";
  } else {
    observations.push("It uses HTTPS, which encrypts the connection but does not prove the site is trustworthy.");
  }
  if (url.username || url.password) {
    observations.push("The address contains sign-in information before the host. Treat it with caution.");
    tone = "warning";
  }
  if (url.hostname.split(".").some((label) => label.startsWith("xn--"))) {
    observations.push("The host uses internationalized characters. Check the spelling carefully.");
    tone = "warning";
  }
  observations.push(`Host shown: ${url.hostname}`);
  showResult(linkResult, "Quick format review", observations, tone);
});

function estimatePasswordStrength(password) {
  if (password.length === 0) {
    return { label: "Enter a sample password to see general guidance.", tips: [], tone: "warning" };
  }

  let score = 0;
  if (password.length >= 12) score++;
  if (password.length >= 16) score++;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
  if (/\d/.test(password)) score++;
  if (/[^\p{L}\p{N}]/u.test(password)) score++;

  const tips = [];
  if (password.length < 12) tips.push("Use at least 12 characters; longer is generally better.");
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password)) tips.push("Mixing letter cases can add variety.");
  if (!/\d/.test(password) || !/[^\p{L}\p{N}]/u.test(password)) tips.push("Consider adding numbers or symbols if your password manager supports them.");

  if (score <= 1) return { label: "Needs improvement", tips, tone: "warning" };
  if (score <= 3) return { label: "Getting stronger", tips, tone: "warning" };
  return { label: "Good length and variety", tips: ["A unique passphrase stored in a password manager is a strong option."], tone: "good" };
}

passwordForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const estimate = estimatePasswordStrength(passwordInput.value);
  const details = estimate.tips.length ? estimate.tips : ["This is only a basic estimate, not a guarantee of security."];
  showResult(passwordResult, estimate.label, details, estimate.tone);
  passwordInput.value = "";
});
