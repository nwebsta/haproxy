"use strict";

// Domains direkt oder Domainliste: passenden Bereich einblenden.
function setupDomainMode() {
  const form = document.querySelector("[data-domain-mode]");
  if (!form) return;
  const update = () => {
    const checked = form.querySelector("input[name=domain_mode]:checked");
    const mode = checked ? checked.value : "direct";
    form.querySelectorAll("[data-mode]").forEach((el) => {
      el.hidden = el.dataset.mode !== mode;
    });
  };
  form.addEventListener("change", (e) => {
    if (e.target.name === "domain_mode") update();
  });
  update();
}

// Rückfrage vor Löschen, Verwerfen, Wiederherstellen (kein Inline-JS wegen CSP).
document.addEventListener(
  "submit",
  (e) => {
    const msg = e.target.dataset ? e.target.dataset.confirm : null;
    if (msg && !window.confirm(msg)) e.preventDefault();
  },
  true
);

document.addEventListener("DOMContentLoaded", setupDomainMode);
