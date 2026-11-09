/* Small helpers shared by all pages (no inline scripts, for a strict CSP). */
document.querySelectorAll("[data-print]").forEach(function (b) {
  b.addEventListener("click", function () { window.print(); });
});
