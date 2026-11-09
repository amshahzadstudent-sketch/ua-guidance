"use strict";
document.querySelectorAll(".counselor-photo[data-fallback]").forEach(function (img) {
  function fallback() {
    var src = img.dataset.fallback;
    if (!src) return;
    delete img.dataset.fallback;
    img.alt = "Profile photo unavailable";
    img.src = src;
  }
  img.addEventListener("error", fallback, {once: true});
  if (img.complete && img.naturalWidth === 0) fallback();
});
