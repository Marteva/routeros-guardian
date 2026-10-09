// Applies the stored colour theme before the first paint (loaded synchronously
// in <head>; CSP forbids inline scripts). "auto" = no data-theme attribute,
// the stylesheet then follows prefers-color-scheme.
"use strict";
(function () {
  try {
    var t = localStorage.getItem("guardian.theme");
    if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t);
  } catch (e) { /* storage unavailable */ }
})();
