(function () {
  var root = document.documentElement;
  var saved = null;
  try {
    saved = localStorage.getItem("jaunt-theme");
  } catch (error) {
    saved = null;
  }
  if (saved === "light" || saved === "dark") {
    root.setAttribute("data-theme", saved);
  }
})();
