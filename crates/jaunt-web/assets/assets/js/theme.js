const KEY = "jaunt-theme";
const ORDER = ["auto", "light", "dark"];

export function currentTheme() {
  const value = document.documentElement.getAttribute("data-theme");
  return value === "light" || value === "dark" ? value : "auto";
}

function apply(theme) {
  if (theme === "light" || theme === "dark") {
    document.documentElement.setAttribute("data-theme", theme);
  } else {
    document.documentElement.removeAttribute("data-theme");
  }
}

export function setTheme(requested) {
  const next = ORDER.includes(requested) ? requested : "auto";
  apply(next);
  try {
    if (next === "auto") {
      localStorage.removeItem(KEY);
    } else {
      localStorage.setItem(KEY, next);
    }
  } catch {
    return next;
  }
  return next;
}
