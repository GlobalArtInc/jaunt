import { S } from "./strings.js";

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

export function themeLabel() {
  const theme = currentTheme();
  return S.themeLabel(theme.charAt(0).toUpperCase() + theme.slice(1));
}

export function cycleTheme() {
  const next = ORDER[(ORDER.indexOf(currentTheme()) + 1) % ORDER.length];
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
