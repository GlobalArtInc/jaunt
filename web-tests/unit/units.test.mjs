import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import { installDom } from "./support.mjs";

const JS = "../../crates/jaunt-web/assets/assets/";

test("query strings encode separators, fragments and unicode so every value round-trips", async () => {
  installDom();
  const { queryString } = await import(JS + "js/api.js");
  const values = { label: ["env:prod", "k:v&x=1"], q: "a#b c", user: "jürgen@example.com", skip: "", none: null, gone: undefined, limit: 50 };
  const text = queryString(values);
  assert.ok(!text.includes("#") && !text.includes(" ") && !text.slice(1).includes("?"));
  const parsed = new URLSearchParams(text);
  assert.deepEqual(parsed.getAll("label"), ["env:prod", "k:v&x=1"]);
  assert.equal(parsed.get("q"), "a#b c");
  assert.equal(parsed.get("user"), "jürgen@example.com");
  assert.equal(parsed.get("limit"), "50");
  assert.equal(parsed.has("skip") || parsed.has("none") || parsed.has("gone"), false);
  assert.equal(queryString({}), "");
});

test("the theme setting takes auto, light and dark, persists the choice and the early script restores it", async () => {
  const dom = installDom();
  const { setTheme, currentTheme } = await import(JS + "js/theme.js");
  assert.equal(currentTheme(), "auto");
  assert.equal(setTheme("light"), "light");
  assert.equal(window.localStorage.getItem("jaunt-theme"), "light");
  assert.equal(setTheme("dark"), "dark");
  assert.equal(window.localStorage.getItem("jaunt-theme"), "dark");
  document.documentElement.removeAttribute("data-theme");
  window.eval(await readFile(new URL(JS + "theme-init.js", import.meta.url), "utf8"));
  assert.equal(document.documentElement.getAttribute("data-theme"), "dark");
  assert.equal(setTheme("auto"), "auto");
  assert.equal(setTheme("<bad>"), "auto");
  assert.equal(window.localStorage.getItem("jaunt-theme"), null);
  assert.equal(document.documentElement.hasAttribute("data-theme"), false);
  window.localStorage.setItem("jaunt-theme", "<script>");
  window.eval(await readFile(new URL(JS + "theme-init.js", import.meta.url), "utf8"));
  assert.equal(document.documentElement.hasAttribute("data-theme"), false);
  dom.window.close();
});
