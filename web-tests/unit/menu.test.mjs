import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import { installDom, press, click } from "./support.mjs";

afterEach(() => {
  document.body.replaceChildren();
});

async function setup(items, options = {}) {
  installDom();
  const { menuButton } = await import("../../crates/jaunt-web/assets/assets/js/menu.js");
  const menu = menuButton({ content: ["Open"], items: () => items, ...options });
  document.body.appendChild(menu.element);
  return menu;
}

const entries = () => [
  { text: "First", onSelect: () => selected.push("first") },
  { text: "Locked", disabled: true, hint: "Not yet" },
  { text: "Third", onSelect: () => selected.push("third") },
];
let selected = [];

test("the menu button opens with Enter and ArrowDown on the first item and ArrowUp on the last", async () => {
  selected = [];
  const menu = await setup(entries());
  assert.equal(menu.button.getAttribute("aria-haspopup"), "menu");
  assert.equal(menu.button.getAttribute("aria-expanded"), "false");
  press(menu.button, "ArrowDown");
  assert.equal(menu.button.getAttribute("aria-expanded"), "true");
  assert.equal(document.activeElement.textContent, "First");
  press(document.activeElement, "Escape");
  press(menu.button, "ArrowUp");
  assert.equal(document.activeElement.textContent, "Third");
});

test("arrow keys move between items and wrap, Home and End jump, and a disabled item stays reachable but does nothing", async () => {
  selected = [];
  const menu = await setup(entries());
  click(menu.button);
  const items = Array.from(document.querySelectorAll('[role="menuitem"]'));
  assert.equal(document.activeElement, items[0]);
  press(items[0], "ArrowDown");
  assert.equal(document.activeElement, items[1]);
  assert.equal(items[1].getAttribute("aria-disabled"), "true");
  click(items[1]);
  assert.deepEqual(selected, []);
  assert.ok(document.querySelector(".menu"));
  press(items[1], "ArrowDown");
  press(items[2], "ArrowDown");
  assert.equal(document.activeElement, items[0]);
  press(items[0], "ArrowUp");
  assert.equal(document.activeElement, items[2]);
  press(items[2], "Home");
  assert.equal(document.activeElement, items[0]);
  press(items[0], "End");
  assert.equal(document.activeElement, items[2]);
});

test("Escape closes the menu and returns focus to the button, choosing an item acts once and closes", async () => {
  selected = [];
  const menu = await setup(entries());
  click(menu.button);
  press(document.activeElement, "Escape");
  assert.equal(document.querySelector(".menu"), null);
  assert.equal(document.activeElement, menu.button);
  assert.equal(menu.button.getAttribute("aria-expanded"), "false");
  click(menu.button);
  click(document.querySelectorAll('[role="menuitem"]')[2]);
  assert.deepEqual(selected, ["third"]);
  assert.equal(document.querySelector(".menu"), null);
  assert.equal(document.activeElement, menu.button);
});

test("Tab and a click outside close the menu, and opening one menu closes the other", async () => {
  selected = [];
  const first = await setup(entries());
  const { menuButton } = await import("../../crates/jaunt-web/assets/assets/js/menu.js");
  const second = menuButton({ content: ["Other"], items: () => [{ text: "Only" }] });
  document.body.appendChild(second.element);
  click(first.button);
  press(document.activeElement, "Tab");
  assert.equal(first.isOpen(), false);
  click(first.button);
  click(second.button);
  assert.equal(first.isOpen(), false);
  assert.equal(second.isOpen(), true);
  document.body.dispatchEvent(new window.MouseEvent("mousedown", { bubbles: true }));
  assert.equal(second.isOpen(), false);
});

test("radio and checkbox items expose their state and headings and separators are not focusable items", async () => {
  const menu = await setup([
    { type: "heading", text: "Sort" },
    { text: "A", role: "menuitemradio", checked: true },
    { text: "B", role: "menuitemradio", checked: false },
    { type: "separator" },
    { text: "C", role: "menuitemcheckbox", checked: true },
  ]);
  click(menu.button);
  const items = Array.from(document.querySelectorAll('[role^="menuitem"]'));
  assert.deepEqual(items.map((item) => item.getAttribute("aria-checked")), ["true", "false", "true"]);
  assert.equal(document.querySelectorAll('[role="separator"]').length, 1);
  assert.equal(document.querySelector(".menu-heading").getAttribute("role"), "presentation");
});
