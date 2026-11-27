import { el, replace, uniqueId } from "../dom.js";
import { openConfirm, openDialog } from "../dialog.js";
import { clean } from "../format.js";
import { icon } from "../icons.js";
import { menuButton } from "../menu.js";
import { S } from "../strings.js";
import { button } from "../ui.js";
import { createQuickOpen } from "./quick-open.js";
import { createSession } from "./screen.js";
import { createTabs } from "./tabs.js";

const NARROW_QUERY = "(max-width: 640px)";

function isNarrow() {
  return typeof window.matchMedia === "function" && window.matchMedia(NARROW_QUERY).matches;
}

function glyphNode(session) {
  const [className, char] = session.snapshot().glyph;
  return el("span", { class: "st " + className, "aria-hidden": "true", text: char });
}

export function createWorkspace({ host, api, connect, announce, markTerminalOff, onChange, setTitle, now = () => Date.now() }) {
  const text = S.terminal.tabs;
  const tabs = createTabs({ max: connect.terminalConfig().maxPerUser });
  const listeners = new Set();
  let visible = false;
  let destroyed = false;
  let dialog = null;

  const tablist = el("div", { class: "ttabs", role: "tablist", "aria-label": text.listLabel });
  const newButton = el("button", { type: "button", class: "btn btn-ghost btn-sm", on: { click: () => openNew({}) } }, icon("plus", { size: "sm" }), el("span", { text: text.newTerminal }));
  const limitHint = el("span", { class: "visually-hidden", id: uniqueId("limit-hint") });
  const countLabel = el("span", {});
  const countText = el("span", { class: "muted small", role: "status", title: text.countNote }, countLabel, el("span", { class: "visually-hidden", text: ". " + text.countNote }));
  const allMenu = menuButton({
    className: "btn btn-sm btn-menu",
    align: "end",
    content: [icon("list", { size: "sm" }), el("span", { text: text.allTerminals }), icon("chevronDown", { size: "sm" })],
    items: () => menuEntries(),
  });
  const tabbar = el("div", { class: "tabbar" }, tablist, newButton, limitHint, el("div", { class: "tabbar-end" }, countText, allMenu.element));
  const switcherGlyph = el("span", { class: "st", "aria-hidden": "true" });
  const switcherLabel = el("span", { class: "mono" });
  const switcherWords = el("span", { class: "visually-hidden" });
  const switcherCount = el("span", { class: "count" });
  const switcherMenu = menuButton({
    className: "btn switcher-btn",
    content: [switcherGlyph, switcherLabel, switcherWords, switcherCount, icon("chevronDown", { size: "sm" })],
    items: () => menuEntries(),
  });
  const switcherNew = el("button", { type: "button", class: "icon-btn", "aria-label": text.newTerminal, on: { click: () => openNew({}) } }, icon("plus"));
  const switcher = el("div", { class: "switcher n-flex" }, switcherMenu.element, switcherNew);
  const panes = el("div", { class: "ws-panes" });
  const root = el("div", { class: "ws", hidden: true }, tabbar, switcher, panes);
  host.appendChild(root);

  const sessionEnv = {
    api,
    announce: (message) => announce(message),
    config: () => connect.terminalConfig(),
    onChange: () => changed(),
    terminalCount: () => tabs.count(),
    markTerminalOff: () => markTerminalOff(),
    requestNew: (preselect) => openNew(preselect || {}),
    showTerminals: () => showTerminals(),
    requestClose: () => undefined,
  };

  function envFor(id) {
    return { ...sessionEnv, requestClose: () => requestClose(id) };
  }

  function isLive(item) {
    return !item.session.isEnded();
  }

  function liveCount() {
    return tabs.items().filter(isLive).length;
  }

  function menuEntries() {
    const items = tabs.items();
    const entries = [{ type: "heading", text: text.menuHeading(items.length, tabs.max()) }];
    for (const item of items) {
      const snap = item.session.snapshot();
      const elapsed = S.terminal.session.clock(snap.elapsedMs / 1000);
      entries.push({
        role: "menuitemradio",
        checked: item.id === tabs.activeId(),
        content: [glyphNode(item.session), " ", el("span", { class: "mono", text: item.session.label })],
        hint: snap.state === "endedInfo" || snap.state === "endedBad" ? snap.words : snap.words + ", " + elapsed,
        onSelect: () => activate(item.id, { focus: true }),
      });
    }
    entries.push({ type: "separator" });
    entries.push(
      tabs.atLimit()
        ? { text: text.newTerminal, icon: "plus", disabled: true, hint: text.limitReason(tabs.max()) }
        : { text: text.newTerminal, icon: "plus", onSelect: () => openNew({}) },
    );
    const hasEnded = tabs.idsWhere((item) => !isLive(item)).length > 0;
    entries.push({ text: text.closeEnded, icon: "close", disabled: !hasEnded, onSelect: () => closeEnded() });
    return entries;
  }

  function emit() {
    for (const listener of listeners) {
      listener();
    }
    onChange();
  }

  function focusTabButton(id) {
    const target = Array.from(tablist.querySelectorAll('[role="tab"]')).find((node) => node.getAttribute("data-tab") === id);
    if (target && !isNarrow()) {
      target.focus();
      return true;
    }
    return false;
  }

  function paintTabs() {
    tabs.setMax(connect.terminalConfig().maxPerUser);
    const activeEl = document.activeElement;
    const heldTab = activeEl && tablist.contains(activeEl) ? { id: activeEl.getAttribute("data-tab"), close: activeEl.getAttribute("data-close") } : null;
    const items = tabs.items();
    replace(
      tablist,
      items.map((item) => {
        const active = item.id === tabs.activeId();
        const snap = item.session.snapshot();
        const select = el(
          "button",
          { type: "button", role: "tab", class: "ttab-btn", id: "tab-" + item.id, "aria-selected": String(active), "aria-controls": "pane-" + item.id, tabindex: active ? "0" : "-1", data: { tab: item.id } },
          glyphNode(item.session),
          el("span", { class: "lbl", text: item.session.label }),
          el("span", { class: "visually-hidden", text: ", " + snap.words }),
        );
        select.addEventListener("click", () => activate(item.id, { focus: false }));
        const close = el("button", { type: "button", class: "icon-btn", "aria-label": text.closeLabel(item.session.label), data: { close: item.id } }, icon("close", { size: "sm" }));
        close.addEventListener("click", () => requestClose(item.id));
        return el("div", { class: "ttab" + (active ? " is-active" : ""), role: "presentation" }, select, close);
      }),
    );
    const current = tabs.active();
    countLabel.textContent = text.count(items.length, tabs.max());
    const atLimit = tabs.atLimit();
    newButton.disabled = atLimit;
    switcherNew.disabled = atLimit;
    if (atLimit) {
      limitHint.textContent = text.limitReason(tabs.max());
      newButton.setAttribute("aria-describedby", limitHint.id);
      newButton.title = text.limitReason(tabs.max());
      switcherNew.title = text.limitReason(tabs.max());
    } else {
      limitHint.textContent = "";
      newButton.removeAttribute("aria-describedby");
      newButton.removeAttribute("title");
      switcherNew.removeAttribute("title");
    }
    if (current) {
      const snap = current.session.snapshot();
      const [className, char] = snap.glyph;
      switcherGlyph.className = "st " + className;
      switcherGlyph.textContent = char;
      switcherLabel.textContent = current.session.label;
      switcherWords.textContent = ", " + snap.words + text.switcherSuffix;
      switcherCount.textContent = text.switcherCount(items.findIndex((item) => item.id === current.id) + 1, items.length);
    }
    for (const item of items) {
      item.session.refreshCount();
    }
    if (heldTab !== null && document.activeElement !== activeEl) {
      if (heldTab.close !== null) {
        const again = Array.from(tablist.querySelectorAll("[data-close]")).find((node) => node.getAttribute("data-close") === heldTab.close);
        if (again) {
          again.focus();
        }
      } else if (heldTab.id !== null) {
        focusTabButton(heldTab.id);
      }
    }
  }

  function applyActive(previousId, { focus }) {
    const previous = previousId === null ? null : tabs.get(previousId);
    const current = tabs.active();
    if (previous && previous !== current) {
      previous.session.hide();
    }
    for (const item of tabs.items()) {
      if (item !== current && item !== previous) {
        item.session.hide();
      }
    }
    if (current && visible) {
      current.session.show();
      setTitle(current.session.label);
      if (focus) {
        if (current.session.isReady()) {
          current.session.focus();
        } else {
          current.session.focusHeader();
        }
      }
    }
  }

  function changed() {
    if (destroyed) {
      return;
    }
    paintTabs();
    root.hidden = !visible || tabs.count() === 0;
    emit();
  }

  function activate(id, { focus = false } = {}) {
    const previous = tabs.activeId();
    if (!tabs.activate(id)) {
      return;
    }
    applyActive(previous, { focus });
    changed();
  }

  function step(delta) {
    if (tabs.count() < 2) {
      return;
    }
    const previous = tabs.activeId();
    tabs.step(delta);
    applyActive(previous, { focus: true });
    changed();
    const item = tabs.active();
    if (item) {
      announce(text.switched(item.session.label));
    }
  }

  function open({ node, login }) {
    if (tabs.atLimit()) {
      return { ok: false, reason: "limit" };
    }
    const id = uniqueId("term");
    const session = createSession(envFor(id), { node, login });
    session.pane.id = "pane-" + id;
    session.pane.setAttribute("aria-labelledby", "tab-" + id);
    panes.appendChild(session.pane);
    const previous = tabs.activeId();
    tabs.add({ id, session });
    applyActive(previous, { focus: false });
    changed();
    announce(text.opened(session.label));
    session.start();
    return { ok: true, id };
  }

  function closeNow(id) {
    const result = tabs.close(id);
    if (result === null) {
      return;
    }
    result.closed.session.dispose();
    applyActive(null, { focus: false });
    changed();
    announce(text.closed(result.closed.session.label));
    if (result.next !== null && !focusTabButton(result.next)) {
      switcherMenu.button.focus();
    }
  }

  function requestClose(id) {
    const item = tabs.get(id);
    if (!item) {
      return;
    }
    if (!item.session.isReady()) {
      closeNow(id);
      return;
    }
    const snap = item.session.snapshot();
    const copy = S.terminal.close;
    openConfirm({
      title: copy.title(item.session.label),
      intro: [copy.before, el("strong", { text: clean(item.session.node) }), copy.after],
      effects: [copy.effectEnds, snap.recording === "off" ? copy.effectNotRecorded : copy.effectRecorded],
      danger: true,
      closeButton: false,
      focusCancel: true,
      confirmLabel: copy.yes,
      cancelLabel: copy.keep,
      onConfirm: async () => undefined,
      onDone: () => closeNow(id),
    });
  }

  function closeEnded() {
    for (const id of tabs.idsWhere((item) => !isLive(item))) {
      closeNow(id);
    }
  }

  function openNew(preselect) {
    if (dialog !== null && dialog.isOpen()) {
      return;
    }
    const config = connect.terminalConfig();
    tabs.setMax(config.maxPerUser);
    const quick = createQuickOpen({
      connect,
      now,
      count: tabs.count(),
      max: tabs.max(),
      preselect,
      inline: false,
      onOpen: (node, login) => {
        dialog.close();
        open({ node, login });
      },
      onCancel: () => dialog.close(),
    });
    dialog = openDialog({ title: S.terminal.quick.title, body: [quick.body], footer: quick.footer, className: "quick", closeIcon: true, closeLabel: S.terminal.quick.closeLabel });
    quick.focus();
    connect.refresh().then(() => {
      if (dialog !== null && dialog.isOpen() && !destroyed) {
        quick.refresh();
      }
    });
  }

  function showTerminals() {
    const menu = isNarrow() ? switcherMenu : allMenu;
    menu.button.focus();
    menu.open({ focus: "first" });
  }

  function onKeyDown(event) {
    if (event.defaultPrevented || !event.ctrlKey || !event.altKey || event.shiftKey || event.metaKey) {
      return;
    }
    if (event.key === "PageUp" || event.key === "PageDown") {
      event.preventDefault();
      event.stopPropagation();
      step(event.key === "PageDown" ? 1 : -1);
    }
  }

  function onTabKey(event) {
    const buttons = Array.from(tablist.querySelectorAll('[role="tab"]'));
    const index = buttons.indexOf(document.activeElement);
    if (index === -1) {
      return;
    }
    let target = null;
    if (event.key === "ArrowRight") {
      target = buttons[(index + 1) % buttons.length];
    } else if (event.key === "ArrowLeft") {
      target = buttons[(index - 1 + buttons.length) % buttons.length];
    } else if (event.key === "Home") {
      target = buttons[0];
    } else if (event.key === "End") {
      target = buttons[buttons.length - 1];
    }
    if (target) {
      event.preventDefault();
      activate(target.getAttribute("data-tab"), { focus: false });
      focusTabButton(target.getAttribute("data-tab"));
    }
  }

  function onBeforeUnload(event) {
    if (liveCount() > 0) {
      event.preventDefault();
      event.returnValue = "";
    }
  }

  function onPageHide() {
    for (const item of tabs.items()) {
      item.session.closeConnection();
    }
  }

  root.addEventListener("keydown", onKeyDown);
  tablist.addEventListener("keydown", onTabKey);
  window.addEventListener("beforeunload", onBeforeUnload);
  window.addEventListener("pagehide", onPageHide);
  paintTabs();

  return {
    element: root,
    open,
    openNew,
    requestClose,
    closeEnded,
    activate,
    step,
    showTerminals,
    count: () => tabs.count(),
    liveCount,
    max: () => tabs.max(),
    atLimit: () => tabs.atLimit(),
    labels: () => tabs.items().map((item) => item.session.label),
    activeLabel: () => (tabs.active() ? tabs.active().session.label : null),
    setMax(value) {
      tabs.setMax(value);
      paintTabs();
    },
    onChange(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    setVisible(next) {
      visible = next;
      root.hidden = !visible || tabs.count() === 0;
      const current = tabs.active();
      if (current) {
        if (visible) {
          current.session.show();
          setTitle(current.session.label);
        } else {
          current.session.hide();
        }
      }
    },
    destroy() {
      destroyed = true;
      window.removeEventListener("beforeunload", onBeforeUnload);
      window.removeEventListener("pagehide", onPageHide);
      for (const item of tabs.items()) {
        item.session.dispose();
      }
      root.remove();
      listeners.clear();
    },
  };
}
