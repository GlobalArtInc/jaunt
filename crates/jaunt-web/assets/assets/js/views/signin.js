import { el, replace } from "../dom.js";
import { S } from "../strings.js";
import { banner, button } from "../ui.js";

const RETURN_PATH = /^#\/[A-Za-z0-9\/_\-.]*$/;

export function loginHref() {
  const hash = typeof location !== "undefined" ? location.hash : "";
  const target = RETURN_PATH.test(hash) && hash.length <= 120 ? "/" + hash : "/";
  return "/v1/web/login?return_to=" + encodeURIComponent(target);
}

export function renderSignIn(root, { notice, expired, error, onRetry } = {}) {
  document.title = (expired ? S.titles.expired : S.titles.signIn) + " · " + S.product;
  const card = el(
    "section",
    { class: "card", "aria-labelledby": "signin-title" },
    el("div", { class: "brand-row" }, el("span", { class: "brand-mark", "aria-hidden": "true", text: "J" }), S.product),
    el("h1", { id: "signin-title", text: expired ? S.expired.heading : S.signIn.heading }),
  );
  if (expired) {
    card.appendChild(el("p", { text: S.expired.body }));
  } else if (!error) {
    card.appendChild(el("p", { text: S.signIn.body }));
  }
  if (notice) {
    card.appendChild(banner("info", notice));
  }
  if (error) {
    card.appendChild(banner("danger", error));
    card.appendChild(button(S.retry, { kind: "primary", onClick: onRetry }));
  } else {
    card.appendChild(el("a", { class: "btn btn-primary btn-block", href: loginHref(), "data-autofocus": "" }, expired ? S.expired.signIn : S.signIn.button));
    card.appendChild(el("p", { class: "muted small", text: S.signIn.note }));
  }
  card.appendChild(el("p", { class: "muted small" }, S.signIn.server + ": ", el("span", { class: "mono", text: location.host })));
  replace(root, el("main", { class: "solo-guided guided", id: "main", tabindex: "-1" }, card));
  const target = root.querySelector("[data-autofocus]") || root.querySelector("#main");
  target.focus();
}
