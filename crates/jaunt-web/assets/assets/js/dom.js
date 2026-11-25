const FORBIDDEN_ATTRIBUTE = /^(on|style$|srcdoc$|formaction$|xlink:href$)/i;
const SAFE_HASH_LINK = /^#\/[A-Za-z0-9\/_\-.~%:=&?+]*$/;
const LOGIN_LINK = /^\/v1\/web\/login(\?return_to=[A-Za-z0-9%._~-]*)?$/;
const PROPERTY_ATTRIBUTES = new Set(["value", "checked", "disabled", "selected", "hidden", "required", "readOnly"]);

export function safeHref(href) {
  const text = String(href);
  if (SAFE_HASH_LINK.test(text) || LOGIN_LINK.test(text)) {
    return text;
  }
  throw new Error("refused to build a link from an unsafe address");
}

export function encodeSegment(value) {
  return encodeURIComponent(String(value)).replace(/[!'()*]/g, (char) => "%" + char.charCodeAt(0).toString(16).toUpperCase());
}

function append(parent, child) {
  if (child === null || child === undefined || child === false || child === true) {
    return;
  }
  if (Array.isArray(child)) {
    for (const item of child) {
      append(parent, item);
    }
    return;
  }
  if (typeof child === "string" || typeof child === "number") {
    parent.appendChild(document.createTextNode(String(child)));
    return;
  }
  parent.appendChild(child);
}

export function el(tag, props, ...children) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(props || {})) {
    if (value === null || value === undefined || value === false) {
      continue;
    }
    if (name === "class") {
      node.setAttribute("class", value);
    } else if (name === "text") {
      node.textContent = String(value);
    } else if (name === "on") {
      for (const [type, handler] of Object.entries(value)) {
        node.addEventListener(type, handler);
      }
    } else if (name === "data") {
      for (const [key, item] of Object.entries(value)) {
        node.setAttribute("data-" + key, String(item));
      }
    } else if (name === "href") {
      node.setAttribute("href", safeHref(value));
    } else if (FORBIDDEN_ATTRIBUTE.test(name)) {
      throw new Error("refused to set attribute " + name);
    } else if (PROPERTY_ATTRIBUTES.has(name)) {
      node[name] = value;
    } else if (value === true) {
      node.setAttribute(name, "");
    } else {
      node.setAttribute(name, String(value));
    }
  }
  for (const child of children) {
    append(node, child);
  }
  return node;
}

export function replace(parent, ...children) {
  parent.replaceChildren();
  for (const child of children) {
    append(parent, child);
  }
}

export function uniqueId(prefix) {
  uniqueId.counter = (uniqueId.counter || 0) + 1;
  return prefix + "-" + uniqueId.counter;
}
