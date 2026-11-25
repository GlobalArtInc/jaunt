const NS = ["http:", "", "www.w3.org", "2000", "svg"].join("/");

const SHAPES = {
  server: [
    ["rect", { x: 3, y: 4, width: 18, height: 7, rx: 2 }],
    ["rect", { x: 3, y: 13, width: 18, height: 7, rx: 2 }],
    ["path", { d: "M7 7.5h.01M7 16.5h.01" }],
  ],
  pulse: [["path", { d: "M3 12h4l3-7 4 14 3-7h4" }]],
  terminal: [
    ["rect", { x: 3, y: 4, width: 18, height: 16, rx: 2 }],
    ["path", { d: "M7 9l3 3-3 3M12.5 15H17" }],
  ],
  shield: [["path", { d: "M12 3l8 3v6c0 4.5-3.2 8-8 9-4.8-1-8-4.5-8-9V6z" }]],
  audit: [
    ["path", { d: "M4 6h12M4 12h6M4 18h6" }],
    ["circle", { cx: 16.5, cy: 14.5, r: 3 }],
    ["path", { d: "M18.7 16.7L21 19" }],
  ],
  add: [
    ["circle", { cx: 12, cy: 12, r: 9 }],
    ["path", { d: "M12 8v8M8 12h8" }],
  ],
  bell: [["path", { d: "M6 9a6 6 0 0112 0c0 5 2 6 2 7H4c0-1 2-2 2-7zM10 20a2 2 0 004 0" }]],
  chevronDown: [["path", { d: "M6 9l6 6 6-6" }]],
  chevronLeft: [["path", { d: "M15 6l-6 6 6 6" }]],
  chevronRight: [["path", { d: "M9 6l6 6-6 6" }]],
  collapse: [["path", { d: "M18 6l-6 6 6 6M7 5v14" }]],
  menu: [["path", { d: "M4 6h16M4 12h16M4 18h16" }]],
  refresh: [["path", { d: "M20 11a8 8 0 10-2.3 5.7M20 5v6h-6" }]],
  grid: [
    ["rect", { x: 4, y: 4, width: 6.5, height: 6.5, rx: 1 }],
    ["rect", { x: 13.5, y: 4, width: 6.5, height: 6.5, rx: 1 }],
    ["rect", { x: 4, y: 13.5, width: 6.5, height: 6.5, rx: 1 }],
    ["rect", { x: 13.5, y: 13.5, width: 6.5, height: 6.5, rx: 1 }],
  ],
  rows: [
    ["rect", { x: 4, y: 4.5, width: 16, height: 6, rx: 1 }],
    ["rect", { x: 4, y: 13.5, width: 16, height: 6, rx: 1 }],
  ],
  sort: [["path", { d: "M7 4v16M4 17l3 3 3-3M17 20V4M14 7l3-3 3 3" }]],
  tag: [
    ["path", { d: "M3 12V4h8l10 10-8 8z" }],
    ["path", { d: "M7.5 8h.01" }],
  ],
  info: [
    ["circle", { cx: 12, cy: 12, r: 9 }],
    ["path", { d: "M12 11v5M12 8h.01" }],
  ],
  database: [
    ["ellipse", { cx: 12, cy: 6, rx: 7, ry: 3 }],
    ["path", { d: "M5 6v6c0 1.7 3.1 3 7 3s7-1.3 7-3V6M5 12v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6" }],
  ],
  copy: [
    ["rect", { x: 9, y: 9, width: 11, height: 11, rx: 2 }],
    ["path", { d: "M5 15V6a2 2 0 012-2h9" }],
  ],
  check: [["path", { d: "M5 12.5l4.5 4.5L19 7.5" }]],
  close: [["path", { d: "M6 6l12 12M18 6L6 18" }]],
  filter: [["path", { d: "M4 5h16l-6 8v6l-4-2v-5z" }]],
  search: [
    ["circle", { cx: 11, cy: 11, r: 6 }],
    ["path", { d: "M20 20l-4.2-4.2" }],
  ],
  clock: [
    ["circle", { cx: 12, cy: 12, r: 9 }],
    ["path", { d: "M12 7v5l3 2" }],
  ],
  logout: [["path", { d: "M10 4H5v16h5M15 8l4 4-4 4M19 12H9" }]],
  sun: [
    ["circle", { cx: 12, cy: 12, r: 4 }],
    ["path", { d: "M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" }],
  ],
  moon: [["path", { d: "M20 14.5A8 8 0 019.5 4 8 8 0 1020 14.5z" }]],
  monitor: [
    ["rect", { x: 3, y: 4, width: 18, height: 12, rx: 2 }],
    ["path", { d: "M8 20h8M12 16v4" }],
  ],
  alert: [["path", { d: "M12 3l10 18H2zM12 10v5M12 18h.01" }]],
  key: [
    ["circle", { cx: 8, cy: 14, r: 4 }],
    ["path", { d: "M11 11l9-9M16 6l3 3" }],
  ],
};

export const ICON_NAMES = Object.keys(SHAPES);

export function svg(tag, attributes) {
  const node = document.createElementNS(NS, tag);
  for (const [name, value] of Object.entries(attributes)) {
    node.setAttribute(name, String(value));
  }
  return node;
}

export function icon(name, { size, label } = {}) {
  if (!Object.hasOwn(SHAPES, name)) {
    throw new Error("unknown icon " + name);
  }
  const shapes = SHAPES[name];
  const root = svg("svg", { viewBox: "0 0 24 24", class: "icon" + (size ? " icon-" + size : ""), focusable: "false" });
  if (label) {
    root.setAttribute("role", "img");
    root.setAttribute("aria-label", label);
  } else {
    root.setAttribute("aria-hidden", "true");
  }
  for (const [tag, attributes] of shapes) {
    root.appendChild(svg(tag, attributes));
  }
  return root;
}
