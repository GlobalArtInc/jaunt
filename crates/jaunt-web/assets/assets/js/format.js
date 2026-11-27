const UNSAFE_TEXT = /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/g;
const MAX_TEXT = 2048;
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

export function clean(value) {
  if (value === null || value === undefined) {
    return "";
  }
  let text = typeof value === "string" ? value : String(value);
  if (text.length > MAX_TEXT) {
    text = text.slice(0, MAX_TEXT) + "…";
  }
  return text.replace(UNSAFE_TEXT, "�");
}

export function singleLine(value) {
  return String(value === null || value === undefined ? "" : value)
    .replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, " ")
    .replace(/[\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/g, "")
    .trim();
}

function pad(number) {
  return String(number).padStart(2, "0");
}

export function time(seconds) {
  if (typeof seconds !== "number" || !Number.isFinite(seconds)) {
    return "";
  }
  const date = new Date(seconds * 1000);
  if (Number.isNaN(date.getTime())) {
    return "";
  }
  return (
    date.getUTCDate() + " " + MONTHS[date.getUTCMonth()] + " " + date.getUTCFullYear() + " " +
    pad(date.getUTCHours()) + ":" + pad(date.getUTCMinutes()) + " UTC"
  );
}

export function timeWithSeconds(seconds) {
  const base = time(seconds);
  if (base === "") {
    return "";
  }
  const date = new Date(seconds * 1000);
  return base.replace(" UTC", ":" + pad(date.getUTCSeconds()) + " UTC");
}

export function span(totalSeconds) {
  const seconds = Math.max(0, Math.floor(totalSeconds));
  if (seconds < 60) {
    return seconds + " s";
  }
  if (seconds < 3600) {
    return Math.floor(seconds / 60) + " min";
  }
  if (seconds < 86400) {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    return hours + " h" + (minutes > 0 ? " " + minutes + " min" : "");
  }
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  return days + " d" + (hours > 0 ? " " + hours + " h" : "");
}

export function untilOrSince(seconds, nowMs) {
  if (typeof seconds !== "number") {
    return { text: "", urgency: "none" };
  }
  const delta = seconds - Math.floor(nowMs / 1000);
  if (delta <= 0) {
    return { text: "Expired " + span(-delta) + " ago", urgency: "expired" };
  }
  return { text: span(delta) + " left", urgency: delta < 86400 ? "soon" : "fine" };
}

export function ago(seconds, nowMs) {
  if (typeof seconds !== "number") {
    return "";
  }
  const delta = Math.floor(nowMs / 1000) - seconds;
  if (delta < 5) {
    return "Now";
  }
  return span(delta) + " ago";
}

export function recentAgo(seconds, nowMs) {
  if (typeof seconds !== "number" || !Number.isFinite(seconds)) {
    return "";
  }
  const delta = Math.floor(nowMs / 1000) - seconds;
  if (delta < 60) {
    return "just now";
  }
  if (delta < 3600) {
    return Math.floor(delta / 60) + " min ago";
  }
  if (delta < 86400) {
    return Math.floor(delta / 3600) + " h ago";
  }
  if (delta < 172800) {
    return "yesterday";
  }
  return Math.floor(delta / 86400) + " days ago";
}

export function bytes(count) {
  if (typeof count !== "number" || !Number.isFinite(count) || count < 0) {
    return "";
  }
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let value = count;
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  const text = index === 0 ? String(value) : value.toFixed(value >= 10 ? 0 : 1);
  return text + " " + units[index];
}

export function parseUtcInput(value) {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/.exec(value);
  if (!match) {
    return null;
  }
  const [, year, month, day, hour, minute] = match.map(Number);
  const millis = Date.UTC(year, month - 1, day, hour, minute);
  return Number.isNaN(millis) ? null : Math.floor(millis / 1000);
}

export function rfc3339(seconds) {
  const date = new Date(seconds * 1000);
  return (
    date.getUTCFullYear() + "-" + pad(date.getUTCMonth() + 1) + "-" + pad(date.getUTCDate()) + "T" +
    pad(date.getUTCHours()) + ":" + pad(date.getUTCMinutes()) + ":" + pad(date.getUTCSeconds()) + "Z"
  );
}

export function inputValueFromSeconds(seconds) {
  return rfc3339(seconds).slice(0, 16);
}

export function plural(count, one, many) {
  return count + " " + (count === 1 ? one : many);
}
