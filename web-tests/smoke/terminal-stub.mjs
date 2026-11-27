import { createHash, randomBytes } from "node:crypto";

const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const SUBPROTOCOL = "jaunt-terminal.v1";
const TICKET_PREFIX = "jaunt-ticket.";
const ESC = "\u001b";
const MAX_FRAME = 65536;

function encodeFrame(opcode, payload) {
  const length = payload.length;
  let header;
  if (length < 126) {
    header = Buffer.from([0x80 | opcode, length]);
  } else if (length < 65536) {
    header = Buffer.from([0x80 | opcode, 126, length >> 8, length & 0xff]);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x80 | opcode;
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(length), 2);
  }
  return Buffer.concat([header, payload]);
}

function takeFrames(state) {
  const frames = [];
  for (;;) {
    const buffer = state.buffer;
    if (buffer.length < 2) {
      break;
    }
    const opcode = buffer[0] & 0x0f;
    const masked = (buffer[1] & 0x80) !== 0;
    let length = buffer[1] & 0x7f;
    let offset = 2;
    if (length === 126) {
      if (buffer.length < 4) break;
      length = buffer.readUInt16BE(2);
      offset = 4;
    } else if (length === 127) {
      if (buffer.length < 10) break;
      length = Number(buffer.readBigUInt64BE(2));
      offset = 10;
    }
    const total = offset + (masked ? 4 : 0) + length;
    if (buffer.length < total) {
      break;
    }
    const payload = Buffer.from(buffer.subarray(offset + (masked ? 4 : 0), total));
    if (masked) {
      const mask = buffer.subarray(offset, offset + 4);
      for (let index = 0; index < payload.length; index += 1) {
        payload[index] ^= mask[index % 4];
      }
    }
    frames.push({ opcode, payload });
    state.buffer = buffer.subarray(total);
  }
  return frames;
}

export function hostileStream() {
  const parts = [];
  parts.push(`start of hostile output\r\n`);
  parts.push(`${ESC}]0;pwned-title\u0007${ESC}]2;pwned-title\u0007${ESC}]1;pwned-icon\u0007`);
  parts.push(`${ESC}]52;c;cHduZWQ=\u0007${ESC}]52;p;cHduZWQ=${ESC}\\${ESC}]52;c;?\u0007`);
  parts.push(`${ESC}]8;;javascript:window.__pwned=1${ESC}\\click-me${ESC}]8;;${ESC}\\ ${ESC}]8;;https://evil.example/x${ESC}\\evil-link${ESC}]8;;${ESC}\\\r\n`);
  parts.push(`${ESC}]10;?\u0007${ESC}]11;?\u0007${ESC}]4;1;?\u0007\r\n`);
  parts.push(`${ESC}P1000p${ESC}\\${ESC}_apc payload${ESC}\\${ESC}^pm payload${ESC}\\${ESC}Xsos payload${ESC}\\\r\n`);
  parts.push(`<img src=x onerror=window.__pwned=1> <script>window.__pwned=1</script> "><svg onload=window.__pwned=1>\r\n`);
  parts.push(`${ESC}[?1049h${ESC}[2J${ESC}[?2004h${ESC}[?25l\u0007\u0007\u0007${ESC}[?25h${ESC}[?2004l${ESC}[?1049l\r\n`);
  parts.push(`${ESC}[999999999;999999999H${ESC}[999999999A${ESC}[999999999@${ESC}[999999999X${ESC}[999999999b\r\n`);
  for (const final of ["b", "L", "M", "S", "T", "Z", "I", "^", "@", "P", "X"]) {
    parts.push(`x${ESC}[999999999${final}${ESC}[2147483647${final}\r\n`);
  }
  parts.push(`${"A".repeat(300000)}\r\n`);
  parts.push(`${ESC}]0;${"T".repeat(200000)}\u0007${ESC}]52;c;${"Zm9v".repeat(50000)}\u0007`);
  parts.push(`${ESC}[0m\r\nend of hostile output\r\n`);
  return Buffer.from(parts.join(""), "utf8");
}

export function queryStream() {
  return Buffer.from(
    [`${ESC}[c`, `${ESC}[>c`, `${ESC}[5n`, `${ESC}[6n`, `${ESC}[?6n`, `${ESC}[?15n`, `${ESC}[18t`, `${ESC}[14t`, `${ESC}[21t`, `${ESC}[?2004$p`, `${ESC}[4$p`, `${ESC}P$qm${ESC}\\`, `${ESC}P$q"p${ESC}\\`, `${ESC}]10;?\u0007`, `${ESC}]11;?\u0007`, `${ESC}]52;c;?\u0007`, `${ESC}Z`, `\r\nend of queries\r\n`].join(""),
    "utf8",
  );
}

export function createTerminalBackend({ origin }) {
  const tickets = new Map();
  const sessions = [];
  const control = { sessions, tickets, denyNext: null, handshakeFailures: [], plan: null };

  function issue(current, input, targets) {
    if (control.denyNext) {
      const reply = control.denyNext;
      control.denyNext = null;
      return reply;
    }
    const node = input && typeof input.node === "string" ? input.node : null;
    const login = input && typeof input.login === "string" ? input.login : null;
    if (node === null || login === null) {
      return { status: 400, body: { error: "invalid_request" } };
    }
    const target = (targets || []).find((entry) => entry.node === node);
    if (!target || !target.logins.includes(login) || !target.connected) {
      return { status: 403, body: { error: "denied" } };
    }
    const ticket = randomBytes(32).toString("base64url");
    tickets.set(ticket, { node, login, session: current, used: false });
    return { status: 200, body: { ticket, expires_in: 30 } };
  }

  function refuse(socket, why) {
    control.handshakeFailures.push(why);
    socket.write("HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    socket.destroy();
  }

  function upgrade(request, socket, sessionOf) {
    const url = new URL(request.url, origin.value);
    if (url.pathname !== "/v1/web/terminal") {
      refuse(socket, "path");
      return;
    }
    if (request.headers.origin !== origin.value) {
      refuse(socket, "origin");
      return;
    }
    const current = sessionOf(request);
    if (!current) {
      refuse(socket, "session");
      return;
    }
    const names = ["node", "login", "cols", "rows"];
    for (const name of names) {
      if (url.searchParams.getAll(name).length !== 1) {
        refuse(socket, "query " + name);
        return;
      }
    }
    const cols = Number(url.searchParams.get("cols"));
    const rows = Number(url.searchParams.get("rows"));
    if (!(cols >= 1 && cols <= 500 && rows >= 1 && rows <= 200)) {
      refuse(socket, "size");
      return;
    }
    const offered = String(request.headers["sec-websocket-protocol"] || "").split(",").map((item) => item.trim());
    const ticketName = offered.find((item) => item.startsWith(TICKET_PREFIX));
    const ticket = ticketName ? tickets.get(ticketName.slice(TICKET_PREFIX.length)) : null;
    if (!offered.includes(SUBPROTOCOL) || !ticket || ticket.used || ticket.session !== current || ticket.node !== url.searchParams.get("node") || ticket.login !== url.searchParams.get("login")) {
      refuse(socket, "ticket");
      return;
    }
    ticket.used = true;
    const key = request.headers["sec-websocket-key"];
    const accept = createHash("sha1").update(key + GUID).digest("base64");
    socket.write(["HTTP/1.1 101 Switching Protocols", "Upgrade: websocket", "Connection: Upgrade", "Sec-WebSocket-Accept: " + accept, "Sec-WebSocket-Protocol: " + SUBPROTOCOL, "", ""].join("\r\n"));
    startSession(socket, { node: ticket.node, login: ticket.login, cols, rows });
  }

  function startSession(socket, query) {
    const record = { query, input: [], resizes: [], pings: 0, closed: null, line: "", escape: null, muted: false, oversized: 0 };
    const state = { buffer: Buffer.alloc(0) };
    const sendText = (message) => socket.write(encodeFrame(1, Buffer.from(JSON.stringify(message))));
    const sendBinary = (bytes) => {
      const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
      for (let offset = 0; offset < buffer.length; offset += MAX_FRAME) {
        socket.write(encodeFrame(2, buffer.subarray(offset, offset + MAX_FRAME)));
      }
    };
    const prompt = () => sendBinary(`${ESC}[1;32m${query.login}@${query.node}${ESC}[0m:~$ `);
    const close = (code, reason = "") => {
      const payload = Buffer.alloc(2 + Buffer.byteLength(reason));
      payload.writeUInt16BE(code, 0);
      payload.write(reason, 2);
      socket.write(encodeFrame(8, payload));
      record.closed = code;
      socket.end();
    };
    Object.assign(record, { sendText, sendBinary, close, alive: true });
    sessions.push(record);
    const plan = control.plan;
    control.plan = null;
    const greet = (fields) => {
      sendText({ t: "ready", session_id: "stub-session-" + sessions.length, ...fields });
      sendBinary(`Connected to ${query.node} as ${query.login}\r\n`);
      prompt();
    };
    if (plan && plan.refuse) {
      sendText({ t: "error", code: plan.refuse.code, ref: plan.refuse.ref });
      close(1008, plan.refuse.code);
    } else if (plan && plan.account) {
      sendText({ t: "progress", stage: "account" });
      record.release = () => greet({ account_created: true, home: plan.account.home });
    } else {
      greet({});
    }

    function sendBypass(kind) {
      const finals = ["L", "S", "T", "M", "Z", "@", "P", "X", "b"];
      const cycle = (open, join) => finals.map((final) => open + join + "4999" + final).join("");
      const frame = (unit) => Buffer.from(unit.repeat(Math.floor(MAX_FRAME / Buffer.byteLength(unit))), "utf8");
      if (kind === "bypassnul") {
        sendBinary(frame(cycle(ESC + "[", "\u0000")));
      } else if (kind === "bypassdel") {
        sendBinary(frame(cycle(ESC + "[", "\u007f")));
      } else if (kind === "bypass8bit") {
        sendBinary(frame(cycle("\u009b", "\u0000")));
      } else if (kind === "bypasssplit") {
        for (let pair = 0; pair < 1500; pair += 1) {
          sendBinary(Buffer.from(ESC + "[" + "\u0000".repeat(70) + "4999"));
          sendBinary(Buffer.from("L"));
        }
      }
      sendBinary(`\r\nend of ${kind}\r\n`);
    }

    function runLine(line) {
      sendBinary("\r\n");
      if (line === "echo hello") {
        sendBinary("hello\r\n");
      } else if (line === "hostile") {
        sendBinary(hostileStream());
      } else if (line === "flood4k") {
        sendBinary(`${"x" + ESC + "[5000S"}`.repeat(500) + "\r\nend of flood4k\r\n");
      } else if (line === "flood86k") {
        sendBinary(("x" + ["S", "T", "L", "M", "Z", "@", "P", "X", "b"].map((final) => ESC + "[5000" + final).join("")).repeat(2000) + "\r\nend of flood86k\r\n");
      } else if (line === "delflood") {
        sendBinary(Buffer.alloc(MAX_FRAME, 0x7f));
        sendBinary("\r\nend of delflood\r\n");
      } else if (line === "marks3") {
        const marks = Array.from({ length: 63 }, (_, offset) => String.fromCodePoint(0x300 + offset)).join("");
        sendBinary(Buffer.from("e" + marks.slice(0, 21), "utf8"));
        sendBinary(Buffer.from(marks.slice(21, 42), "utf8"));
        sendBinary(Buffer.from(marks.slice(42), "utf8"));
        sendBinary("\r\nend of marks3\r\n");
      } else if (line.startsWith("bypass")) {
        sendBypass(line);
      } else if (line === "queryflood") {
        sendBinary(`${ESC}[6n`.repeat(3000) + "\r\nend of queryflood\r\n");
      } else if (line === "bracketed") {
        sendBinary(`${ESC}[?2004h`);
      } else if (line === "queries") {
        sendBinary(queryStream());
      } else if (line === "exit") {
        sendText({ t: "exit", status: 0, signal: null });
        close(1000, "exit");
        return;
      } else if (line !== "") {
        sendBinary(`bash: command not found\r\n`);
      }
      prompt();
    }

    function onInput(bytes) {
      record.input.push(Array.from(bytes));
      for (const byte of bytes) {
        if (record.escape === "start") {
          record.escape = byte === 0x5b || byte === 0x4f ? "sequence" : null;
        } else if (record.escape === "sequence") {
          if (byte >= 0x40 && byte <= 0x7e) {
            record.escape = null;
          }
        } else if (byte === 27) {
          record.escape = "start";
        } else if (byte === 3) {
          record.line = "";
          sendBinary("^C\r\n");
          prompt();
        } else if (byte === 13) {
          const line = record.line;
          record.line = "";
          runLine(line);
        } else if (byte === 127) {
          if (record.line.length > 0) {
            record.line = record.line.slice(0, -1);
            sendBinary("\b \b");
          }
        } else if (byte >= 32 && byte < 127) {
          record.line += String.fromCharCode(byte);
          sendBinary(Buffer.from([byte]));
        }
      }
    }

    socket.on("data", (chunk) => {
      state.buffer = Buffer.concat([state.buffer, chunk]);
      for (const frame of takeFrames(state)) {
        if (frame.opcode === 2) {
          if (frame.payload.length > MAX_FRAME) {
            record.oversized += 1;
            close(1009, "frame too big");
            return;
          }
          onInput(frame.payload);
        } else if (frame.opcode === 1) {
          let message = null;
          try {
            message = JSON.parse(frame.payload.toString("utf8"));
          } catch {
            close(1008, "malformed");
            return;
          }
          if (message.t === "resize") {
            record.resizes.push([message.cols, message.rows]);
          } else if (message.t === "ping") {
            record.pings += 1;
            if (!record.muted) {
              sendText({ t: "pong" });
            }
          }
        } else if (frame.opcode === 8) {
          record.closed = record.closed === null ? 1000 : record.closed;
          record.alive = false;
          socket.end(encodeFrame(8, frame.payload.subarray(0, 2)));
        } else if (frame.opcode === 9) {
          socket.write(encodeFrame(10, frame.payload));
        }
      }
    });
    socket.on("close", () => {
      record.alive = false;
      if (record.closed === null) {
        record.closed = 1006;
      }
    });
    socket.on("error", () => {
      record.alive = false;
    });
  }

  return { issue, upgrade, control };
}
