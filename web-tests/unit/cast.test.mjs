import assert from "node:assert/strict";
import { test } from "node:test";

import { CAST_LIMITS, CastError, CastParser, parseCastBytes, readCast } from "../../crates/jaunt-web/assets/assets/js/recording/cast.js";

const encoder = new TextEncoder();
const HEADER = '{"version":2,"width":100,"height":30,"timestamp":1700000000,"env":{"SHELL":"/bin/bash"}}';

function bytesOf(...lines) {
  return encoder.encode(lines.join("\n") + "\n");
}

function parseInChunks(bytes, size, limits) {
  const parser = new CastParser(limits);
  for (let offset = 0; offset < bytes.length; offset += size) {
    parser.push(bytes.subarray(offset, offset + size));
  }
  return parser.finish();
}

test("a well-formed cast gives the header, the events in order and the duration", () => {
  const cast = parseCastBytes(bytesOf(HEADER, '[0.5,"o","hello"]', '[1.25,"i","ls\\r"]', '[2,"r","120x40"]', '[3,"o","bye"]'));
  assert.deepEqual(cast.header, { version: 2, cols: 100, rows: 30 });
  assert.deepEqual(cast.times, [0.5, 1.25, 2, 3]);
  assert.deepEqual(cast.codes, ["o", "i", "r", "o"]);
  assert.deepEqual(cast.data, ["hello", "ls\r", "120x40", "bye"]);
  assert.equal(cast.duration, 3);
  assert.equal(cast.hasInput, true);
  assert.equal(cast.skipped, 0);
});

test("chunk boundaries inside a line or a multi-byte character change nothing", () => {
  const bytes = bytesOf(HEADER, '[0.1,"o","héllo wörld ✓ 𝄞"]', '[0.2,"o","second"]');
  const whole = parseCastBytes(bytes);
  for (const size of [1, 2, 3, 7, 64]) {
    assert.deepEqual(parseInChunks(bytes, size).data, whole.data, String(size));
  }
  assert.equal(whole.data[0], "héllo wörld ✓ 𝄞");
});

test("malformed lines are skipped and counted and never stop the rest", () => {
  const bad = [
    "not json",
    "[1,2",
    '{"a":1}',
    '[1,"o"]',
    '["1","o","x"]',
    '[-1,"o","x"]',
    '[1e999,"o","x"]',
    '[99999999999,"o","x"]',
    '[1,"o",5]',
    '[1,5,"x"]',
    '[1,"r","0x10"]',
    '[1,"r","axb"]',
    '[1,"r","12345x10"]',
    "null",
    '"text"',
  ];
  const cast = parseCastBytes(bytesOf(HEADER, '[0.1,"o","a"]', ...bad, '[0.2,"o","b"]'));
  assert.deepEqual(cast.data, ["a", "b"]);
  assert.equal(cast.skipped, bad.length);
});

test("markers and unknown event codes are ignored without counting as damage", () => {
  const cast = parseCastBytes(bytesOf(HEADER, '[0.1,"m","mark"]', '[0.2,"x","0"]', '[0.3,"o","a"]'));
  assert.deepEqual(cast.data, ["a"]);
  assert.equal(cast.ignored, 2);
  assert.equal(cast.skipped, 0);
});

test("times never run backwards and a resize is clamped to the screen limits", () => {
  const cast = parseCastBytes(bytesOf(HEADER, '[5,"o","a"]', '[2,"o","b"]', '[6,"r","9999x9999"]'));
  assert.deepEqual(cast.times, [5, 5, 6]);
  assert.equal(cast.data[2], "500x200");
});

test("an over-long line is dropped whole, counted once, even when it spans many chunks", () => {
  const limits = { ...CAST_LIMITS, maxLineChars: 200 };
  const giant = '[0.2,"o","' + "A".repeat(5000) + '"]';
  const bytes = bytesOf(HEADER, '[0.1,"o","a"]', giant, '[0.3,"o","b"]');
  for (const size of [1, 13, 4096, 1 << 20]) {
    const cast = parseInChunks(bytes, size, limits);
    assert.deepEqual(cast.data, ["a", "b"], String(size));
    assert.equal(cast.skipped, 1, String(size));
  }
  const unterminated = encoder.encode(HEADER + '\n[0.1,"o","a"]\n[0.2,"o","' + "B".repeat(5000));
  const tail = parseInChunks(unterminated, 100, limits);
  assert.deepEqual(tail.data, ["a"]);
  assert.equal(tail.skipped, 1);
});

test("invalid UTF-8 and lone surrogates become replacement characters", () => {
  const prefix = encoder.encode(HEADER + '\n[0.1,"o","ok ');
  const suffix = encoder.encode(' end"]\n[0.2,"o","\\ud800 lone"]\n');
  const bytes = new Uint8Array([...prefix, 0xff, 0xfe, 0xc3, 0x28, ...suffix]);
  const cast = parseCastBytes(bytes);
  assert.equal(cast.data[0], "ok ���( end");
  assert.equal(cast.data[1], "� lone");
  assert.equal(cast.data[1].isWellFormed(), true);
});

test("control characters and escape sequences stay inert data inside the event strings", () => {
  const hostile = "\u001b]0;pwned\u0007\u001b]52;c;aGk=\u0007\u001b]8;;javascript:alert(1)\u001b\\x\u001b]8;;\u001b\\\u009d0;title\u009c\u0000\u0007";
  const cast = parseCastBytes(bytesOf(HEADER, JSON.stringify([0.1, "o", hostile])));
  assert.equal(cast.data[0], hostile);
  assert.equal(cast.count, 1);
});

test("a bad header makes the cast unplayable with a typed error, never another exception", () => {
  const nested = "[".repeat(30000) + "]".repeat(30000);
  const cases = [
    "",
    "not json",
    "[]",
    "null",
    '{"version":1,"width":80,"height":24}',
    '{"width":80,"height":24}',
    '{"version":2,"pad":"' + "x".repeat(70000) + '"}',
  ];
  for (const header of cases) {
    assert.throws(() => parseCastBytes(bytesOf(header, '[0.1,"o","a"]')), (error) => error instanceof CastError && error.code === "bad_header", header.slice(0, 30));
  }
  assert.throws(() => new CastParser().finish(), (error) => error.code === "bad_header");
  const cast = parseCastBytes(bytesOf('{"version":2,"width":80,"height":24,"env":' + nested + "}", '[0.1,"o","a"]'));
  assert.deepEqual(cast.header, { version: 2, cols: 80, rows: 24 });
});

test("header sizes are clamped or defaulted and a deeply nested event line is skipped", () => {
  const huge = parseCastBytes(bytesOf('{"version":2,"width":100000,"height":100000}'));
  assert.deepEqual(huge.header, { version: 2, cols: 500, rows: 200 });
  const odd = parseCastBytes(bytesOf('{"version":2,"width":-5,"height":"x"}'));
  assert.deepEqual(odd.header, { version: 2, cols: 80, rows: 24 });
  const deep = parseCastBytes(bytesOf(HEADER, '[0.1,"o",' + "[".repeat(40000) + "]".repeat(40000) + "]"));
  assert.equal(deep.count, 0);
  assert.equal(deep.skipped, 1);
});

test("a million events within the size cap parse in bounded passes", () => {
  const lines = HEADER + "\n" + '[0.001,"o","x"]\n'.repeat(1_000_000);
  const bytes = encoder.encode(lines);
  assert.ok(bytes.length < CAST_LIMITS.maxBytes);
  const started = Date.now();
  const cast = parseInChunks(bytes, 64 * 1024);
  assert.equal(cast.count, 1_000_000);
  assert.equal(cast.skipped, 0);
  assert.ok(Date.now() - started < 20_000);
});

test("the byte cap and the event cap stop the parse with a typed error", () => {
  const small = { ...CAST_LIMITS, maxBytes: 100 };
  assert.throws(() => parseCastBytes(bytesOf(HEADER, '[0.1,"o","' + "a".repeat(200) + '"]'), small), (error) => error.code === "too_large");
  const few = { ...CAST_LIMITS, maxEvents: 3 };
  assert.throws(() => parseCastBytes(bytesOf(HEADER, ...Array.from({ length: 5 }, () => '[0.1,"o","a"]')), few), (error) => error.code === "too_large");
});

test("reading a stream stops and cancels it on an error or an abort", async () => {
  let cancelled = false;
  let sent = 0;
  const make = (chunks) =>
    new ReadableStream({
      pull(controller) {
        sent += 1;
        controller.enqueue(chunks[(sent - 1) % chunks.length]);
      },
      cancel() {
        cancelled = true;
      },
    });
  const limits = { ...CAST_LIMITS, maxBytes: 1000 };
  await assert.rejects(readCast(make([bytesOf(HEADER), encoder.encode('[0.1,"o","' + "z".repeat(400) + '"]\n')]), { limits }), (error) => error.code === "too_large");
  assert.equal(cancelled, true);

  const controller = new AbortController();
  controller.abort();
  cancelled = false;
  await assert.rejects(readCast(make([bytesOf(HEADER)]), { signal: controller.signal }), (error) => error.code === "aborted");
  assert.equal(cancelled, true);
});

test("the delete character is dropped from output, where it does nothing, and kept in typed input", () => {
  const cast = parseCastBytes(bytesOf(HEADER, '[0.1,"o","a\\u007fb"]', '[0.2,"i","x\\u007f"]'));
  assert.deepEqual(cast.data, ["ab", "x\u007f"]);
});
