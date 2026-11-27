import assert from "node:assert/strict";
import { test } from "node:test";

import { installDom } from "./support.mjs";

const JS = "../../crates/jaunt-web/assets/assets/js/";

function fakeApi(replies) {
  const calls = [];
  return {
    calls,
    async get(path) {
      calls.push(path);
      const reply = replies[path];
      if (reply instanceof Error) {
        throw reply;
      }
      if (reply === undefined) {
        throw Object.assign(new Error("missing"), { status: 404 });
      }
      return reply;
    },
  };
}

test("the command is built only from a dns-label node, a dns suffix and a plain login", async () => {
  installDom();
  const { createConnectInfo } = await import(JS + "connect.js");
  const info = createConnectInfo(fakeApi({ "/v1/client-config": { ssh_suffix: "jaunt.example.com" } }));
  assert.equal(info.command("web-01"), null);
  await info.load();
  assert.equal(info.command("web-01"), "ssh YOUR_LOGIN@web-01.jaunt.example.com");
  assert.equal(info.command("web-01", "deploy"), "ssh deploy@web-01.jaunt.example.com");
  for (const bad of ["Web", "a b", "a;b", "-a", "a_b", "", "a.b", "$(id)", "a\nb"]) {
    assert.equal(info.command(bad), null, bad);
  }
  for (const login of ["a b", "x;y", "$(id)", "", "-rf", "a\nb", "a".repeat(65)]) {
    assert.equal(info.command("web-01", login), null, JSON.stringify(login));
  }
});

test("an unsafe suffix from the server disables the command", async () => {
  installDom();
  const { createConnectInfo } = await import(JS + "connect.js");
  for (const suffix of ["bad suffix", "x;y.com", "UPPER.com", "a..b", 7, null]) {
    const info = createConnectInfo(fakeApi({ "/v1/client-config": { ssh_suffix: suffix } }));
    await info.load();
    assert.equal(info.command("web-01"), null, String(suffix));
  }
});

test("targets keep only safe logins, ignore malformed entries and are absent when the endpoint is missing", async () => {
  installDom();
  const { createConnectInfo } = await import(JS + "connect.js");
  const info = createConnectInfo(fakeApi({ "/v1/web/terminal/targets": [{ node: "a", logins: ["ok", "no way", 5] }, { node: 3, logins: [] }, null, { node: "b" }] }));
  await info.load();
  assert.equal(info.hasTargets(), true);
  assert.deepEqual(info.loginsFor("a"), ["ok"]);
  assert.equal(info.loginsFor("b"), null);
  const none = createConnectInfo(fakeApi({}));
  await none.load();
  assert.equal(none.hasTargets(), false);
  assert.equal(none.loginsFor("a"), null);
  const odd = createConnectInfo(fakeApi({ "/v1/web/terminal/targets": { not: "a list" } }));
  await odd.load();
  assert.equal(odd.hasTargets(), false);
});

test("the information is requested once, and a network failure is retried on the next load", async () => {
  installDom();
  const { createConnectInfo } = await import(JS + "connect.js");
  const api = fakeApi({ "/v1/client-config": { ssh_suffix: "a.example" } });
  const info = createConnectInfo(api);
  await Promise.all([info.load(), info.load()]);
  await info.load();
  assert.equal(api.calls.filter((path) => path === "/v1/client-config").length, 1);
  const down = fakeApi({ "/v1/client-config": Object.assign(new Error("down"), { status: 0 }), "/v1/web/terminal/targets": Object.assign(new Error("down"), { status: 0 }) });
  const flaky = createConnectInfo(down);
  await flaky.load();
  await flaky.load();
  assert.equal(down.calls.filter((path) => path === "/v1/client-config").length, 2);
});

test("reset forgets the suffix and the targets so the next user gets fresh information", async () => {
  installDom();
  const { createConnectInfo } = await import(JS + "connect.js");
  const replies = { "/v1/client-config": { ssh_suffix: "a.example" }, "/v1/web/terminal/targets": [{ node: "n", logins: ["ann"] }] };
  const api = fakeApi(replies);
  const info = createConnectInfo(api);
  await info.load();
  assert.equal(info.command("n"), "ssh YOUR_LOGIN@n.a.example");
  assert.deepEqual(info.loginsFor("n"), ["ann"]);
  info.reset();
  assert.equal(info.command("n"), null);
  assert.equal(info.hasTargets(), false);
  replies["/v1/client-config"] = { ssh_suffix: "b.example" };
  replies["/v1/web/terminal/targets"] = [{ node: "n", logins: ["bob"] }];
  await info.load();
  assert.equal(info.command("n"), "ssh YOUR_LOGIN@n.b.example");
  assert.deepEqual(info.loginsFor("n"), ["bob"]);
});

test("a pin counts only after the server answered, and its path escapes the node name", async () => {
  installDom();
  const { createConnectInfo } = await import(JS + "connect.js");
  const api = fakeApi({ "/v1/web/terminal/targets": [{ node: "a%b/c", logins: ["ok"], pinned: false }, { node: "plain", logins: ["ok"], pinned: true }] });
  const seen = [];
  let outcome = "refuse";
  api.put = async (path) => {
    seen.push(["PUT", path, info.isPinned("a%b/c")]);
    if (outcome === "refuse") {
      throw Object.assign(new Error("full"), { status: 409 });
    }
  };
  api.del = async (path) => {
    seen.push(["DELETE", path, info.isPinned("plain")]);
    if (outcome === "refuse") {
      throw Object.assign(new Error("down"), { status: 500 });
    }
  };
  const info = createConnectInfo(api);
  await info.load();
  await assert.rejects(info.setPinned("a%b/c", true));
  assert.equal(info.isPinned("a%b/c"), false);
  await assert.rejects(info.setPinned("plain", false));
  assert.equal(info.isPinned("plain"), true);
  outcome = "accept";
  await info.setPinned("a%b/c", true);
  assert.equal(info.isPinned("a%b/c"), true);
  await info.setPinned("plain", false);
  assert.equal(info.isPinned("plain"), false);
  assert.deepEqual(seen.map(([method, path, during]) => [method, path, during]), [
    ["PUT", "/v1/web/pins/a%25b%2Fc", false],
    ["DELETE", "/v1/web/pins/plain", true],
    ["PUT", "/v1/web/pins/a%25b%2Fc", false],
    ["DELETE", "/v1/web/pins/plain", true],
  ]);
});

test("the terminal limits are read only when they are whole numbers in a sensible range", async () => {
  installDom();
  const { readTerminalConfig } = await import(JS + "connect.js");
  assert.deepEqual(readTerminalConfig({ max_per_user: 4, idle_timeout_secs: 1800 }), { maxPerUser: 4, idleTimeoutSecs: 1800 });
  for (const bad of [null, [], "x", { max_per_user: 0, idle_timeout_secs: 0 }, { max_per_user: "4", idle_timeout_secs: "9" }, { max_per_user: 1e9, idle_timeout_secs: 1e12 }, { max_per_user: 1.5 }]) {
    assert.deepEqual(readTerminalConfig(bad), { maxPerUser: null, idleTimeoutSecs: null }, JSON.stringify(bad));
  }
});
