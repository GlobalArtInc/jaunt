import assert from "node:assert/strict";
import { test } from "node:test";

import { createTabs } from "../../crates/jaunt-web/assets/assets/js/terminal/tabs.js";
import { latencyBand, latencyBars, latencyTotal } from "../../crates/jaunt-web/assets/assets/js/terminal/latency.js";
import { openingSteps } from "../../crates/jaunt-web/assets/assets/js/terminal/steps.js";

function filled(max, count) {
  const tabs = createTabs({ max });
  for (let index = 0; index < count; index += 1) {
    tabs.add({ id: "t" + index });
  }
  return tabs;
}

test("adding a tab makes it active and the limit refuses the next one without changing anything", () => {
  const tabs = filled(3, 3);
  assert.equal(tabs.activeId(), "t2");
  assert.equal(tabs.atLimit(), true);
  assert.equal(tabs.add({ id: "extra" }), false);
  assert.deepEqual(tabs.items().map((item) => item.id), ["t0", "t1", "t2"]);
  assert.equal(tabs.activeId(), "t2");
});

test("without a known limit nothing is refused", () => {
  const tabs = filled(null, 30);
  assert.equal(tabs.atLimit(), false);
  assert.equal(tabs.count(), 30);
});

test("stepping wraps around in both directions and does nothing for an empty strip", () => {
  const tabs = filled(4, 3);
  tabs.activate("t0");
  assert.equal(tabs.step(-1), "t2");
  assert.equal(tabs.step(1), "t0");
  assert.equal(tabs.step(1), "t1");
  assert.equal(createTabs({ max: 4 }).step(1), null);
});

test("closing the active tab picks its right neighbour, or the left one at the end, and closing another keeps the active one", () => {
  let tabs = filled(5, 4);
  tabs.activate("t1");
  assert.equal(tabs.close("t1").next, "t2");
  tabs = filled(5, 3);
  assert.equal(tabs.close("t2").next, "t1");
  tabs = filled(5, 3);
  tabs.activate("t0");
  assert.equal(tabs.close("t2").next, "t0");
  tabs = filled(5, 1);
  assert.equal(tabs.close("t0").next, null);
  assert.equal(tabs.count(), 0);
  assert.equal(tabs.close("missing"), null);
});

test("tabs can be selected by a test, and the ids of the ended ones are listed", () => {
  const tabs = filled(5, 4);
  tabs.items()[1].ended = true;
  tabs.items()[3].ended = true;
  assert.deepEqual(tabs.idsWhere((item) => item.ended === true), ["t1", "t3"]);
  assert.equal(tabs.activate("nope"), false);
});

test("latency bands change above 150 and above 400 milliseconds", () => {
  const cases = [[0, "good"], [150, "good"], [151, "slow"], [400, "slow"], [401, "poor"], [5000, "poor"]];
  for (const [ms, band] of cases) {
    assert.equal(latencyBand(ms), band, String(ms));
  }
  assert.deepEqual(["good", "slow", "poor"].map(latencyBars), [3, 2, 1]);
});

test("the header latency adds the node leg when it is known and is the browser leg alone otherwise", () => {
  assert.equal(latencyTotal(18, 24), 42);
  assert.equal(latencyTotal(18, null), 18);
  assert.equal(latencyTotal(18, undefined), 18);
});

test("the opening steps follow the stage and gain the account step only when it is announced", () => {
  const ids = (steps) => steps.map((step) => step.id + (step.done ? ":done" : "") + (step.current ? ":now" : ""));
  assert.deepEqual(ids(openingSteps({ withAccount: false, current: "ticket" })), ["ticket:now", "node", "shell"]);
  assert.deepEqual(ids(openingSteps({ withAccount: false, current: "node" })), ["ticket:done", "node:now", "shell"]);
  assert.deepEqual(ids(openingSteps({ withAccount: true, current: "account" })), ["ticket:done", "node:done", "account:now", "shell"]);
  assert.deepEqual(ids(openingSteps({ withAccount: true, current: "shell" })), ["ticket:done", "node:done", "account:done", "shell:now"]);
});
