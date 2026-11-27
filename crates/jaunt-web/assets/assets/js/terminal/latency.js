export const GOOD_MAX_MS = 150;
export const SLOW_MAX_MS = 400;

export function latencyBand(ms) {
  if (ms <= GOOD_MAX_MS) {
    return "good";
  }
  return ms <= SLOW_MAX_MS ? "slow" : "poor";
}

export function latencyBars(band) {
  return band === "good" ? 3 : band === "slow" ? 2 : 1;
}

export function latencyTotal(clientMs, nodeMs) {
  return clientMs + (nodeMs === null || nodeMs === undefined ? 0 : nodeMs);
}
