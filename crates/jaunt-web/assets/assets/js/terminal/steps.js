export const STAGE_ORDER = ["ticket", "node", "account", "shell"];

export function openingSteps({ withAccount, current }) {
  const ids = withAccount ? STAGE_ORDER : STAGE_ORDER.filter((id) => id !== "account");
  const position = Math.max(0, ids.indexOf(current));
  return ids.map((id, index) => ({ id, done: index < position, current: index === position }));
}
