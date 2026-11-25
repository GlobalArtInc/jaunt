import { spawnSync } from "node:child_process";
import { cp, mkdir, mkdtemp, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const WEB_TESTS = fileURLToPath(new URL("..", import.meta.url));
const REPO = join(WEB_TESTS, "..");
const REF = process.env.BEFORE_REF || "HEAD";
const OUT = join(WEB_TESTS, "screenshots-out", "before");

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { maxBuffer: 256 * 1024 * 1024, ...options });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed: ${String(result.stderr || result.error || "")}`);
  }
  return result;
}

const scratch = await mkdtemp(join(tmpdir(), "jaunt-before-"));
try {
  const archive = run("git", ["-C", REPO, "archive", "--format=tar", REF, "--", "crates/jaunt-web/assets", "web-tests/smoke", "web-tests/fixtures.mjs", "web-tests/package.json"]);
  run("tar", ["-x", "-C", scratch], { input: archive.stdout });
  await symlink(join(WEB_TESTS, "node_modules"), join(scratch, "web-tests", "node_modules"));
  const smoke = spawnSync(process.execPath, ["smoke/run.mjs"], { cwd: join(scratch, "web-tests"), stdio: "inherit", env: { ...process.env, SCREENSHOT_DIR: "", JAUNT_ASSETS: "" } });
  await rm(OUT, { recursive: true, force: true });
  await mkdir(OUT, { recursive: true });
  await cp(join(scratch, "web-tests", "screenshots-out"), OUT, { recursive: true });
  console.log(`screenshots of ${REF} written to ${OUT}`);
  process.exitCode = smoke.status === 0 ? 0 : 1;
} finally {
  await rm(scratch, { recursive: true, force: true });
}
