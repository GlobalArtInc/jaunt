# Web console tests

Dev-only. Nothing here is embedded in the binary or part of the Rust workspace.

    cd web-tests
    npm ci
    npm test
    npx playwright install chromium
    npm run smoke

`npm test` runs the DOM tests (node:test and jsdom) against the real modules in `crates/jaunt-web/assets`.

`npm run smoke` starts an API stub that serves the embedded assets with the daemon's CSP, then drives Chromium at 380 px and 1440 px in the light and dark themes. It checks horizontal overflow, minimum font sizes, rendered text contrast, token contrast, focus rings, dialog focus and CSP violations, and writes screenshots to `screenshots-out/` (git-ignored).

`npm run smoke:recording` drives the recording player in Chromium against the same stub at 380 px and 1440 px in both themes: it plays a recorded cast and a hostile one, checks layout, keyboard control, minimum font sizes, contrast, the content security policy and the requests the page makes, and writes screenshots to `screenshots-out/`. The stub serves generated casts from `smoke/casts.mjs`; a recording from a real node is not used.

`npm run smoke:csi` feeds the real terminal adapter every CSI sequence from final byte `@` to `~`, with and without the `?`, `>`, `<`, `=` markers and each intermediate byte, with first parameters of 999999999 and 2147483647, one sequence at a time after a printable character, and fails if any of them keeps the main thread busy for 500 ms or more. It takes a few minutes. `CSI_SWEEP_FINALS=Lb` narrows it to some final bytes and `CSI_SWEEP_GUARD_MS` changes the hang guard.

