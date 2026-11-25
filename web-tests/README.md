# Web console tests

Dev-only. Nothing here is embedded in the binary or part of the Rust workspace.

    cd web-tests
    npm ci
    npm test
    npx playwright install chromium
    npm run smoke

`npm test` runs the DOM tests (node:test and jsdom) against the real modules in `crates/jaunt-web/assets`.

`npm run smoke` starts an API stub that serves the embedded assets with the daemon's CSP, then drives Chromium at 380 px and 1440 px in the light and dark themes. It checks horizontal overflow, minimum font sizes, rendered text contrast, token contrast, focus rings, dialog focus and CSP violations, and writes screenshots to `screenshots-out/` (git-ignored).
