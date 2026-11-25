Vendored: xterm.js (npm package @xterm/xterm)

Version:  5.5.0
License:  MIT (LICENSE.txt, copied unchanged from the package)
Source:   https://registry.npmjs.org/@xterm/xterm/-/xterm-5.5.0.tgz
          repository https://github.com/xtermjs/xterm.js
Package:  npm integrity sha512-hqJHYaQb5OptNunnyAnkHyM8aCjZ1MEIDTQu1iIbbTD/xops91NB5yq1ZK/dC2JDbVWtF23zUtl9JE2NqwT87A==
          tarball sha256 bd954fa721872170188cc5d7e83e88db3c83c9a18a4e8d24c2783d26491f59d2

Files, copied byte for byte from the package (no local modification):
  xterm.js   from lib/xterm.js    sha256 1f991ac3b4b283ebf96e60ae23a00a52765dd3a2e46fa6fdda9f1aab032f7495
  xterm.css  from css/xterm.css   sha256 ba8e6985669488981ccf40c0cefe3aba80722cb6c92de7ad628b0bd717faf2b6
  LICENSE.txt from LICENSE        sha256 b569f629d00f2626a8100df2a1798210535621e42164dfd426a6fe5aac7b0ccd

How it is used: the recording player loads xterm.js and xterm.css on demand from this directory (same origin, no network). It is an unmodified UMD script that defines the global Terminal.

Why 5.5.0 and not 6.0.0: version 6 removed the canvas renderer, so it needs WebGL with no fallback; version 5.5.0 with the canvas addon renders with a plain 2D canvas on every browser. Neither version works without the style shim described in js/recording/terminal.js: at open() the library creates style elements, which the console policy (style-src 'self') refuses.

Update procedure: fetch the package with npm pack, verify the integrity above, extract into a new empty directory, copy the files, update this file and the hashes pinned in crates/jaunt-web/src/lib.rs. Never edit the files by hand.
