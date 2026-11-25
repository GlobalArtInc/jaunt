const ESC = "\u001b";
const HEADER = { version: 2, width: 80, height: 24, timestamp: 1700000000, env: { SHELL: "/bin/bash", TERM: "xterm-256color" } };

function builder() {
  const events = [];
  let time = 0;
  return {
    out(delay, text) {
      time += delay;
      events.push([Number(time.toFixed(3)), "o", text]);
    },
    typed(delay, text) {
      time += delay;
      events.push([Number(time.toFixed(3)), "i", text]);
    },
    resize(delay, size) {
      time += delay;
      events.push([Number(time.toFixed(3)), "r", size]);
    },
    mark(delay, label) {
      time += delay;
      events.push([Number(time.toFixed(3)), "m", label]);
    },
    done: (header = HEADER) => Buffer.from([JSON.stringify(header), ...events.map((event) => JSON.stringify(event))].join("\n") + "\n"),
  };
}

export function richCast() {
  const cast = builder();
  cast.out(0.3, `${ESC}[1;32malice@web-01${ESC}[0m:${ESC}[1;34m~${ESC}[0m$ `);
  for (const char of "ls -la\r") {
    cast.typed(0.12, char);
  }
  cast.out(0.05, "ls -la\r\n");
  cast.out(0.2, `total 24\r\n${ESC}[1;34mdrwxr-xr-x${ESC}[0m  4 alice alice 4096 Nov 24 10:12 ${ESC}[1;34m.${ESC}[0m\r\n`);
  cast.out(0.05, `-rw-r--r--  1 alice alice  220 Nov 24 10:12 ${ESC}[32m.bash_logout${ESC}[0m\r\n`);
  cast.out(0.05, `-rwxr-xr-x  1 alice alice 1810 Nov 24 10:14 ${ESC}[1;32mdeploy.sh${ESC}[0m\r\n`);
  cast.mark(0.1, "listing done");
  cast.out(0.2, `${ESC}[1;32malice@web-01${ESC}[0m:${ESC}[1;34m~${ESC}[0m$ ./deploy.sh\r\n`);
  for (let step = 0; step <= 10; step += 1) {
    cast.out(0.15, `\r${ESC}[33m[${"#".repeat(step).padEnd(10, ".")}]${ESC}[0m ${String(step * 10).padStart(3)}%`);
  }
  cast.out(0.2, `\r\n${ESC}[2mwaiting for the rollout (long pause)${ESC}[0m\r\n`);
  cast.out(95, `${ESC}[1;31mERROR${ESC}[0m health check failed on ${ESC}[4mweb-02${ESC}[0m\r\n`);
  cast.resize(0.5, "100x30");
  cast.out(0.2, `${ESC}[38;5;208mcolour 208${ESC}[0m ${ESC}[48;2;30;60;120m truecolor ${ESC}[0m ${ESC}[7m reverse ${ESC}[0m\r\n`);
  cast.out(0.2, "box: ┌───┐ wide: 日本語 café ✓\r\n");
  cast.out(0.3, `${ESC}[2J${ESC}[H${ESC}[1;32malice@web-01${ESC}[0m:${ESC}[1;34m~${ESC}[0m$ exit\r\n`);
  return cast.done();
}

export function hostileCast() {
  const cast = builder();
  cast.out(0.1, "start\r\n");
  cast.out(0.1, `${ESC}]0;pwned-title\u0007${ESC}]2;pwned-title\u0007${ESC}]1;pwned-icon\u0007`);
  cast.out(0.1, `${ESC}]52;c;cHduZWQ=\u0007${ESC}]52;p;cHduZWQ=${ESC}\\`);
  cast.out(0.1, `${ESC}]8;;javascript:window.__pwned=1${ESC}\\click-me${ESC}]8;;${ESC}\\ ${ESC}]8;;https://evil.example/x${ESC}\\evil-link${ESC}]8;;${ESC}\\\r\n`);
  cast.out(0.1, `\u009d0;c1-title\u009c\u009d52;c;cHduZWQ=\u009c\u0090$qm${ESC}\\\r\n`);
  cast.out(0.1, `${ESC}[c${ESC}[>c${ESC}[6n${ESC}[?6n${ESC}[5n${ESC}Z${ESC}[18t${ESC}[8;50;200t${ESC}[22;0t${ESC}[1;1;1;1;1T\r\n`);
  cast.out(0.1, `${ESC}P1000p${ESC}\\${ESC}_apc payload${ESC}\\${ESC}^pm payload${ESC}\\${ESC}Xsos payload${ESC}\\\r\n`);
  cast.out(0.1, "<img src=x onerror=window.__pwned=1> <script>window.__pwned=1</script> \"><svg onload=window.__pwned=1>\r\n");
  cast.out(0.1, `${ESC}[?1049h${ESC}[2J${ESC}[?1000h${ESC}[?1006h${ESC}[?2004h${ESC}[?25l\u0007\u0007\u0007\r\n`);
  cast.out(0.1, "\u0000\u0001\u0002\u0003\u0004\u0005\u0006\u000e\u000f\u0018\u001a\u007f\r\n");
  cast.out(0.1, `${ESC}[999999999;999999999H${ESC}[999999999A${ESC}[999999999@${ESC}[999999999X${ESC}[999999999b${ESC}[0;1;2;3;4;5;6;7;8;9;10;11;12;13;14;15;16;17;18;19;20;21;22;23;24;25;26;27;28;29;30;31;32;33;34;35;36;37;38;39;40m\r\n`);
  for (const [letter, final] of [["a", "b"], ["b", "L"], ["c", "M"], ["d", "S"], ["e", "T"], ["f", "Z"], ["g", "I"], ["h", "^"], ["i", "@"], ["j", "P"], ["k", "X"]]) {
    cast.out(0.05, `${letter}${ESC}[999999999${final}${ESC}[2147483647${final}\r\n`);
  }
  const marks = Array.from({ length: 63 }, (_, offset) => String.fromCodePoint(0x300 + offset)).join("");
  cast.out(0.05, "e" + marks.slice(0, 21));
  cast.out(0.05, marks.slice(21, 42));
  cast.out(0.05, marks.slice(42) + "\r\n");
  cast.out(0.1, "\u007f".repeat(65536));
  cast.out(0.1, ("x" + ESC + "[5000S").repeat(500));
  cast.out(0.1, ("x" + ["S", "T", "L", "M", "Z", "b"].map((final) => ESC + "[5000" + final).join("")).repeat(2000));
  cast.out(0.1, `${"A".repeat(300000)}\r\n`);
  cast.out(0.1, `${ESC}]0;${"T".repeat(200000)}\u0007${ESC}]52;c;${"Zm9v".repeat(50000)}\u0007`);
  cast.out(0.1, `${ESC}[?1049l${ESC}[?25h${ESC}[?1000l${ESC}[?1006l${ESC}[?2004l${ESC}[0m\r\nend of hostile output\r\n`);
  cast.typed(0.1, `${ESC}]52;c;c2VjcmV0${"\u0007"}typed`);
  return Buffer.concat([cast.done(), Buffer.from("garbage line\n[1,2\n\xff\xfe invalid utf8\n", "latin1")]);
}

export function incompleteCast() {
  const cast = builder();
  cast.out(0.2, "a recording that stops half way\r\n");
  cast.out(1, "last line before the cut");
  return cast.done();
}
