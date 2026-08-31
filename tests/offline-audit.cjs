const fs = require("fs");
const path = require("path");
const assert = require("assert");
const html = fs.readFileSync("index.html", "utf8");
const scripts = [...html.matchAll(/<script\s+src="([^"]+)"/g)].map(m => m[1]);
assert.deepStrictEqual(scripts, ["browser-data.js", "browser-engine.js"]);
for (const source of scripts) {
  assert(!/^https?:/i.test(source), `remote script: ${source}`);
  assert(fs.existsSync(path.resolve(source)), `missing script: ${source}`);
}
assert(!/\bfetch\s*\(|XMLHttpRequest|WebSocket|sendBeacon|loadPyodide|pyodide\./.test(html));
assert(!/\bfetch\s*\(|XMLHttpRequest|WebSocket|sendBeacon/.test(fs.readFileSync("browser-engine.js", "utf8")));
console.log("Offline audit OK: direct-file scripts present, no automatic network API");
