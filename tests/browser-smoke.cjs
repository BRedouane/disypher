const fs = require("fs");
const vm = require("vm");
global.window = global;
vm.runInThisContext(fs.readFileSync("browser-data.js", "utf8"), { filename: "browser-data.js" });
vm.runInThisContext(fs.readFileSync("browser-engine.js", "utf8"), { filename: "browser-engine.js" });
console.log(JSON.stringify(DisypherEngine.selfTest()));
