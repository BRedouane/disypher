const fs = require("fs");
const vm = require("vm");
const assert = require("assert");
global.window = global;
vm.runInThisContext(fs.readFileSync("browser-data.js", "utf8"));
vm.runInThisContext(fs.readFileSync("browser-engine.js", "utf8"));
const ref = JSON.parse(fs.readFileSync("tests/reference.json", "utf8"));
for (const vector of ref.vectors) {
  const actual = DisypherEngine.encode(ref.sample, vector.cipher, vector.params);
  assert.strictEqual(actual, vector.encoded, `${vector.cipher} encoding differs`);
  const stage = DisypherEngine.encodeStages(ref.sample, [{cipher: vector.cipher, params: vector.params}]);
  assert.deepStrictEqual(stage, vector.stages, `${vector.cipher} stage metadata differs`);
}
for (const item of ref.analyses) {
  const actual = DisypherEngine.analyse(item.text, item.only, item.params);
  assert.deepStrictEqual(actual, item.report, `${item.name} analysis differs`);
}
for (const item of ref.banks) {
  DisypherEngine.loadBank(item.code);
  const actual = DisypherEngine.analyse(item.text, ["caesar"]);
  assert.deepStrictEqual(actual, item.report, `${item.code} bank differs`);
}
DisypherEngine.loadBank("universal");
console.log(`Parity OK: ${ref.vectors.length} methods, ${ref.analyses.length} analyses, ${ref.banks.length + 1} banks`);
