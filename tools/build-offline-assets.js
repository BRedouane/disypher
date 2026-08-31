const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const inputs = [
  ["vendor/pyodide/pyodide.asm.wasm", "application/wasm"],
  ["vendor/pyodide/python_stdlib.zip", "application/zip"],
  ["vendor/pyodide/pyodide-lock.json", "application/json"],
  ["disypher/__init__.py", "text/x-python"],
  ["disypher/banks/es.json", "application/json"],
  ["disypher/banks/de.json", "application/json"],
  ["disypher/banks/it.json", "application/json"],
  ["disypher/banks/universal.json", "application/json"],
];

const records = inputs.map(([name, type]) => {
  const data = fs.readFileSync(path.join(root, name)).toString("base64");
  return `${JSON.stringify(name)}:{type:${JSON.stringify(type)},data:${JSON.stringify(data)}}`;
});

const output = `(function(){\nconst assets={${records.join(",")}};\n` +
`if(location.protocol!=="file:")return;\n` +
`const original=window.fetch.bind(window);\n` +
`window.fetch=function(input,init){const raw=typeof input==="string"?input:input.url;let pathname;try{pathname=decodeURIComponent(new URL(raw,location.href).pathname).replace(/\\\\/g,"/")}catch(error){return original(input,init)}const key=Object.keys(assets).find(name=>pathname.endsWith("/"+name)||pathname.endsWith(name));if(!key)return original(input,init);const asset=assets[key],binary=atob(asset.data),bytes=new Uint8Array(binary.length);for(let i=0;i<binary.length;i++)bytes[i]=binary.charCodeAt(i);return Promise.resolve(new Response(bytes,{status:200,headers:{"Content-Type":asset.type,"Content-Length":String(bytes.length)}}))};\n` +
`window.DISYPHER_OFFLINE_ASSETS=true;\n})();\n`;

fs.writeFileSync(path.join(root, "offline-assets.js"), output);
console.log(`offline-assets.js: ${Buffer.byteLength(output).toLocaleString()} bytes`);
