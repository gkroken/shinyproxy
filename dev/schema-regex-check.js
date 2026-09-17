// Cross-checks every pattern in the released schemas against a second regex engine.
//
// The server will validate with networknt on java.util.regex; JSON Schema specifies
// ECMA-262. Neither treats `$` as end-of-input -- both match it before a final newline --
// which is how a 65-character SHA-256 once passed the manifest schema (finding dd46cac-F2).
// One implementation agreeing with itself says nothing about the other, so the anchors are
// exercised here in Node as well as in Python.
//
// Run through dev/validate-manifests.sh.

const fs = require("fs");

const manifest = JSON.parse(fs.readFileSync("schemas/manifest.schema.json", "utf8"));
const descriptor = JSON.parse(fs.readFileSync("schemas/output-descriptor/v1.schema.json", "utf8"));
const images = JSON.parse(fs.readFileSync("spec/image-references-v1.json", "utf8"));

// [label, pattern, a value that must be accepted]
const cases = [
  ["manifest.sha256",      manifest.properties.files.items.properties.sha256.pattern, "a".repeat(64)],
  ["manifest.version",     manifest.properties.runtime.properties.version.pattern,    "4.4.1"],
  ["manifest.entrypoint",  manifest.properties.entrypoint.pattern,                    "app.py"],
  ["manifest.path",        manifest.$defs.payloadPath.pattern,                        "src/app.py"],
  ["descriptor.uuid",      descriptor.$defs.uuid.pattern,                             "11111111-1111-4111-8111-111111111111"],
  ["descriptor.path",      descriptor.$defs.renditionPath.pattern,                    "assets/logo.png"],
  ["descriptor.created",   descriptor.properties.created_at.pattern,                  "2026-09-17T17:20:31Z"],
  ["descriptor.media",     descriptor.properties.files.items.properties.media_type.pattern, "text/html"],
  ["image.tag",            images.tag.pattern,             "build-22222222-2222-4222-8222-222222222222"],
  ["image.repository",     images.repository.pattern,      "skald/content/11111111-1111-4111-8111-111111111111"],
  ["image.execution",      images.execution_reference.pattern,
     "registry.internal:5000/skald/content/11111111-1111-4111-8111-111111111111@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
];

// Suffixes that must never be tolerated. CR and CRLF matter as much as LF: a value arriving
// from a Windows-authored file carries them, and `$` is not the only lenient anchor.
const suffixes = [
  ["LF",    "\n"],
  ["CR",    "\r"],
  ["CRLF",  "\r\n"],
  ["LF+x",  "\nx"],
];

let ok = true;

for (const [name, pattern, good] of cases) {
  const re = new RegExp(pattern);
  const positive = re.test(good);
  const rejected = suffixes.filter(([, s]) => !re.test(good + s)).map(([label]) => label);
  const pass = positive && rejected.length === suffixes.length;
  if (!pass) ok = false;
  // Plain concatenation: console.log understands %s but not printf padding such as %-16s,
  // and a half-substituted line claiming a passing anchor failed is worse than no line.
  console.log("  " + (pass ? "ok  " : "FAIL") + " " + name.padEnd(20) +
    " accepts-valid=" + positive + " rejects=[" + rejected.join(",") + "]");
}

console.log("");
console.log("RESULT:", ok ? "anchors hold in ECMA-262 as well" : "MISMATCH");
process.exit(ok ? 0 : 1);
