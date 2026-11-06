// Regression checks for the viewer's body rendering, run in CI with `node viewer/check.mjs`.
//
// Loads the script from index.html into a VM with a stub DOM, sets up a capture by hand, and
// renders body slots the way a page does. Captured headers and DNS names are Operator bytes: they
// must never reach innerHTML unescaped, and an `identity` coding must read as no coding.

import { readFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import vm from "node:vm";
import assert from "node:assert/strict";

const html = readFileSync(new URL("index.html", import.meta.url), "utf8");
const script = html.slice(html.indexOf("<script>") + 8, html.lastIndexOf("</script>"));

// Any property of the stub is a callable that returns the stub, so top-level wiring runs.
const stub = new Proxy(function () {}, { get: (t, k) => (k === Symbol.toPrimitive ? () => "" : stub), apply: () => stub });
const ctx = vm.createContext({
  document: stub, window: stub, location: { hash: "" }, console,
  TextDecoder, TextEncoder, DecompressionStream, Blob, Response, Uint8Array, Map, Set,
});
vm.runInContext(script, ctx);

const HASH = "f1e20" + "ab".repeat(32);
const JSON_BODY = '{"id":"chatcmpl-1","object":"chat.completion","choices":[]}';

// One exchange whose response body is `wire`, sent with `content_encoding`.
async function render(wire, response) {
  ctx.wire = wire;
  ctx.response = { dir: "resp", content_type: "application/json", body_len: wire.length, body_hash: HASH, ...response };
  vm.runInContext(`
    FILES = new Map([["bodies/${HASH}", { arrayBuffer: async () => wire.buffer.slice(wire.byteOffset, wire.byteOffset + wire.length) }]]);
    D = { bodyRefs: new Map([["${HASH}", [{ http: { flow: "f", exchange: 0, request: {}, response }, dir: "response" }]]]) };
  `, ctx);
  const slot = { dataset: { hash: HASH, ct: "application/json", proto: "" }, innerHTML: "" };
  await ctx.fillBody(slot);
  return slot.innerHTML;
}

const checks = [];
const check = (name, fn) => checks.push([name, fn]);
const XSS = '<img src=x onerror=alert(1)>';

check("a captured Content-Encoding is escaped in the tab label and note", async () => {
  const out = await render(new TextEncoder().encode(JSON_BODY), { content_encoding: XSS, decode_error: "unsupported" });
  assert.ok(!out.includes("<img"), out);
  assert.ok(out.includes("wire (&lt;img src=x onerror=alert(1)&gt;)"), out);
});

check("an HTML-bearing coding the viewer cannot decode stays escaped in the error", async () => {
  const wire = gzipSync(JSON_BODY);
  const out = await render(new Uint8Array(wire), { content_encoding: `gzip, ${XSS}`, decoded_hash: HASH });
  assert.ok(!out.includes("<img"), out);
});

check("identity alone is no coding: the body reads as JSON", async () => {
  for (const coding of ["identity", " Identity ", "identity, identity", ""]) {
    const out = await render(new TextEncoder().encode(JSON_BODY), { content_encoding: coding });
    assert.ok(out.includes(">json</button>"), `${coding}: ${out}`);
    assert.ok(!out.includes("not decoded"), `${coding}: ${out}`);
    assert.ok(!out.includes("wire ("), `${coding}: ${out}`);
  }
});

check("identity tokens are dropped before picking the decoder", async () => {
  const out = await render(new Uint8Array(gzipSync(JSON_BODY)), { content_encoding: "identity, GZIP", decoded_hash: HASH });
  assert.ok(out.includes(">json</button>"), out);
  assert.ok(out.includes("wire (identity, GZIP)"), out);
});

check("the Workunit page's coding note and the exchange's decoded cell escape captured values", async () => {
  ctx.m = { content_encoding: XSS, decode_error: "unsupported", decoded_len: null, decoded_hash: null };
  const note = vm.runInContext(`
    D = { httpByKey: new Map([["f#0", { response: m }]]) };
    codingNote({ flow: "f", exchange: 0 })[1] + decodedCell(m);
  `, ctx);
  assert.ok(!note.includes("<img"), note);
  assert.ok(note.includes("&lt;img"), note);
});

check("a captured DNS name is escaped in the DNS table, the packet's DNS message and the Slice page", () => {
  ctx.dns = { window_start_ns: "1800000000000000000", index: 3, ts_ns: "1800000000010000000", flow: "tap0|udp|a|b|0", dir: "orig",
    response: false,
    qname: XSS, qtype: 16, qclass: 1, qname_len: 29, labels: 1, label_len_max: 29, qname_entropy: 3.9,
    txt_records: 0, txt_bytes: 0, txt_max: null, size: 47, trailing_bytes: 4 };
  const out = vm.runInContext(`
    const slice = { flow: dns.flow, link: "tap0", window_start_ns: dns.window_start_ns, verdict: "opaque",
      orig_stats: { packets: 1, datagrams: 1 }, resp_stats: { packets: 0 }, orig_bytes: {}, resp_bytes: {} };
    const dnsF = { messages: 1, queries: 1, responses: 0, other_datagrams: 0, query_bytes: 47, response_bytes: 0, bytes: 47,
      query_rate: 1, qname_entropy_max: 3.9, qname_entropy_mean: 3.9, qname_len_max: 29, label_len_max: 29, label_len_mean: 29,
      txt_records: 0, txt_bytes: 0, txt_max: null };
    D = { base: 0n, flowsById: new Map([[dns.flow, { id: dns.flow, link: "tap0", kind: "udp", orig: "a", resp: "b", slices: [slice] }]]),
      packetsBySlice: new Map(), dnsBySlice: new Map([[dns.flow + "@" + dns.window_start_ns, [dns]]]),
      featuresBySlice: new Map([[dns.flow + "@" + dns.window_start_ns, { flow: dns.flow, window_start_ns: dns.window_start_ns, dns: dnsF }]]) };
    dnsTable([dns]) + kv(dnsRows(dns)) + vSlice(dns.flow, dns.window_start_ns);
  `, ctx);
  assert.ok(!out.includes("<img"), out);
  assert.equal(out.split("&lt;img src=x onerror=alert(1)&gt;").length - 1, 3, out);
  assert.ok(out.includes("4 trailing bytes"), out);
  assert.ok(out.includes("TXT"), out);
});

let failed = 0;
for (const [name, fn] of checks) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.log(`FAIL ${name}\n${e.message}`); }
}
if (failed) process.exit(1);
