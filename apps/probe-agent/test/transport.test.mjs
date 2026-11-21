import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { buildPinnedRequestOptions, requestPinned } from "../src/transport.mjs";

function listen(server) {
  return new Promise(resolve => server.listen(0, "127.0.0.1", () => resolve(server.address().port)));
}
function close(server) {
  return new Promise(resolve => server.close(resolve));
}

test("uses the selected IP in its lookup callback and preserves the HTTP Host header", async () => {
  let observedHost;
  let remoteAddress;
  const server = createServer((request, response) => {
    observedHost = request.headers.host;
    remoteAddress = request.socket.remoteAddress;
    response.writeHead(200, { "content-length": "2" });
    response.end("ok");
  });
  const port = await listen(server);
  try {
    const result = await requestPinned(new URL(`http://monitor.example:${port}/health`), "127.0.0.1", { timeoutMs: 2_000 });
    assert.equal(result.statusCode, 200);
    assert.equal(result.location, null);
    assert.equal(observedHost, `monitor.example:${port}`);
    assert.ok(remoteAddress === "127.0.0.1" || remoteAddress === "::ffff:127.0.0.1");
  } finally { await close(server); }
});

test("aborts a response once the bounded body limit is exceeded", async () => {
  const server = createServer((_request, response) => {
    response.writeHead(200, { "content-type": "text/plain" });
    response.end("x".repeat(1_024));
  });
  const port = await listen(server);
  try {
    await assert.rejects(
      requestPinned(new URL(`http://monitor.example:${port}/large`), "127.0.0.1", { timeoutMs: 2_000, maxResponseBytes: 32 }),
      /RESPONSE_TOO_LARGE/
    );
  } finally { await close(server); }
});

test("uses the original hostname for TLS SNI and keeps certificate verification enabled", () => {
  const options = buildPinnedRequestOptions(new URL("https://status.example/health"), "93.184.216.34");
  assert.equal(options.hostname, "status.example");
  assert.equal(options.servername, "status.example");
  assert.equal(options.rejectUnauthorized, true);
  assert.equal(options.agent, false);
  let pinned;
  options.lookup("ignored.example", {}, (_error, address, family) => { pinned = { address, family }; });
  assert.deepEqual(pinned, { address: "93.184.216.34", family: 4 });
  let familyError;
  options.lookup("ignored.example", { family: 6 }, error => { familyError = error; });
  assert.match(familyError.message, /PINNED_ADDRESS_FAMILY_MISMATCH/);
});
