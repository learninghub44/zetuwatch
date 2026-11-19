import test from "node:test";
import assert from "node:assert/strict";
import { runProbe, normalizeProbeInput } from "../src/runner.mjs";
import { assertPublicDnsAnswers, isPublicIpAddress } from "../../../packages/monitoring-core/src/ip-address.mjs";
import { validateMonitorUrl } from "../../../packages/monitoring-core/src/url-safety.mjs";

const publicAddress = "93.184.216.34";

test("rejects an entire DNS answer set when any answer is private", async () => {
  let requests = 0;
  const result = await runProbe({ targetUrl: "https://monitor.example.com/health" }, {
    resolver: async () => [publicAddress, "127.0.0.1"],
    requester: async () => { requests += 1; return { statusCode: 200, location: null }; }
  });
  assert.equal(result.isUp, false);
  assert.equal(result.errorCode, "DNS_FAILURE");
  assert.equal(requests, 0);
});

test("passes the validated address to the transport instead of asking it to resolve again", async () => {
  let pinned;
  const result = await runProbe({ targetUrl: "https://monitor.example.com/health" }, {
    resolver: async hostname => { assert.equal(hostname, "monitor.example.com"); return [publicAddress]; },
    requester: async (_url, address) => { pinned = address; return { statusCode: 200, location: null }; }
  });
  assert.equal(pinned, publicAddress);
  assert.equal(result.isUp, true);
  assert.equal(result.errorCode, null);
});

test("resolves and pins each redirect hop independently", async () => {
  const resolved = [];
  const connected = [];
  let hop = 0;
  const result = await runProbe({ targetUrl: "https://first.example.com/health", maxRedirects: 2 }, {
    resolver: async hostname => {
      resolved.push(hostname);
      return [hostname === "first.example.com" ? publicAddress : "1.1.1.1"];
    },
    requester: async (url, address) => {
      connected.push({ hostname: url.hostname, address });
      hop += 1;
      return hop === 1
        ? { statusCode: 302, location: "https://second.example.com/ready" }
        : { statusCode: 200, location: null };
    }
  });
  assert.deepEqual(resolved, ["first.example.com", "second.example.com"]);
  assert.deepEqual(connected, [
    { hostname: "first.example.com", address: publicAddress },
    { hostname: "second.example.com", address: "1.1.1.1" }
  ]);
  assert.equal(result.isUp, true);
  assert.equal(result.redirectCount, 1);
});

test("blocks a redirect to a private address before opening another connection", async () => {
  let requests = 0;
  const result = await runProbe({ targetUrl: "https://first.example.com/", maxRedirects: 2 }, {
    resolver: async () => [publicAddress],
    requester: async () => {
      requests += 1;
      return { statusCode: 302, location: "http://127.0.0.1/admin" };
    }
  });
  assert.equal(result.errorCode, "REDIRECT_BLOCKED");
  assert.equal(requests, 1);
});

test("rejects HTTPS-to-HTTP redirect downgrade", async () => {
  const result = await runProbe({ targetUrl: "https://first.example.com/", maxRedirects: 1 }, {
    resolver: async () => [publicAddress],
    requester: async () => ({ statusCode: 302, location: "http://second.example.com/" })
  });
  assert.equal(result.errorCode, "REDIRECT_DOWNGRADE");
});

test("does not follow redirects unless explicitly allowed", async () => {
  const result = await runProbe({ targetUrl: "https://first.example.com/" }, {
    resolver: async () => [publicAddress],
    requester: async () => ({ statusCode: 302, location: "https://second.example.com/" })
  });
  assert.equal(result.errorCode, "REDIRECT_LIMIT");
  assert.equal(result.redirectCount, 0);
});

test("recomputes the total deadline after DNS before opening the HTTP connection", async () => {
  let elapsed = 0;
  let requestTimeout;
  const result = await runProbe({
    targetUrl: "https://monitor.example.com/health",
    timeoutMs: 1_000
  }, {
    now: () => elapsed,
    resolver: async () => {
      elapsed += 400;
      return [publicAddress];
    },
    requester: async (_url, _address, options) => {
      requestTimeout = options.timeoutMs;
      elapsed += options.timeoutMs;
      return { statusCode: 200, location: null };
    }
  });

  assert.equal(requestTimeout, 600);
  assert.equal(result.isUp, true);
  assert.equal(result.responseTimeMs, 1_000);
});

test("does not open a socket when DNS consumes the remaining total probe budget", async () => {
  let elapsed = 0;
  let requests = 0;
  const result = await runProbe({
    targetUrl: "https://monitor.example.com/health",
    timeoutMs: 1_000
  }, {
    now: () => elapsed,
    resolver: async () => {
      elapsed += 950;
      return [publicAddress];
    },
    requester: async () => {
      requests += 1;
      return { statusCode: 200, location: null };
    }
  });

  assert.equal(result.isUp, false);
  assert.equal(result.errorCode, "TIMEOUT");
  assert.equal(requests, 0);
});

test("rejects methods, custom headers, and non-default ports", () => {
  assert.throws(() => normalizeProbeInput({ targetUrl: "https://monitor.example.com/", method: "POST" }), /PROBE_METHOD_NOT_ALLOWED/);
  assert.throws(() => normalizeProbeInput({ targetUrl: "https://monitor.example.com/", headers: { authorization: "secret" } }), /PROBE_JOB_INVALID/);
  assert.throws(() => normalizeProbeInput({ targetUrl: "https://monitor.example.com:8443/" }), /PORT_NOT_ALLOWED/);
});

test("detects redirect loops without making a repeated connection", async () => {
  let requests = 0;
  const result = await runProbe({ targetUrl: "https://loop.example.com/", maxRedirects: 3 }, {
    resolver: async () => [publicAddress],
    requester: async () => { requests += 1; return { statusCode: 302, location: "https://loop.example.com/" }; }
  });
  assert.equal(result.errorCode, "REDIRECT_LOOP");
  assert.equal(requests, 1);
});

test("shared IP policy allows public unicast and rejects special-use IPv4/IPv6", () => {
  assert.equal(isPublicIpAddress("1.1.1.1"), true);
  assert.equal(isPublicIpAddress("2606:4700:4700::1111"), true);
  for (const address of [
    "0.0.0.0", "10.1.2.3", "100.64.0.1", "127.0.0.1", "169.254.169.254",
    "172.16.0.1", "192.0.2.1", "192.168.1.1", "198.18.0.1", "203.0.113.10",
    "224.0.0.1", "240.0.0.1", "::1", "fc00::1", "fe80::1", "ff02::1",
    "2001:db8::1", "2002::1", "::ffff:8.8.8.8"
  ]) assert.equal(isPublicIpAddress(address), false, address);
  assert.throws(() => assertPublicDnsAnswers(Array(17).fill(publicAddress)), /DNS_TOO_MANY_ADDRESSES/);
});

test("rejects shortened, integer-only, octal and hexadecimal IPv4 URL spellings", () => {
  for (const target of [
    "http://127.1/health",
    "http://2130706433/health",
    "http://0x7f000001/health",
    "http://0177.0.0.1/health",
    "http://0x08080808/health"
  ]) {
    assert.throws(() => validateMonitorUrl(target), /IP_NOT_ALLOWED/);
  }
  assert.equal(validateMonitorUrl("https://8.8.8.8/health").hostname, "8.8.8.8");
  assert.equal(validateMonitorUrl("https://8.8.8.8./health").hostname, "8.8.8.8");
});
