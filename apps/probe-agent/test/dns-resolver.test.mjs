import test from "node:test";
import assert from "node:assert/strict";
import { resolveWithResolver } from "../src/dns-resolver.mjs";

const publicIpv4 = "93.184.216.34";
const publicIpv6 = "2606:4700:4700::1111";

test("cancels outstanding A/AAAA queries when the shared DNS deadline expires", async () => {
  let cancelCalls = 0;
  const pending = new Promise(() => {});
  const resolver = {
    resolve4: () => pending,
    resolve6: () => pending,
    cancel: () => { cancelCalls += 1; }
  };

  await assert.rejects(resolveWithResolver("monitor.example.com", 100, resolver), /DNS_TIMEOUT/);
  assert.equal(cancelCalls, 1);
});

test("accepts one empty address family when the other family has public answers", async () => {
  const resolver = {
    resolve4: async () => { throw Object.assign(new Error("no A records"), { code: "ENODATA" }); },
    resolve6: async () => [publicIpv6],
    cancel: () => { throw new Error("completed lookups should not be cancelled"); }
  };

  const addresses = await resolveWithResolver("monitor.example.com", 500, resolver);
  assert.deepEqual(addresses, [publicIpv6]);
});

test("fails closed when either address-family lookup has a resolver error", async () => {
  const resolver = {
    resolve4: async () => [publicIpv4],
    resolve6: async () => { throw Object.assign(new Error("temporary resolver failure"), { code: "EAI_AGAIN" }); },
    cancel: () => undefined
  };

  await assert.rejects(resolveWithResolver("monitor.example.com", 500, resolver), /DNS_LOOKUP_FAILED/);
});

test("rejects a mixed public/private A and AAAA answer set", async () => {
  const resolver = {
    resolve4: async () => [publicIpv4],
    resolve6: async () => ["fc00::1"],
    cancel: () => undefined
  };

  await assert.rejects(resolveWithResolver("monitor.example.com", 500, resolver), /DNS_NON_PUBLIC_ADDRESS/);
});

test("rejects a hostname with no usable A or AAAA records", async () => {
  const noData = () => Promise.reject(Object.assign(new Error("no records"), { code: "ENODATA" }));
  const resolver = { resolve4: noData, resolve6: noData, cancel: () => undefined };

  await assert.rejects(resolveWithResolver("monitor.example.com", 500, resolver), /DNS_NO_ADDRESSES/);
});

test("rejects malformed hostnames and unbounded DNS timeouts before querying", async () => {
  let queries = 0;
  const resolver = {
    resolve4: () => { queries += 1; return Promise.resolve([publicIpv4]); },
    resolve6: () => { queries += 1; return Promise.resolve([]); },
    cancel: () => undefined
  };

  await assert.rejects(resolveWithResolver("", 500, resolver), /DNS_HOST_INVALID/);
  await assert.rejects(resolveWithResolver("monitor.example.com", 2_501, resolver), /DNS_TIMEOUT_INVALID/);
  expectNeverQueried();
  function expectNeverQueried() { assert.equal(queries, 0); }
});
