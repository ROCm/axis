// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { evaluateAudit } from "./audit.mjs";

const picomatch = {
  name: "picomatch",
  severity: "high",
  url: "https://github.com/advisories/GHSA-fc5q-39xc-vjpf",
};

function report(...advisories) {
  return {
    vulnerabilities: {
      picomatch: { via: advisories },
      vite: { via: ["picomatch", "tinyglobby"] },
    },
  };
}

const exception = {
  advisory: "GHSA-fc5q-39xc-vjpf",
  package: "picomatch",
  latestVulnerable: "4.0.7",
  reason: "build-time only",
};
const unpatched = new Map([["picomatch", "4.0.7"]]);

test("excepts the listed advisory while no newer release exists", () => {
  const result = evaluateAudit(report(picomatch), [exception], unpatched);
  assert.deepEqual(result.blocking, []);
  assert.deepEqual(result.excepted, ["picomatch GHSA-fc5q-39xc-vjpf"]);
});

test("blocks the advisory again once a newer release is published", () => {
  const result = evaluateAudit(report(picomatch), [exception], new Map([["picomatch", "4.0.8"]]));
  assert.deepEqual(result.blocking, ["picomatch GHSA-fc5q-39xc-vjpf"]);
  assert.deepEqual(result.superseded, [{ key: "picomatch GHSA-fc5q-39xc-vjpf", latest: "4.0.8" }]);
});

test("blocks other high and critical advisories", () => {
  const other = { name: "ws", severity: "critical", url: "https://github.com/advisories/GHSA-xxxx" };
  const result = evaluateAudit(report(picomatch, other), [exception], unpatched);
  assert.deepEqual(result.blocking, ["ws GHSA-xxxx"]);
});

test("does not except the advisory for a different package", () => {
  const renamed = { ...picomatch, name: "picomatch-fork" };
  const result = evaluateAudit(report(renamed), [exception], unpatched);
  assert.deepEqual(result.blocking, ["picomatch-fork GHSA-fc5q-39xc-vjpf"]);
});

test("ignores moderate and low advisories", () => {
  const moderate = { ...picomatch, severity: "moderate" };
  assert.deepEqual(evaluateAudit(report(moderate), [], unpatched).blocking, []);
});

test("reports an exception that no longer matches a finding", () => {
  const result = evaluateAudit({ vulnerabilities: {} }, [exception], unpatched);
  assert.deepEqual(result.unused, ["picomatch GHSA-fc5q-39xc-vjpf"]);
});

test("rejects malformed exceptions", () => {
  assert.throws(
    () => evaluateAudit(report(picomatch), [{ ...exception, latestVulnerable: "" }], unpatched),
    /need advisory, package, latestVulnerable and reason/,
  );
  assert.throws(
    () => evaluateAudit(report(picomatch), [{ ...exception, reason: undefined }], unpatched),
    /need advisory, package, latestVulnerable and reason/,
  );
});

test("fails closed when the latest release is unknown", () => {
  assert.throws(
    () => evaluateAudit(report(picomatch), [exception], new Map()),
    /no published version found for picomatch/,
  );
});

test("fails closed when npm audit returns an error instead of a report", () => {
  assert.throws(
    () => evaluateAudit({ error: { code: "ENOTFOUND" } }, [exception], unpatched),
    /did not return a vulnerability report/,
  );
});
