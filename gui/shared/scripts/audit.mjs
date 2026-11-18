// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";

const projectDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const blockingSeverities = new Set(["high", "critical"]);

export function validateExceptions(exceptions) {
  if (!Array.isArray(exceptions)) throw new Error("audit exceptions must be an array");
  for (const exception of exceptions) {
    const { advisory, package: name, latestVulnerable, reason } = exception ?? {};
    if (![advisory, name, latestVulnerable, reason].every((v) => typeof v === "string" && v)) {
      throw new Error("audit exceptions need advisory, package, latestVulnerable and reason");
    }
  }
  return exceptions;
}

export function evaluateAudit(report, exceptions, latestVersions) {
  if (typeof report?.vulnerabilities !== "object" || report.vulnerabilities === null) {
    throw new Error("npm audit did not return a vulnerability report");
  }

  const active = new Map();
  const superseded = [];
  for (const exception of validateExceptions(exceptions)) {
    const { advisory, package: name, latestVulnerable } = exception;
    const latest = latestVersions.get(name);
    if (typeof latest !== "string" || !latest) {
      throw new Error(`no published version found for ${name}`);
    }
    const key = `${name} ${advisory}`;
    if (latest === latestVulnerable) active.set(key, latestVulnerable);
    else superseded.push({ key, latest });
  }

  const blocking = new Set();
  const excepted = new Set();
  for (const vulnerability of Object.values(report.vulnerabilities)) {
    for (const via of vulnerability?.via ?? []) {
      if (typeof via !== "object" || !blockingSeverities.has(via.severity)) continue;
      const key = `${via.name} ${String(via.url ?? via.source).split("/").pop()}`;
      (active.has(key) ? excepted : blocking).add(key);
    }
  }
  const unused = [...active.keys()].filter((key) => !excepted.has(key));
  return { blocking: [...blocking], excepted: [...excepted], superseded, unused, active };
}

async function npm(args) {
  try {
    const { stdout } = await promisify(execFile)("npm", args, {
      cwd: projectDir,
      maxBuffer: 64 * 1024 * 1024,
    });
    return stdout;
  } catch (error) {
    // npm audit exits 1 when it finds advisories but still prints the report.
    if (args[0] === "audit" && typeof error.stdout === "string" && error.stdout.trim()) {
      return error.stdout;
    }
    throw error;
  }
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  const exceptions = validateExceptions(
    JSON.parse(await readFile(path.join(projectDir, "audit-exceptions.json"), "utf8")),
  );
  const latestVersions = new Map();
  for (const name of new Set(exceptions.map((exception) => exception.package))) {
    latestVersions.set(name, (await npm(["view", name, "version"])).trim());
  }
  const report = JSON.parse(await npm(["audit", "--json"]));
  const result = evaluateAudit(report, exceptions, latestVersions);
  for (const key of result.excepted) {
    console.log(`Excepted while ${result.active.get(key)} is the latest release: ${key}`);
  }
  for (const key of result.unused) console.log(`Unused audit exception: ${key}`);
  for (const { key, latest } of result.superseded) {
    console.error(
      `${latest} is now published, so the exception for ${key} no longer applies. ` +
        "Update the lockfile if it fixes the advisory, then remove the exception.",
    );
  }
  if (result.blocking.length > 0) {
    console.error(`High or critical advisories: ${result.blocking.join(", ")}`);
    process.exitCode = 1;
  } else {
    console.log("No unexcepted high or critical advisories");
  }
}
