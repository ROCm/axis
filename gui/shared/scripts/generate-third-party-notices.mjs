// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import { readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const beginMarker = "<!-- BEGIN GENERATED GUI FRONTEND NOTICES -->";
const endMarker = "<!-- END GENERATED GUI FRONTEND NOTICES -->";
const supportedLicenses = new Set(["MIT"]);
export const reviewedShippedDevPackages = new Map([
  [
    "node_modules/vite",
    {
      name: "vite",
      version: "8.3.1",
      license: "MIT",
      resolved: "https://registry.npmjs.org/vite/-/vite-8.3.1.tgz",
      integrity:
        "sha512-/bvH9E9tmCXRGp2uXY3WbOldqpTwFkbha/8ANaEQ6VkxhH60KyqLwgZq6lG2y+4uT55x9+9eUHMpQ7uGnOCKjA==",
      licenseFile: "LICENSE.md",
      licenseSha256: "387dd7baa307083401a27c58c362c30832f5ba1dba84f10cc22c33401523f45c",
      shippedComponent: "Vite module-preload polyfill",
    },
  ],
]);
const projectDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repositoryDir = path.resolve(projectDir, "../..");
const noticesPath = path.join(repositoryDir, "THIRD_PARTY_NOTICES.md");

function fail(message) {
  console.error(message);
  process.exitCode = 1;
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function normalizeNoticeText(text) {
  return text
    .replaceAll("\r\n", "\n")
    .replaceAll("\r", "\n")
    .split("\n")
    .map((line) => line.replace(/[ \t]+$/, ""))
    .join("\n");
}

export async function findLicenseFile(packageDir, relativeTo = projectDir) {
  const entries = await readdir(packageDir, { withFileTypes: true });
  const candidates = entries
    .filter((entry) => entry.isFile() && /^licen[cs]e(?:\..+)?$/i.test(entry.name))
    .map((entry) => entry.name)
    .sort((left, right) => {
      if (left === "LICENSE") return -1;
      if (right === "LICENSE") return 1;
      return compareText(left, right);
    });

  if (candidates.length === 0) {
    throw new Error(`No license file found in ${path.relative(relativeTo, packageDir)}`);
  }
  return path.join(packageDir, candidates[0]);
}

export async function generateSection(
  sourceProjectDir = projectDir,
  reviewedDevPackages = reviewedShippedDevPackages,
) {
  const lockfile = JSON.parse(
    await readFile(path.join(sourceProjectDir, "package-lock.json"), "utf8"),
  );
  if (lockfile.lockfileVersion !== 3 || typeof lockfile.packages !== "object") {
    throw new Error("Expected an npm package-lock v3 packages map");
  }

  const packages = [];
  const reviewedDevPackagesFound = new Set();
  for (const [packagePath, locked] of Object.entries(lockfile.packages)) {
    if (packagePath === "") continue;
    const reviewedDevPackage = reviewedDevPackages.get(packagePath);
    if (locked.dev === true && reviewedDevPackage === undefined) continue;
    if (reviewedDevPackage !== undefined) {
      reviewedDevPackagesFound.add(packagePath);
      for (const field of ["version", "license", "resolved", "integrity"]) {
        if (locked[field] !== reviewedDevPackage[field]) {
          throw new Error(
            `${reviewedDevPackage.name} locked ${field} does not match the reviewed runtime value`,
          );
        }
      }
      if (locked.dev !== true) {
        throw new Error(`${reviewedDevPackage.name} is no longer a reviewed dev-only runtime package`);
      }
    }
    if (!packagePath.startsWith("node_modules/")) {
      throw new Error(`Unexpected production package path: ${packagePath}`);
    }

    const nodeModulesDir = path.resolve(sourceProjectDir, "node_modules");
    const packageDir = path.resolve(sourceProjectDir, packagePath);
    if (!packageDir.startsWith(`${nodeModulesDir}${path.sep}`)) {
      throw new Error(`Production package path escapes node_modules: ${packagePath}`);
    }
    const metadata = JSON.parse(await readFile(path.join(packageDir, "package.json"), "utf8"));
    if (reviewedDevPackage && metadata.name !== reviewedDevPackage.name) {
      throw new Error(`Installed package name does not match reviewed runtime package ${packagePath}`);
    }
    if (metadata.version !== locked.version) {
      throw new Error(
        `${metadata.name} install version ${metadata.version} does not match lockfile ${locked.version}`,
      );
    }
    if (metadata.license !== locked.license || !supportedLicenses.has(locked.license)) {
      throw new Error(
        `${metadata.name}@${metadata.version} has unreviewed license ${JSON.stringify(locked.license)}`,
      );
    }

    const licensePath = reviewedDevPackage
      ? path.join(packageDir, reviewedDevPackage.licenseFile)
      : await findLicenseFile(packageDir, sourceProjectDir);
    const licenseBytes = await readFile(licensePath);
    if (reviewedDevPackage) {
      const actualLicenseHash = createHash("sha256").update(licenseBytes).digest("hex");
      if (actualLicenseHash !== reviewedDevPackage.licenseSha256) {
        throw new Error(`${reviewedDevPackage.name} installed license text hash does not match review`);
      }
    }
    const licenseText = normalizeNoticeText(licenseBytes.toString("utf8")).trimEnd();
    packages.push({
      name: metadata.name,
      version: metadata.version,
      license: locked.license,
      licenseText,
      shippedComponent: reviewedDevPackage?.shippedComponent,
    });
  }

  for (const packagePath of reviewedDevPackages.keys()) {
    if (!reviewedDevPackagesFound.has(packagePath)) {
      throw new Error(`Reviewed shipped runtime package is absent from lockfile: ${packagePath}`);
    }
  }

  packages.sort(
    (left, right) => compareText(left.name, right.name) || compareText(left.version, right.version),
  );
  if (packages.length === 0) throw new Error("No production frontend dependencies found");

  const entries = packages.map(
    ({ name, version, license, licenseText, shippedComponent }) =>
      `### ${name} ${version}\n\nDeclared license: ${license}\n\n${
        shippedComponent ? `Shipped runtime component: ${shippedComponent}\n\n` : ""
      }${licenseText}`,
  );
  return normalizeNoticeText([
    beginMarker,
    "## GUI Frontend Dependencies",
    "",
    "These notices conservatively cover the desktop GUI's complete locked production",
    "dependency closure plus explicitly reviewed build dependencies that contribute code",
    "to shipped assets. This section is generated from `gui/shared/package-lock.json` and",
    "the license files distributed by the corresponding locked packages.",
    "",
    ...entries.flatMap((entry, index) => (index === 0 ? [entry] : ["", "---", "", entry])),
    endMarker,
  ].join("\n"));
}

export function withGeneratedSection(current, generated) {
  const beginCount = current.split(beginMarker).length - 1;
  const endCount = current.split(endMarker).length - 1;
  if (beginCount === 0 && endCount === 0) {
    return normalizeNoticeText(`${current.trimEnd()}\n\n${generated}\n`);
  }
  if (beginCount !== 1 || endCount !== 1) throw new Error("Malformed generated notice markers");
  const begin = current.indexOf(beginMarker);
  const end = current.indexOf(endMarker);
  if (end < begin) throw new Error("Malformed generated notice markers");
  const suffixStart = end + endMarker.length;
  return normalizeNoticeText(
    `${current.slice(0, begin)}${generated}${current.slice(suffixStart)}`,
  );
}

async function main() {
  const mode = process.argv[2];
  if (mode !== "--check" && mode !== "--write" && mode !== "--print") {
    fail("Usage: generate-third-party-notices.mjs --check|--write|--print");
  } else {
    try {
      const generated = await generateSection();
      if (mode === "--print") {
        process.stdout.write(`${generated}\n`);
      } else {
      const current = await readFile(noticesPath, "utf8").catch((error) => {
        if (mode === "--write" && error?.code === "ENOENT") return "";
        throw error;
      });
        const expected = withGeneratedSection(current, generated);
        if (mode === "--write") {
          await writeFile(noticesPath, expected);
        } else if (current !== expected) {
          fail("THIRD_PARTY_NOTICES.md is stale; run npm run notices:generate in gui/shared");
        }
      }
    } catch (error) {
      fail(error instanceof Error ? error.message : String(error));
    }
  }
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  await main();
}
