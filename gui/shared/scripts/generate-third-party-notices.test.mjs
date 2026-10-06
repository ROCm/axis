// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { afterEach } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  generateSection,
  normalizeNoticeText,
  reviewedShippedDevPackages,
  withGeneratedSection,
} from "./generate-third-party-notices.mjs";

const fixtureRoots = new Set();
const execFileAsync = promisify(execFile);
const scriptPath = fileURLToPath(new URL("./generate-third-party-notices.mjs", import.meta.url));

afterEach(async () => {
  const roots = [...fixtureRoots];
  fixtureRoots.clear();
  await Promise.all(roots.map((root) => rm(root, { recursive: true, force: true })));
});

async function fixture({
  lockfileVersion = 3,
  packagePath = "node_modules/example",
  lockVersion = "1.0.0",
  installedVersion = lockVersion,
  lockLicense = "MIT",
  installedLicense = lockLicense,
  dev = false,
  includeLicense = true,
  licenseText = "Exact license text\n",
} = {}) {
  const root = await mkdtemp(path.join(tmpdir(), "axis-gui-notices-"));
  fixtureRoots.add(root);
  const packages = {
    "": { name: "fixture" },
    [packagePath]: { version: lockVersion, license: lockLicense, ...(dev ? { dev: true } : {}) },
  };
  await writeFile(
    path.join(root, "package-lock.json"),
    JSON.stringify({ lockfileVersion, packages }),
  );
  const packageDir = path.resolve(root, packagePath);
  const nodeModulesDir = path.resolve(root, "node_modules");
  if (packageDir.startsWith(`${nodeModulesDir}${path.sep}`)) {
    await mkdir(packageDir, { recursive: true });
    await writeFile(
      path.join(packageDir, "package.json"),
      JSON.stringify({ name: "example", version: installedVersion, license: installedLicense }),
    );
    if (includeLicense) await writeFile(path.join(packageDir, "LICENSE"), licenseText);
  }
  return root;
}

async function generateFixture(options) {
  return generateSection(await fixture(options), new Map());
}

test("generates notices from locked production package metadata and license files", async () => {
  const section = await generateFixture();
  assert.match(section, /### example 1\.0\.0/);
  assert.match(section, /Declared license: MIT/);
  assert.match(section, /Exact license text/);
});

test("normalizes legal text line endings and trailing spaces and tabs", async () => {
  const section = await generateFixture({
    licenseText: "First line  \r\n\t \r\nSecond line\t\rThird line  \r\n",
  });
  assert.match(
    section,
    /Declared license: MIT\n\nFirst line\n\nSecond line\nThird line\n<!-- END GENERATED/,
  );
  assert.doesNotMatch(section, /\r/);
  assert.equal(
    section.split("\n").some((line) => line.endsWith(" ") || line.endsWith("\t")),
    false,
  );
});

test("rejects unsupported lockfile versions", async () => {
  await assert.rejects(generateFixture({ lockfileVersion: 2 }), /package-lock v3/);
});

test("rejects production package paths outside node_modules", async () => {
  await assert.rejects(generateFixture({ packagePath: "vendor/example" }), /Unexpected/);
});

test("rejects path traversal from node_modules", async () => {
  await assert.rejects(
    generateFixture({ packagePath: "node_modules/../../example" }),
    /escapes node_modules/,
  );
});

test("rejects installed versions that differ from the lockfile", async () => {
  await assert.rejects(
    generateFixture({ installedVersion: "2.0.0" }),
    /does not match lockfile/,
  );
});

test("rejects package metadata that differs from the locked license", async () => {
  await assert.rejects(
    generateFixture({ installedLicense: "Apache-2.0" }),
    /unreviewed license/,
  );
});

test("rejects license expressions that have not been reviewed", async () => {
  await assert.rejects(
    generateFixture({ lockLicense: "Apache-2.0" }),
    /unreviewed license/,
  );
});

test("rejects packages without distributed license text", async () => {
  await assert.rejects(generateFixture({ includeLicense: false }), /No license file/);
});

test("rejects a lockfile without production dependencies", async () => {
  await assert.rejects(generateFixture({ dev: true }), /No production/);
});

async function viteFixture({
  lockVersion = "8.3.1",
  installedVersion = lockVersion,
  lockLicense = "MIT",
  installedLicense = lockLicense,
  integrity = reviewedShippedDevPackages.get("node_modules/vite").integrity,
  resolved = reviewedShippedDevPackages.get("node_modules/vite").resolved,
  licenseText = "Reviewed Vite license\n",
  licenseSha256,
  extraPackages = {},
} = {}) {
  const root = await mkdtemp(path.join(tmpdir(), "axis-gui-vite-notices-"));
  fixtureRoots.add(root);
  const packagePath = "node_modules/vite";
  await writeFile(
    path.join(root, "package-lock.json"),
    JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "fixture" },
        [packagePath]: {
          version: lockVersion,
          license: lockLicense,
          resolved,
          integrity,
          dev: true,
        },
        ...extraPackages,
      },
    }),
  );
  const packageDir = path.join(root, packagePath);
  await mkdir(packageDir, { recursive: true });
  await writeFile(
    path.join(packageDir, "package.json"),
    JSON.stringify({ name: "vite", version: installedVersion, license: installedLicense }),
  );
  await writeFile(path.join(packageDir, "LICENSE.md"), licenseText);
  const reviewed = new Map([
    [
      packagePath,
      {
        ...reviewedShippedDevPackages.get(packagePath),
        licenseSha256:
          licenseSha256 ?? createHash("sha256").update(licenseText).digest("hex"),
      },
    ],
  ]);
  return { root, reviewed };
}

test("includes the explicitly reviewed Vite runtime contribution", async () => {
  const { root, reviewed } = await viteFixture();
  const section = await generateSection(root, reviewed);
  assert.match(section, /### vite 8\.3\.1/);
  assert.match(section, /Shipped runtime component: Vite module-preload polyfill/);
  assert.match(section, /Reviewed Vite license/);
});

test("rejects Vite lock, metadata, and license hash drift", async () => {
  for (const options of [
    { lockVersion: "7.3.7" },
    { installedVersion: "7.3.7" },
    { lockLicense: "Apache-2.0" },
    { installedLicense: "Apache-2.0" },
    { integrity: "sha512-tampered" },
    { resolved: "https://registry.npmjs.org/vite/-/vite-7.3.7.tgz" },
    { licenseSha256: "0".repeat(64) },
  ]) {
    const { root, reviewed } = await viteFixture(options);
    await assert.rejects(generateSection(root, reviewed));
  }
});

test("does not include unrelated dev dependencies", async () => {
  const { root, reviewed } = await viteFixture({
    extraPackages: {
      "node_modules/dev-only": { version: "1.0.0", license: "MIT", dev: true },
    },
  });
  const section = await generateSection(root, reviewed);
  assert.doesNotMatch(section, /dev-only/);
});

test("rejects a missing reviewed shipped runtime package", async () => {
  await assert.rejects(generateSection(await fixture()), /absent from lockfile/);
});

test("appends, replaces, and validates generated section markers", () => {
  assert.equal(withGeneratedSection("# Existing\n", "generated"), "# Existing\n\ngenerated\n");
  assert.equal(
    withGeneratedSection(
      "before\n<!-- BEGIN GENERATED GUI FRONTEND NOTICES -->old<!-- END GENERATED GUI FRONTEND NOTICES -->\nafter\n",
      "generated",
    ),
    "before\ngenerated\nafter\n",
  );
  assert.equal(
    withGeneratedSection(
      "before  \r\n<!-- BEGIN GENERATED GUI FRONTEND NOTICES -->old\t\r\n<!-- END GENERATED GUI FRONTEND NOTICES -->\r\nafter\t\r\n",
      "generated  \r\ntext\t",
    ),
    "before\ngenerated\ntext\nafter\n",
  );
  for (const malformed of [
    "<!-- BEGIN GENERATED GUI FRONTEND NOTICES -->",
    "<!-- END GENERATED GUI FRONTEND NOTICES -->",
    "<!-- END GENERATED GUI FRONTEND NOTICES --><!-- BEGIN GENERATED GUI FRONTEND NOTICES -->",
    "<!-- BEGIN GENERATED GUI FRONTEND NOTICES --><!-- BEGIN GENERATED GUI FRONTEND NOTICES --><!-- END GENERATED GUI FRONTEND NOTICES -->",
  ]) {
    assert.throws(() => withGeneratedSection(malformed, "generated"), /Malformed/);
  }
});

test("Node and Python composition are idempotent across normalization drift", async () => {
  const pythonScriptsDir = path.resolve(path.dirname(scriptPath), "../../../scripts");
  const pythonCompose = async (distribution, frontend) => {
    const program = [
      "import sys",
      "sys.path.insert(0, sys.argv[1])",
      "import generate_third_party_notices as notices",
      "sys.stdout.buffer.write(notices.compose_document(sys.argv[2], sys.argv[3].encode('utf-8')))",
    ].join("; ");
    return (
      await execFileAsync(
        "python3",
        ["-c", program, pythonScriptsDir, distribution, frontend],
        { encoding: "utf8" },
      )
    ).stdout;
  };
  const frontend =
    "<!-- BEGIN GENERATED GUI FRONTEND NOTICES -->\r\nfrontend  \r\n\t \rtext\t\r\n<!-- END GENERATED GUI FRONTEND NOTICES -->";
  const pythonDocument = await pythonCompose("distribution  \r\n", frontend);
  const driftedDocument = pythonDocument
    .replace("# Third-Party Notices\n\n", "# Third-Party Notices  \r\n\r\n")
    .replace("distribution\n", "distribution\t\r\n");
  const nodeDocument = withGeneratedSection(driftedDocument, frontend);

  assert.equal(nodeDocument, pythonDocument);
  assert.equal(
    await pythonCompose("distribution\n", normalizeNoticeText(frontend)),
    nodeDocument,
  );
});

test("print mode emits exactly one complete generated section", async () => {
  const { stdout, stderr } = await execFileAsync(process.execPath, [scriptPath, "--print"]);
  assert.equal(stderr, "");
  assert.equal(stdout, `${await generateSection()}\n`);
  assert.match(stdout, /### vite 8\.3\.1/);
  assert.match(stdout, /Shipped runtime component: Vite module-preload polyfill/);
});

test("rejects unsupported command modes", async () => {
  await assert.rejects(
    execFileAsync(process.execPath, [scriptPath, "--invalid"]),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /--check\|--write\|--print/);
      return true;
    },
  );
});
