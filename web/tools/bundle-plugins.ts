// Bundles plugins/*/src/index.ts into web/plugins/<name>.js (esbuild IIFE, es2023, opened by the `// @` lines
// written from plugins/<name>/manifest.ts) and lists them in web/plugins/index.json for the site.
// usage: node web/tools/bundle-plugins.ts   (esbuild on PATH, or ESBUILD=path/to/esbuild)
//        node web/tools/bundle-plugins.ts --out <dir> [name...]   bundles only, unlisted ones too, for dev builds
// The bundles are not committed: CI runs this for the `site` release that sunbird-tools/site deploys.
// It also writes web/version.json, what the site ships, for the runtime's update check (crates/runtime/src/update.rs):
// the loader's baked version and each plugin bundle's CRC-32.
// The native artifacts next to them come from `nu scripts/site.nu web`, which CI also runs:
//   libphoenix-{arm64,armv7}.so and libshadowhook_nothing-{arm64,armv7}.so. The site job adds
//   libphoenix-ios.dylib from the macOS ios workflow.
import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { crc32 } from 'node:zlib';

const root = fileURLToPath(new URL('../../', import.meta.url));
const esbuild = process.env.ESBUILD ?? 'esbuild';
const args = process.argv.slice(2);
const dev = args[0] === '--out';
const out = dev ? `${args[1]}/` : fileURLToPath(new URL('../plugins/', import.meta.url));
const only = dev ? args.slice(2) : [];
interface Listed {
  name: string;
  description: string;
  warning?: string;
}

// The `// @` lines crates/runtime reads in Header and permissions.rs.
const banner = (manifest: Phoenix.Manifest): string => {
  const { permissions: granted = {} } = manifest;
  return [
    `// @description ${manifest.description}`,
    `// @version ${manifest.version}`,
    `// @author ${manifest.author}`,
    manifest.enabled === false && '// @enabled false',
    manifest.warning && `// @warning ${manifest.warning}`,
    manifest.unlisted && '// @unlisted',
    manifest.minSunbird && `// @min-sunbird ${manifest.minSunbird}`,
    granted.gateway?.length && `// @gateway ${granted.gateway.join(' ')}`,
    granted.gatewaySend?.length && `// @gateway-send ${granted.gatewaySend.join(' ')}`,
    ...(granted.discord ?? []).map((route) => `// @discord ${route}`),
    granted.fetch?.length && `// @fetch ${granted.fetch.join(' ')}`,
    granted.stores && '// @stores',
    granted.messages && '// @messages',
    granted.bridge && '// @bridge',
    granted.uiTree && '// @ui-tree',
  ].filter((line): line is string => typeof line === 'string').join('\n');
};

const index: Listed[] = [];
for (const name of readdirSync(`${root}plugins`).sort()) {
  const entry = `${root}plugins/${name}/src/index.ts`;
  if (!existsSync(entry) || (only.length > 0 && !only.includes(name))) continue;
  const manifest: Phoenix.Manifest = (await import(pathToFileURL(`${root}plugins/${name}/manifest.ts`).href)).default;
  // Unlisted plugins, like the API demo, ship only in dev builds.
  if (manifest.unlisted && !dev) continue;
  const r = spawnSync(esbuild, [entry, '--bundle', '--format=iife', '--target=es2023', '--log-level=warning', `--banner:js=${banner(manifest)}`, `--outfile=${out}${name}.js`],
    { stdio: 'inherit' });
  if (r.status !== 0) process.exit(r.status ?? 1);
  index.push({
    name,
    description: manifest.description,
    ...(manifest.warning ? { warning: manifest.warning } : {}),
  });
}
if (dev) process.exit(0);
writeFileSync(`${out}index.json`, JSON.stringify(index, null, 2) + '\n');
// crates/runtime/src/update.rs marks the version as `phoenix-version:<version>;`. An older loader has none: `0`
// is older than every build, so nobody is told to update to it.
// Without the Android loader (a desktop-only build, `scripts/dev.ps1 -Desktop`) there is no version to ship.
const so = `${out}libphoenix-arm64.so`;
if (existsSync(so)) {
  const loader = readFileSync(so, 'latin1').match(/phoenix-version:([\w.-]+);/)?.[1] ?? '0';
  const loader_crcs = Object.fromEntries(
    readdirSync(out)
      .filter((name) => /^libphoenix-.*\.(so|dylib)$/.test(name))
      .sort()
      .map((name) => [name, crc32(readFileSync(`${out}${name}`))]),
  );
  const plugins = Object.fromEntries(index.map(({ name }) => [name, crc32(readFileSync(`${out}${name}.js`))]));
  writeFileSync(fileURLToPath(new URL('../version.json', import.meta.url)), JSON.stringify({ loader, loader_crcs, plugins }, null, 2) + '\n');
} else {
  console.log('no libphoenix-arm64.so, leaving web/version.json as it is');
}
console.log(`bundled ${index.map((p) => p.name).join(', ')}`);
