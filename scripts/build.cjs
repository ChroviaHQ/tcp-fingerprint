const { spawnSync } = require('node:child_process');
const { mkdirSync, mkdtempSync, copyFileSync, renameSync, rmSync } = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const dist = path.join(root, 'dist');
let temp;
try {
  mkdirSync(dist, { recursive: true });
  temp = mkdtempSync(path.join(dist, '.build-'));
  const docs = ['LICENSE', 'README.md', 'CONTRIBUTING.md', 'SECURITY.md'];
  const files = ['tcp-fingerprint-linux-amd64', 'tcp-fingerprint-linux-arm64', 'install.sh', ...docs];
  for (const arch of ['amd64', 'arm64']) {
    const output = path.join(temp, `tcp-fingerprint-linux-${arch}`);
    const result = spawnSync('go', ['build', '-trimpath', '-ldflags=-s -w', '-o', output, '.'], {
      cwd: root,
      env: { ...process.env, GOOS: 'linux', GOARCH: arch, CGO_ENABLED: '0' },
      stdio: 'inherit',
    });
    if (result.error || result.status !== 0) {
      throw new Error(result.error?.message || `Build failed for linux/${arch}`);
    }
  }
  copyFileSync(path.join(root, 'scripts', 'install.sh'), path.join(temp, 'install.sh'));
  for (const file of docs) {
    copyFileSync(path.join(root, file), path.join(temp, file));
  }
  for (const file of files) {
    renameSync(path.join(temp, file), path.join(dist, file));
    console.log(path.join(dist, file));
  }
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
} finally {
  if (temp) rmSync(temp, { recursive: true, force: true });
}
