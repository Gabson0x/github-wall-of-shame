// Parent: run each test in a fresh child with a timeout; classify result.
const { spawn } = require('child_process');
const path = require('path');

const TESTS = [
  ['control_valid.avif', 'decode', 30],
  ['control_valid.avif', 'meta', 30],
  ['benign.heic', 'decode', 60],
  ['ctrl_iloc.heif', 'decode', 30],
  ['chain_small.heif', 'decode', 30],
  ['chain.heif', 'meta', 30],
  ['chain.heif', 'decode', 30],
  ['flood.heif', 'decode', 120],
  ['flood4.heif', 'decode', 180],
  ['wasm300k.heif', 'decode', 180],
  ['deadlock.heic', 'meta', 30],
  ['deadlock.heic', 'decode', 45],
];

(async () => {
  for (const [file, mode, timeoutSec] of TESTS) {
    const t0 = Date.now();
    await new Promise(res => {
      const p = spawn('node', [path.join(__dirname, 'run_one.js'), path.join(__dirname, file), mode], { cwd: __dirname });
      let out = '';
      p.stdout.on('data', d => out += d);
      p.stderr.on('data', d => out += d);
      const killer = setTimeout(() => p.kill('SIGKILL'), timeoutSec * 1000);
      p.on('close', (code, signal) => {
        clearTimeout(killer);
        const ms = Date.now() - t0;
        const timedOut = signal === 'SIGKILL' && ms >= timeoutSec * 1000 - 800;
        const verdict = timedOut ? 'HUNG(killed at timeout)' : `exit=${code}${signal ? ' signal=' + signal : ''}`;
        console.log(`${file.padEnd(20)} ${mode.padEnd(6)} ${verdict.padEnd(28)} ${String(ms).padStart(7)}ms  ${(out || '').trim().slice(0, 220)}`);
        res();
      });
    });
  }
  console.log('done');
})();
