// Child process: feed one file through sharp, report JSON verdict.
const sharp = require('sharp');
const fs = require('fs');
const [file, mode = 'decode'] = process.argv.slice(2);
const buf = fs.readFileSync(file);
const t0 = process.hrtime.bigint();
const elapsed = () => Number(process.hrtime.bigint() - t0) / 1e6;

(async () => {
  if (mode === 'meta') {
    const m = await sharp(buf, { failOn: 'none' }).metadata();
    console.log(JSON.stringify({ file, mode, ok: true, msg: `meta ${m.format} ${m.width}x${m.height}`, ms: elapsed(), rss_mb: Math.round(process.memoryUsage().rss / 1048576) }));
  } else {
    const out = await sharp(buf, { failOn: 'none' }).resize(256, 256, { fit: 'inside' }).png().toBuffer();
    console.log(JSON.stringify({ file, mode, ok: true, msg: `decoded to ${out.length}B png`, ms: elapsed(), rss_mb: Math.round(process.memoryUsage().rss / 1048576) }));
  }
  process.exit(0);
})().catch(e => {
  console.log(JSON.stringify({ file, mode, ok: false, msg: 'error: ' + String(e.message).slice(0, 160), ms: elapsed(), rss_mb: Math.round(process.memoryUsage().rss / 1048576) }));
  process.exit(2);
});
