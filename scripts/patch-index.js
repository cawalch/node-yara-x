const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const indexPath = path.join(__dirname, '..', 'index.js');
let content = fs.readFileSync(indexPath, 'utf8');

const oldCode = "return require('child_process').execSync('ldd --version', { encoding: 'utf8' }).includes('musl')";
const newCode = `    const { spawnSync } = require('child_process')
    const { stdout } = spawnSync('ldd', ['--version'], { encoding: 'utf8' })
    return stdout && stdout.includes('musl')`;

if (content.includes(oldCode)) {
  content = content.replace(oldCode, newCode);
  fs.writeFileSync(indexPath, content, 'utf8');
  console.log('Successfully patched index.js to use spawnSync instead of execSync');
} else {
  // Check if it matches the pattern but slightly different formatting?
  // Or check if already patched.
  if (content.includes("spawnSync('ldd'")) {
      console.log('index.js seems to be already patched');
  } else {
      console.error('Could not find the exact code to patch in index.js');
      // Let's print the relevant part of the file to debug if it fails
      const start = content.indexOf('const isMuslFromChildProcess');
      if (start !== -1) {
          console.error('Found isMuslFromChildProcess but content mismatch:');
          console.error(content.substring(start, start + 300));
      }
      process.exit(1);
  }
}
