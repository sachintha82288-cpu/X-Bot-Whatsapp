import jsQR from 'jsqr'
import { readFileSync } from 'node:fs'
const ours = JSON.parse(readFileSync(process.argv[2], 'utf8'))
let failures = 0
for (const [text, data] of Object.entries(ours)) {
  const scale = 4
  const quiet = 4
  const size = data.size
  const width = (size + quiet * 2) * scale
  const buffer = new Uint8ClampedArray(width * width * 4).fill(255)
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (data.rows[r][c] !== '1') continue
      for (let dy = 0; dy < scale; dy++) {
        for (let dx = 0; dx < scale; dx++) {
          const y = (r + quiet) * scale + dy
          const x = (c + quiet) * scale + dx
          const offset = (y * width + x) * 4
          buffer[offset] = buffer[offset + 1] = buffer[offset + 2] = 0
        }
      }
    }
  }
  const result = jsQR(buffer, width, width)
  const ok = result && result.data === text
  if (!ok) failures++
  console.log(`len=${text.length} size=${size} ${ok ? 'DECODED OK' : 'DECODE FAILED'}`)
}
console.log(failures === 0 ? 'ALL QR CODES DECODE' : `${failures} FAILURES`)
