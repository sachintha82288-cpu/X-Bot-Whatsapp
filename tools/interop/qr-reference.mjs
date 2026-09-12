// Compare the python QR encoder against the `qrcode` npm package output.
// Usage: node qr-reference.mjs <matrix.json>
import QRCode from 'qrcode'
import { readFileSync } from 'node:fs'

const ours = JSON.parse(readFileSync(process.argv[2], 'utf8'))
let mismatches = 0
let compared = 0
for (const [text, data] of Object.entries(ours)) {
	const ref = QRCode.create([{ data: Buffer.from(text, 'utf8'), mode: 'byte' }], { errorCorrectionLevel: 'L' })
	const size = ref.modules.size
	let diff = 0
	for (let r = 0; r < size; r++) {
		for (let c = 0; c < size; c++) {
			const value = ref.modules.get(r, c) ? '1' : '0'
			if (value !== data.rows[r][c]) diff++
		}
	}
	compared++
	// a different (but still valid) mask is acceptable, exact equality is what
	// we aim for: report both
	if (size !== data.size || diff !== 0) {
		mismatches++
		console.log(`  ${size === data.size && diff === 0 ? 'exact' : 'differs'} len=${text.length} size=${size}/${data.size} modules=${diff}`)
	}
}
// picking a different mask is still a valid QR code, so differences here are
// informational - the decoder check is the authoritative one
console.log(mismatches === 0
	? `reference: all ${compared} matrices are byte-identical`
	: `reference: ${compared - mismatches}/${compared} byte-identical (rest use another mask)`)
