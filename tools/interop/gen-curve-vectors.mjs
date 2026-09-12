/**
 * Interop harness: generates reference vectors with the *real* WhatsApp
 * libraries (Baileys v7 / libsignal) so the pure-Python implementation in
 * this repository can be checked byte-for-byte.
 *
 * Usage (dev only — the bot itself needs no Node.js):
 *   cd tools/interop && npm install baileys
 *   node gen-curve-vectors.mjs /tmp/curve-vectors.json
 */
import { writeFileSync } from 'fs'
import * as curve from 'libsignal/src/curve'
import { randomBytes } from 'crypto'

const out = { cases: [] }

for (let i = 0; i < 5; i++) {
	const { pubKey, privKey } = curve.generateKeyPair()
	const message = randomBytes(20 + i * 7)
	const signature = curve.calculateSignature(privKey, message)
	// double check the reference itself
	const ok = curve.verifySignature(pubKey, message, signature)
	if (!ok) throw new Error('reference signature did not verify')
	out.cases.push({
		priv: Buffer.from(privKey).toString('hex'),
		pub: Buffer.from(pubKey).toString('hex'),
		msg: Buffer.from(message).toString('hex'),
		sig: Buffer.from(signature).toString('hex')
	})
}

// DH agreement vectors (33-byte prefixed public keys are what WA uses)
const a = curve.generateKeyPair()
const b = curve.generateKeyPair()
out.dh = {
	aPriv: Buffer.from(a.privKey).toString('hex'),
	aPub: Buffer.from(a.pubKey).toString('hex'),
	bPriv: Buffer.from(b.privKey).toString('hex'),
	bPub: Buffer.from(b.pubKey).toString('hex'),
	sharedAB: Buffer.from(curve.calculateAgreement(b.pubKey, a.privKey)).toString('hex'),
	sharedBA: Buffer.from(curve.calculateAgreement(a.pubKey, b.privKey)).toString('hex')
}

writeFileSync(process.argv[2] || '/tmp/curve-vectors.json', JSON.stringify(out, null, 1))
console.log('wrote', out.cases.length, 'signature cases')
