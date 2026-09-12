/**
 * Binary-protocol interop check.
 *
 * 1. Encodes a bunch of nodes with Baileys' WABinary -> writes vectors JSON.
 * 2. Reads the Python encoder's output and decodes it with Baileys, dumping
 *    the structures so both implementations can be compared.
 *
 * Usage:
 *   node binary-interop.mjs encode <out.json>
 *   node binary-interop.mjs decode <in.json> <out.json>
 */
import { writeFileSync, readFileSync } from 'fs'
import { encodeBinaryNode, decodeBinaryNode } from 'baileys/lib/WABinary/index.js'
import { randomBytes } from 'crypto'

const nodes = [
	{ tag: 'iq', attrs: { id: '1234', type: 'get', xmlns: 'w:p', to: 's.whatsapp.net' }, content: [{ tag: 'ping', attrs: {} }] },
	{ tag: 'message', attrs: { id: 'ABCD', to: '94771234567@s.whatsapp.net', type: 'text' }, content: [{ tag: 'enc', attrs: { v: '2', type: 'pkmsg' }, content: randomBytes(64) }] },
	{ tag: 'success', attrs: { lid: '12345678@lid', t: '1699999999' } },
	{ tag: 'iq', attrs: { to: 's.whatsapp.net', type: 'set', xmlns: 'encrypt' }, content: [{ tag: 'registration', attrs: {}, content: randomBytes(200) }] },
	{ tag: 'participants', attrs: {}, content: [{ tag: 'to', attrs: { jid: '94771234567:12@s.whatsapp.net' }, content: [{ tag: 'enc', attrs: { v: '2', type: 'msg' }, content: randomBytes(100) }] }] },
	{ tag: 'ib', attrs: {}, content: [{ tag: 'edge_routing', attrs: {}, content: [{ tag: 'routing_info', attrs: {}, content: Buffer.from([8, 2, 8, 5]) }] }] },
	{ tag: 'test', attrs: { a: '0123456789-', b: 'ABCDEF', c: 'true', d: 'hello world', e: '5', f: 'x'.repeat(300) } },
	{ tag: 'big', attrs: { n: '1' }, content: randomBytes(70000) },
	{ tag: 'text', attrs: {}, content: 'plain string content' },
	{ tag: 'empty', attrs: {} },
	{ tag: 'deep', attrs: { x: 'y' }, content: [{ tag: 'a', attrs: {}, content: [{ tag: 'b', attrs: {}, content: [{ tag: 'c', attrs: { d: 'e' }, content: 'f' }] }] }] },
	{ tag: 'g.us', attrs: { jid: '120363012345678901@g.us', addressing_mode: 'lid' } },
	{ tag: 'iq', attrs: { type: 'result', id: 'zz' }, content: [{ tag: 'device-list', attrs: {}, content: [{ tag: 'device', attrs: { id: '0', 'key-index': '12' } }, { tag: 'device', attrs: { id: '33' } }] }] }
]

const dump = n => ({
	tag: n.tag,
	attrs: n.attrs,
	content: n.content === undefined || n.content === null
		? null
		: Array.isArray(n.content)
			? n.content.map(dump)
			: typeof n.content === 'string'
				? n.content
				: { b64: Buffer.from(n.content).toString('base64') }
})

const mode = process.argv[2]
if (mode === 'encode') {
	const out = nodes.map(n => ({ node: dump(n), hex: Buffer.from(encodeBinaryNode(n)).toString('hex') }))
	writeFileSync(process.argv[3], JSON.stringify(out))
	console.log('wrote', out.length, 'binary vectors')
} else if (mode === 'decode') {
	const input = JSON.parse(readFileSync(process.argv[3], 'utf8'))
	const out = []
	for (const hex of input) {
		try {
			out.push(dump(await decodeBinaryNode(Buffer.from(hex, 'hex'))))
		} catch (e) {
			out.push({ error: String(e) })
		}
	}
	writeFileSync(process.argv[4], JSON.stringify(out))
	console.log('decoded', out.length, 'payloads')
} else {
	throw new Error('unknown mode')
}
