/**
 * Protobuf interop check: encodes WhatsApp payloads with Baileys' generated
 * protobuf classes and dumps both the object and the encoded hex so the
 * pure-Python codec can be compared.
 *
 * Usage: node proto-interop.mjs <out.json> [python-encoded.json]
 */
import { writeFileSync, readFileSync } from 'fs'
import proto from 'baileys/WAProto/index.js'
const p = proto?.proto ?? proto
import { randomBytes } from 'crypto'

const key = randomBytes(32)
const cases = [
	['SignalMessage', { ratchetKey: key, counter: 7, previousCounter: 0, ciphertext: randomBytes(40) }],
	['PreKeySignalMessage', { registrationId: 1234, preKeyId: 5, signedPreKeyId: 6, baseKey: key, identityKey: randomBytes(33), message: randomBytes(60) }],
	['SenderKeyMessage', { id: 987654, iteration: 3, ciphertext: randomBytes(48) }],
	['SenderKeyDistributionMessage', { id: 42, iteration: 0, chainKey: key, signingKey: randomBytes(33) }],
	['Message', { conversation: 'hello world' }],
	['Message', { extendedTextMessage: { text: 'hi there', contextInfo: { stanzaId: 'ABC123', participant: '94771234567@s.whatsapp.net' } } }],
	['Message', { imageMessage: { url: 'https://mmg.whatsapp.net/x', mimetype: 'image/jpeg', fileSha256: randomBytes(32), fileLength: 12345, height: 100, width: 200, mediaKey: key, fileEncSha256: randomBytes(32), directPath: '/v/t62/x', mediaKeyTimestamp: 1699999999, jpegThumbnail: randomBytes(500) } }],
	['Message', { senderKeyDistributionMessage: { groupId: '1203630@g.us', axolotlSenderKeyDistributionMessage: randomBytes(70) } }],
	['ClientPayload', { connectType: 1, connectReason: 1, passive: true, pull: true, username: 94771234567, device: 12, userAgent: { platform: 1, releaseChannel: 0, appVersion: { primary: 2, secondary: 3000, tertiary: 1029 } } }],
	['ClientPayload', { connectType: 1, connectReason: 1, passive: false, pull: false, devicePairingData: { eRegid: Buffer.from([0, 0, 0, 1]), eKeytype: Buffer.from([5]), eIdent: randomBytes(32), eSkeyId: Buffer.from([0, 0, 5]), eSkeyVal: randomBytes(32), eSkeySig: randomBytes(64), buildHash: randomBytes(16), deviceProps: randomBytes(30) } }],
	['WebMessageInfo', { key: { remoteJid: '94771234567@s.whatsapp.net', fromMe: true, id: 'X1', participant: undefined }, message: { conversation: 'yo' }, messageTimestamp: 1700000000, status: 2 }],
	['DeviceProps', { os: 'X-Bot', platformType: 1, requireFullSync: true, historySyncConfig: { storageQuotaMb: 10240, inlineInitialPayloadInE2EeMsg: true } }],
	['Message', { reactionMessage: { key: { remoteJid: 'x@s.whatsapp.net', fromMe: false, id: 'M1' }, text: '❤️', groupingKey: 'k' } }],
	['Message', { locationMessage: { degreesLatitude: -7.123456, degreesLongitude: 110.987654, name: 'somewhere' } }],
	['Message', { pollCreationMessage: { name: 'vote?', options: [{ optionName: 'a' }, { optionName: 'b' }], selectableOptionsCount: 1 } }],
	['Message', { stickerMessage: { url: 'https://mmg.whatsapp.net/s', fileSha256: randomBytes(32), fileEncSha256: randomBytes(32), mediaKey: key, mimetype: 'image/webp', height: 512, width: 512, isAnimated: false, stickerSentTs: 1700000000 } }],
	['IdentityKeyPairStructure', { publicKey: key, privateKey: randomBytes(32) }],
	['RecordStructure', { currentSession: { sessionVersion: 3, localRegistrationId: 555, remoteRegistrationId: 777, rootKey: key, senderChain: { senderRatchetKey: key, senderRatchetKeyPrivate: key, chainKey: { index: 4, key: key } } }, previousSessions: [] }]
]

const encoded = cases.map(([name, obj]) => {
	const Type = p[name]
	if (!Type) throw new Error('unknown proto ' + name)
	const msg = Type.fromObject(obj)
	const bytes = Type.encode(msg).finish()
	// canonical dump from decoding the encoded bytes
	const decoded = Type.decode(bytes).toJSON()
	return { name, bytes: Buffer.from(bytes).toString('hex'), json: decoded }
})

writeFileSync(process.argv[2] || '/tmp/proto-vectors.json', JSON.stringify(encoded, null, 1))
console.log('wrote', encoded.length, 'protobuf vectors')
