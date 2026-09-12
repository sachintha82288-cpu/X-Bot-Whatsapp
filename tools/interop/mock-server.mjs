/**
 * A fake WhatsApp server used to test the Python client end to end.
 *
 * It speaks the real wire protocol (WebSocket + Noise XX + binary nodes) and
 * uses Baileys' own primitives (node codec, protobufs, crypto) plus libsignal
 * for the E2E layer, so every byte the Python client sends has to be exactly
 * what WhatsApp expects.
 *
 * Scenario:
 *   1. accept the registration payload the client sends after the handshake
 *   2. reply with a <pair-success> built with the client's advSecretKey
 *   3. send <success> so the client uploads its pre-keys
 *   4. serve pre-key bundles + USync device lists
 *   5. decrypt the text message the client sends and hand it a reply
 *
 * Environment:
 *   MOCK_PORT        port to listen on              (default 8899)
 *   MOCK_ADV_SECRET  the client's advSecretKey (base64)
 */
import { WebSocketServer } from 'ws'
import * as WB from 'baileys/lib/WABinary/index.js'
import { Curve, hkdf, sha256, aesEncryptGCM, aesDecryptGCM, hmacSign } from 'baileys/lib/Utils/crypto.js'
import * as Defaults from 'baileys/lib/Defaults/index.js'
import { unpadRandomMax16, writeRandomPadMax16, encodeBigEndian } from 'baileys/lib/Utils/generics.js'
import WAProtoModule from 'baileys/WAProto/index.js'

import libsignalModule from 'libsignal'

const proto = WAProtoModule.proto ?? WAProtoModule.default?.proto ?? WAProtoModule
const libsignal = libsignalModule.default ?? libsignalModule
const KeyHelper = libsignal.keyhelper
const { ProtocolAddress, SessionCipher, SessionRecord } = libsignal

const NOISE_HEADER = Buffer.from(Defaults.NOISE_WA_HEADER)
const NOISE_MODE = Buffer.from(Defaults.NOISE_MODE)
const PORT = Number(process.env.MOCK_PORT || 0)
const ADV_SECRET = process.env.MOCK_ADV_SECRET || ''
const USER_NUMBER = process.env.MOCK_NUMBER || '15550001111'
const CLIENT_JID = `${USER_NUMBER}:1@s.whatsapp.net`
const PHONE_JID = `${USER_NUMBER}:0@s.whatsapp.net`
const PEER_USER = process.env.MOCK_PEER || '15551234567'
const PEER_JID = `${PEER_USER}:0@s.whatsapp.net`
const CLIENT_LID = '99887766554433@lid'
const EXPECTED_TEXT = process.env.MOCK_EXPECT || 'ping from python'

const log = (event, data = {}) => console.log(JSON.stringify({ event, ...data }))
const fail = message => {
	console.log(JSON.stringify({ event: 'FAIL', message }))
	process.exit(1)
}

// ---------------------------------------------------------------------------
// Noise responder (mirror image of the client side)
// ---------------------------------------------------------------------------
class Transport {
	constructor(encKey, decKey) {
		this.encKey = encKey
		this.decKey = decKey
		this.writeCounter = 0
		this.readCounter = 0
	}
	iv(counter) {
		const iv = Buffer.alloc(12)
		iv.writeUInt32BE(counter >>> 0, 8)
		return iv
	}
	encrypt(plaintext) {
		return aesEncryptGCM(plaintext, this.encKey, this.iv(this.writeCounter++), Buffer.alloc(0))
	}
	decrypt(ciphertext) {
		return aesDecryptGCM(ciphertext, this.decKey, this.iv(this.readCounter++), Buffer.alloc(0))
	}
}

class NoiseResponder {
	constructor({ staticKeyPair, caKeyPair, caSerial }) {
		this.staticKeyPair = staticKeyPair
		this.caKeyPair = caKeyPair
		this.caSerial = caSerial
		this.intermediateKeyPair = Curve.generateKeyPair()
		this.hash = NOISE_MODE.length === 32 ? NOISE_MODE : sha256(NOISE_MODE)
		this.salt = this.hash
		this.encKey = this.hash
		this.decKey = this.hash
		this.counter = 0
		this.transport = null
		this.authenticate(NOISE_HEADER)
	}
	authenticate(data) {
		if (!this.transport) this.hash = sha256(Buffer.concat([this.hash, data]))
	}
	iv(counter) {
		const iv = Buffer.alloc(12)
		iv.writeUInt32BE(counter >>> 0, 8)
		return iv
	}
	encrypt(plaintext) {
		if (this.transport) return this.transport.encrypt(plaintext)
		const result = aesEncryptGCM(plaintext, this.encKey, this.iv(this.counter++), this.hash)
		this.authenticate(result)
		return result
	}
	decrypt(ciphertext) {
		if (this.transport) return this.transport.decrypt(ciphertext)
		const result = aesDecryptGCM(ciphertext, this.decKey, this.iv(this.counter++), this.hash)
		this.authenticate(ciphertext)
		return result
	}
	localHKDF(data) {
		const key = hkdf(Buffer.from(data), 64, { salt: this.salt, info: '' })
		return [key.subarray(0, 32), key.subarray(32)]
	}
	mixIntoKey(data) {
		const [write, read] = this.localHKDF(data)
		this.salt = write
		this.encKey = read
		this.decKey = read
		this.counter = 0
	}
	finishInit() {
		const [write, read] = this.localHKDF(Buffer.alloc(0))
		// what the client writes is what the server reads
		this.transport = new Transport(read, write)
	}
	hello() {
		const ephemeral = Curve.generateKeyPair()
		this.ephemeral = ephemeral
		this.authenticate(ephemeral.public)
		if (process.env.MOCK_DEBUG) log('hash-ee', { hash: Buffer.from(this.hash).toString('hex'), salt: Buffer.from(this.salt).toString('hex') })
		this.mixIntoKey(Curve.sharedKey(ephemeral.private, this.clientEphemeral))
		if (process.env.MOCK_DEBUG) log('after-ee', { salt: Buffer.from(this.salt).toString('hex'), enc: Buffer.from(this.encKey).toString('hex') })
		const staticEnc = this.encrypt(this.staticKeyPair.public)
		this.mixIntoKey(Curve.sharedKey(this.staticKeyPair.private, this.clientEphemeral))
		const payload = this.encrypt(this.certificateChain())
		if (process.env.MOCK_DEBUG) log('hello-built', { hash: Buffer.from(this.hash).toString('hex'), staticHex: Buffer.from(staticEnc).toString('hex'), payloadHex: Buffer.from(payload).toString('hex') })
		return proto.HandshakeMessage.encode({
			serverHello: { ephemeral: ephemeral.public, static: staticEnc, payload }
		}).finish()
	}
	certificateChain() {
		const leafDetails = proto.CertChain.NoiseCertificate.Details.encode({
			issuerSerial: this.caSerial,
			key: this.staticKeyPair.public,
			notBefore: 0,
			notAfter: 0
		}).finish()
		const leaf = {
			details: leafDetails,
			signature: Curve.sign(this.intermediateKeyPair.private, leafDetails)
		}
		const intermediateDetails = proto.CertChain.NoiseCertificate.Details.encode({
			issuerSerial: this.caSerial,
			key: this.intermediateKeyPair.public,
			notBefore: 0,
			notAfter: 0
		}).finish()
		const intermediate = {
			details: intermediateDetails,
			signature: Curve.sign(this.caKeyPair.private, intermediateDetails)
		}
		return proto.CertChain.encode({ leaf, intermediate }).finish()
	}
}

const frame = payload => {
	const out = Buffer.alloc(3 + payload.length)
	out.writeUIntBE(payload.length, 0, 3)
	payload.copy(out, 3)
	return out
}

// ---------------------------------------------------------------------------
// libsignal storage for the fake phone
// ---------------------------------------------------------------------------
class MockStorage {
	constructor({ identityKeyPair, registrationId, preKeys, signedPreKeys }) {
		this.identityKeyPair = identityKeyPair
		this.registrationId = registrationId
		this.preKeys = preKeys
		this.signedPreKeys = signedPreKeys
		this.sessions = {}
	}
	async getOurIdentity() {
		return this.identityKeyPair
	}
	async getOurRegistrationId() {
		return this.registrationId
	}
	async getLocalRegistrationId() {
		return this.registrationId
	}
	async isTrustedIdentity() {
		return true
	}
	async loadSession(id) {
		return this.sessions[id] ? SessionRecord.deserialize(this.sessions[id]) : new SessionRecord()
	}
	async storeSession(id, record) {
		this.sessions[id] = record.serialize()
	}
	async loadPreKey(id) {
		return this.preKeys[id]
	}
	async removePreKey(id) {
		delete this.preKeys[id]
	}
	async loadSignedPreKey(id) {
		return this.signedPreKeys[id]
	}
	async loadSignedPreKeys() {
		return Object.values(this.signedPreKeys)
	}
	async storePreKey(id, keyPair) {
		this.preKeys[id] = keyPair
	}
	async storeSignedPreKey(id, keyPair) {
		this.signedPreKeys[id] = keyPair
	}
}

const addressOf = jid => {
	const [userPart] = jid.split('@')
	const [user, device] = userPart.split(':')
	return new ProtocolAddress(user, Number(device || 0))
}

// ---------------------------------------------------------------------------
// server state
// ---------------------------------------------------------------------------
const phoneIdentity = await KeyHelper.generateIdentityKeyPair()
const phoneRegistrationId = await KeyHelper.generateRegistrationId()
const phoneSignedPreKey = await KeyHelper.generateSignedPreKey(phoneIdentity, 7)
const phonePreKey = await KeyHelper.generatePreKey(1234)
const accountKeyPair = Curve.generateKeyPair()
const caKeyPair = Curve.generateKeyPair()

const keyMaterial = {
	identityKeyPair: phoneIdentity,
	registrationId: phoneRegistrationId,
	preKeys: { [phonePreKey.keyId]: phonePreKey.keyPair },
	signedPreKeys: { [phoneSignedPreKey.keyId]: phoneSignedPreKey.keyPair }
}
// the fake server plays two identities (the linked phone and the chat peer),
// so each one keeps its own sessions
const phoneStorage = new MockStorage(keyMaterial)
const peerStorage = new MockStorage({
	...keyMaterial,
	preKeys: { ...keyMaterial.preKeys },
	signedPreKeys: { ...keyMaterial.signedPreKeys }
})

const server = new WebSocketServer({ port: PORT, host: '127.0.0.1' })

server.on('listening', () => {
	log('listening', {
		port: server.address().port,
		phone: PHONE_JID,
		client: CLIENT_JID,
		peer: PEER_JID,
		caPublicKey: caKeyPair.public.toString('base64')
	})
})

server.on('connection', socket => {
	let buffer = Buffer.alloc(0)
	let stage = 'header'
	let noise = null
	const seen = { clientPayload: null, incoming: null, replySent: false, receipts: 0, acks: 0 }

	const sendFrame = payload => socket.send(frame(payload))
	const sendNode = node => {
		const encoded = WB.encodeBinaryNode(node)
		if (process.env.MOCK_DEBUG && noise.transport) log('transport-send', { tag: node.tag, writeCounter: noise.transport.writeCounter })
		sendFrame(noise.transport ? noise.transport.encrypt(encoded) : encoded)
	}

	const result = (node, content) =>
		sendNode({ tag: 'iq', attrs: { id: node.attrs.id, type: 'result', to: 's.whatsapp.net' }, content })

	const finish = () => {
		log('RESULT', {
			registered: !!seen.clientPayload?.devicePairingData,
			preKeysUploaded: seen.preKeysUploaded || 0,
			incoming: seen.incoming,
			replySent: seen.replySent,
			acks: seen.acks,
			receipts: seen.receipts
		})
		process.exit(0)
	}

	const decryptEnc = async (jid, enc) => {
		const user0 = jid.split('@')[0].split(':')[0]
		const storage = user0 === USER_NUMBER ? phoneStorage : peerStorage
		// in libsignal a session always belongs to the *peer* of this device
		const cipher = new SessionCipher(storage, addressOf(CLIENT_JID))
		const body = Buffer.from(enc.content)
		let plaintext
		if (enc.attrs.type === 'pkmsg') {
			plaintext = await cipher.decryptPreKeyWhisperMessage(body, 'binary')
		} else if (enc.attrs.type === 'msg') {
			plaintext = await cipher.decryptWhisperMessage(body, 'binary')
		} else {
			throw new Error(`unsupported enc type ${enc.attrs.type}`)
		}
		return proto.Message.decode(unpadRandomMax16(plaintext))
	}

	const inspectMessage = async node => {
		const info = { id: node.attrs.id, to: node.attrs.to, parts: [] }
		for (const child of node.content || []) {
			if (child.tag === 'participants') {
				for (const to of child.content) {
					try {
						const message = await decryptEnc(to.attrs.jid, to.content[0])
						const inner = message.deviceSentMessage?.message
						info.parts.push({
							jid: to.attrs.jid,
							type: to.content[0].attrs.type,
							text: message.conversation || inner?.conversation || null,
							dsm: !!message.deviceSentMessage,
							destination: message.deviceSentMessage?.destinationJid || null
						})
					} catch (error) {
						info.parts.push({ jid: to.attrs.jid, error: String(error) })
					}
				}
			} else if (child.tag === 'enc') {
				info.group = { type: child.attrs.type, length: child.content.length }
			}
		}
		return info
	}

	const sendText = async (jid, text) => {
		const padded = writeRandomPadMax16(proto.Message.encode({ conversation: text }).finish())
		// we impersonate the peer: the session lives on the peer's side of the client
		const cipher = new SessionCipher(peerStorage, addressOf(CLIENT_JID))
		const raw = await cipher.encrypt(padded)
		const ciphertext = raw && raw.body ? Buffer.from(raw.body) : Buffer.from(raw)
		const type = ciphertext[0] === 0x33 ? 'msg' : 'msg'
		sendNode({
			tag: 'message',
			attrs: {
				id: '3EB0' + Math.random().toString(16).slice(2, 14).toUpperCase(),
				from: PEER_JID,
				to: CLIENT_JID,
				type: 'text',
				t: String(Math.floor(Date.now() / 1000)),
				notify: 'Fake Phone'
			},
			content: [{ tag: 'enc', attrs: { v: '2', type }, content: ciphertext }]
		})
		seen.replySent = true
		setTimeout(finish, 1500)
	}

	const handleNode = async node => {
		if (node.tag === 'ack') {
			seen.acks += 1
			return
		}
		if (node.tag === 'receipt') {
			seen.receipts += 1
			return
		}
		if (node.tag === 'message') {
			seen.incoming = await inspectMessage(node)
			// ack it like WhatsApp does
			sendNode({ tag: 'ack', attrs: { id: node.attrs.id, to: node.attrs.from, class: 'message', from: CLIENT_JID } })
			await sendText(PEER_JID, 'pong from the fake phone')
			return
		}
		if (node.tag !== 'iq') {
			log('unhandled-node', { node: JSON.parse(JSON.stringify(node)) })
			return
		}
		const child = node.content?.[0]
		const xmlns = node.attrs.xmlns
		if (xmlns === 'encrypt' && node.attrs.type === 'get') {
			if (child?.tag === 'count') {
				result(node, [{ tag: 'count', attrs: { value: '900' } }])
				return
			}
			if (child?.tag === 'key') {
				const users = child.content.filter(item => item.tag === 'user')
				result(node, [{
					tag: 'list',
					attrs: {},
					content: users.map(user => ({
						tag: 'user',
						attrs: { jid: user.attrs.jid },
						content: [
							{ tag: 'registration', attrs: {}, content: encodeBigEndian(phoneRegistrationId, 4) },
							{ tag: 'identity', attrs: {}, content: phoneIdentity.pubKey },
							{ tag: 'skey', attrs: {}, content: [
								{ tag: 'id', attrs: {}, content: encodeBigEndian(phoneSignedPreKey.keyId, 3) },
								{ tag: 'value', attrs: {}, content: phoneSignedPreKey.keyPair.pubKey },
								{ tag: 'signature', attrs: {}, content: phoneSignedPreKey.signature }
							] },
							{ tag: 'key', attrs: {}, content: [
								{ tag: 'id', attrs: {}, content: encodeBigEndian(phonePreKey.keyId, 3) },
								{ tag: 'value', attrs: {}, content: phonePreKey.keyPair.pubKey }
							] }
						]
					}))
				}])
				return
			}
		}
		if (xmlns === 'encrypt' && node.attrs.type === 'set') {
			const listNode = (node.content || []).find(item => item.tag === 'list')
			seen.preKeysUploaded = listNode ? listNode.content.length : 0
			result(node, [])
			return
		}
		if (xmlns === 'usync') {
			const usync = node.content.find(item => item.tag === 'usync')
			const list = usync.content.find(item => item.tag === 'list')
			const users = list.content.map(user => {
				const user0 = user.attrs.jid.split('@')[0].split(':')[0]
				const devices = user0 === PEER_USER ? [0] : [0, 1]
				return {
					tag: 'user',
					attrs: { jid: user.attrs.jid },
					content: [{
						tag: 'devices',
						attrs: {},
						content: [{ tag: 'device-list', attrs: {}, content: devices.map(id => ({ tag: 'device', attrs: { id: String(id), 'key-index': String(id + 1) } })) }]
					}]
				}
			})
			result(node, [{ tag: 'usync', attrs: {}, content: [{ tag: 'list', attrs: {}, content: users }] }])
			return
		}
		if (node.attrs.type === 'set' || node.attrs.type === 'get') {
			result(node, [])
			return
		}
		log('unhandled-iq', { node: JSON.parse(JSON.stringify(node)) })
	}

	const handleTransport = async payload => {
		// decodeBinaryNode is async in Baileys v7
		const node = await WB.decodeBinaryNode(payload)
		await handleNode(node)
	}

	const processBuffer = async () => {
		while (true) {
			if (stage === 'header') {
				if (buffer.length < NOISE_HEADER.length + 3) return
				if (!buffer.subarray(0, NOISE_HEADER.length).equals(NOISE_HEADER)) {
					fail(`unexpected prologue: ${buffer.subarray(0, 8).toString('hex')}`)
				}
				buffer = buffer.subarray(NOISE_HEADER.length)
				stage = 'hello'
				continue
			}
			if (buffer.length < 3) return
			const size = buffer.readUIntBE(0, 3)
			if (buffer.length < size + 3) return
			const payload = buffer.subarray(3, size + 3)
			buffer = buffer.subarray(size + 3)

			if (stage === 'hello') {
				const message = proto.HandshakeMessage.decode(payload)
				if (!message.clientHello) fail('expected a clientHello')
				noise = new NoiseResponder({ staticKeyPair: Curve.generateKeyPair(), caKeyPair, caSerial: 0 })
				noise.clientEphemeral = message.clientHello.ephemeral
				noise.authenticate(message.clientHello.ephemeral)
				const helloFrame = noise.hello()
				sendFrame(helloFrame)
				if (process.env.MOCK_DEBUG) log('hello-sent', { length: helloFrame.length })
				stage = 'finish'
				continue
			}
			if (stage === 'finish') {
				const message = proto.HandshakeMessage.decode(payload)
				if (!message.clientFinish) fail('expected a clientFinish')
				if (process.env.MOCK_DEBUG) log('server pre-clientStatic', { hash: Buffer.from(noise.hash).toString('hex'), dec: Buffer.from(noise.decKey).toString('hex'), counter: noise.counter, ct: Buffer.from(message.clientFinish.static).toString('hex').slice(0, 32) })
				const clientStatic = noise.decrypt(message.clientFinish.static)
				// "se": the client's static key against our ephemeral key
				noise.mixIntoKey(Curve.sharedKey(noise.ephemeral.private, clientStatic))
				const clientPayload = proto.ClientPayload.decode(noise.decrypt(message.clientFinish.payload))
				seen.clientPayload = proto.ClientPayload.toObject(clientPayload)
				log('client-payload', { registered: !!clientPayload.devicePairingData, username: clientPayload.username })
				noise.finishInit()
				stage = 'transport'
				onLogin(clientPayload)
				continue
			}
			if (process.env.MOCK_DEBUG) log('transport-recv', { readCounter: noise.transport.readCounter })
			const plaintext = noise.transport.decrypt(payload)
			await handleTransport(plaintext)
		}
	}

	socket.on('message', data => {
		if (process.env.MOCK_DEBUG) log('recv-bytes', { stage, length: data.length, head: data.subarray(0, 8).toString('hex') })
		buffer = Buffer.concat([buffer, data])
		processBuffer().catch(error => fail(`frame processing failed: ${error.stack || error}`))
	})
	socket.on('error', error => fail(`socket error: ${error}`))

	const onLogin = payload => {
		if (payload.devicePairingData) {
			const eIdent = Buffer.from(payload.devicePairingData.eIdent)
			const deviceDetails = proto.ADVDeviceIdentity.encode({
				rawId: 123456,
				timestamp: Math.floor(Date.now() / 1000),
				keyIndex: 5
			}).finish()
			const accountSignature = Curve.sign(
				accountKeyPair.private,
				Buffer.concat([Buffer.from([6, 0]), deviceDetails, eIdent])
			)
			const account = proto.ADVSignedDeviceIdentity.encode({
				details: deviceDetails,
				accountSignatureKey: accountKeyPair.public,
				accountSignature
			}).finish()
			const hmac = hmacSign(account, Buffer.from(ADV_SECRET, 'base64'))
			const deviceIdentity = proto.ADVSignedDeviceIdentityHMAC.encode({ details: account, hmac }).finish()
			sendNode({
				tag: 'iq',
				attrs: { id: 'pair-' + Date.now(), type: 'set', to: 's.whatsapp.net' },
				content: [{
					tag: 'pair-success',
					attrs: {},
					content: [
						{ tag: 'device-identity', attrs: {}, content: deviceIdentity },
						{ tag: 'device', attrs: { jid: CLIENT_JID, lid: CLIENT_LID } },
						{ tag: 'platform', attrs: { name: 'smba' } }
					]
				}]
			})
			setTimeout(() => sendNode({
				tag: 'success',
				attrs: { lid: CLIENT_LID, t: String(Math.floor(Date.now() / 1000)) }
			}), 400)
			return
		}
		sendNode({ tag: 'success', attrs: { lid: CLIENT_LID, t: String(Math.floor(Date.now() / 1000)) } })
	}
})

setTimeout(() => fail('timed out waiting for the client scenario'), 60000)
