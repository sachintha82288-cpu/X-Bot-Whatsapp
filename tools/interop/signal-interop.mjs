/**
 * Signal-protocol interop harness.
 *
 * Uses the *real* reference implementation (libsignal-node, the very package
 * Baileys/WhatsApp-compatible clients use) as an oracle for the pure-Python
 * implementation in this repository.
 *
 *   node signal-interop.mjs bundle  <out.json>       # make Bob's pre-key bundle
 *   node signal-interop.mjs bob-decrypt <in.json> <out.json>
 *   node signal-interop.mjs bob-encrypt <in.json> <out.json>
 *   node signal-interop.mjs group <in.json> <out.json>
 */
import { readFileSync, writeFileSync } from 'fs'
import { randomBytes } from 'crypto'
import libsignalModule from 'libsignal'
const libsignal = libsignalModule.default ?? libsignalModule
const KeyHelper = libsignal.keyhelper
const { ProtocolAddress, SessionBuilder, SessionCipher, SessionRecord } = libsignal
import { GroupCipher } from 'baileys/lib/Signal/Group/group_cipher.js'
import { SenderKeyName } from 'baileys/lib/Signal/Group/sender-key-name.js'
import { SenderKeyRecord } from 'baileys/lib/Signal/Group/sender-key-record.js'
import { SenderKeyDistributionMessage } from 'baileys/lib/Signal/Group/sender-key-distribution-message.js'
import { generateSenderKey, generateSenderKeyId, generateSenderSigningKey } from 'baileys/lib/Signal/Group/keyhelper.js'

const STATE_FILE = process.env.SIGNAL_STATE || '/tmp/signal-interop-state.json'

const b64 = buf => Buffer.from(buf).toString('base64')
const unb64 = str => Buffer.from(str, 'base64')

// ---------------------------------------------------------------- Bob store
function makeStore(state, identityKeyPair, registrationId) {
	return {
		loadSession: async addr => (state.sessions[addr] ? SessionRecord.deserialize(state.sessions[addr]) : new SessionRecord()),
		storeSession: async (addr, record) => {
			state.sessions[addr] = record.serialize()
		},
		isTrustedIdentity: async () => true,
		loadPreKey: async id => {
			const entry = state.preKeys[String(id)]
			if (!entry) throw new Error('no such prekey ' + id)
			return { pubKey: unb64(entry.pub), privKey: unb64(entry.priv) }
		},
		removePreKey: async id => {
			delete state.preKeys[String(id)]
		},
		loadSignedPreKey: async id => {
			const entry = state.signedPreKeys[String(id)]
			if (!entry) throw new Error('no such signed prekey ' + id)
			return { pubKey: unb64(entry.pub), privKey: unb64(entry.priv) }
		},
		storeSignedPreKey: async (id, kp) => {
			state.signedPreKeys[String(id)] = { pub: b64(kp.pubKey), priv: b64(kp.privKey) }
		},
		loadIdentityKey: async () => unb64(state.identityKey.pub),
		getIdentityKeyPair: async () => identityKeyPair,
		getLocalRegistrationId: async () => registrationId,
		getOurRegistrationId: async () => registrationId,
		getOurIdentity: async () => identityKeyPair,
		saveIdentity: async () => true
	}
}

const loadState = () => JSON.parse(readFileSync(STATE_FILE, 'utf8'))
const saveState = s => writeFileSync(STATE_FILE, JSON.stringify(s))

const mode = process.argv[2]

if (mode === 'bundle') {
	const identityKeyPair = KeyHelper.generateIdentityKeyPair()
	const registrationId = KeyHelper.generateRegistrationId()
	const preKeyId = 31337
	const signedPreKeyId = 22
	const preKeys = {}
	const savedPre = KeyHelper.generatePreKey(preKeyId)
	preKeys[String(preKeyId)] = { pub: b64(savedPre.keyPair.pubKey), priv: b64(savedPre.keyPair.privKey) }
	const signed = KeyHelper.generateSignedPreKey(identityKeyPair, signedPreKeyId)

	const state = {
		identityKey: { pub: b64(identityKeyPair.pubKey), priv: b64(identityKeyPair.privKey) },
		registrationId,
		preKeys,
		signedPreKeys: { [String(signedPreKeyId)]: { pub: b64(signed.keyPair.pubKey), priv: b64(signed.keyPair.privKey) } },
		signatures: { [String(signedPreKeyId)]: b64(signed.signature) },
		sessions: {}
	}
	saveState(state)

	const out = {
		bob: {
			registrationId,
			deviceId: 1,
			identityKey: b64(identityKeyPair.pubKey),
			signedPreKey: {
				keyId: signedPreKeyId,
				public: b64(signed.keyPair.pubKey),
				signature: b64(signed.signature)
			},
			oneTimePreKey: { keyId: preKeyId, public: b64(savedPre.keyPair.pubKey) },
			// Alice (python) publishes her identity + registration id
			aliceDeviceId: 1
		}
	}
	writeFileSync(process.argv[3], JSON.stringify(out, null, 1))
	console.log('bundle written')
} else if (mode === 'bob-decrypt') {
	const input = JSON.parse(readFileSync(process.argv[3], 'utf8'))
	const state = loadState()
	const identityKeyPair = { pubKey: unb64(state.identityKey.pub), privKey: unb64(state.identityKey.priv) }
	const store = makeStore(state, identityKeyPair, state.registrationId)
	const address = new ProtocolAddress(input.aliceName || 'alice', input.aliceDeviceId || 1)
	const cipher = new SessionCipher(store, address)
	const results = []
	for (const item of input.messages) {
		const body = unb64(item.body)
		let plaintext
		if (item.type === 'pkmsg') {
			plaintext = await cipher.decryptPreKeyWhisperMessage(body, 'binary')
		} else {
			plaintext = await cipher.decryptWhisperMessage(body, 'binary')
		}
		results.push(Buffer.from(plaintext).toString('utf8'))
	}
	saveState(state)

	// send a reply back through the same session
	const replyCipher = new SessionCipher(store, address)
	const reply = await replyCipher.encrypt(Buffer.from('reply from node', 'utf8'))
	saveState(state)
	writeFileSync(process.argv[4], JSON.stringify({
		plaintexts: results,
		reply: { type: reply.type === 3 ? 'pkmsg' : 'msg', body: b64(reply.body) }
	}, null, 1))
	console.log('bob decrypted', results.length, 'messages')
} else if (mode === 'bob-encrypt') {
	const input = JSON.parse(readFileSync(process.argv[3], 'utf8'))
	const state = loadState()
	const identityKeyPair = { pubKey: unb64(state.identityKey.pub), privKey: unb64(state.identityKey.priv) }
	const store = makeStore(state, identityKeyPair, state.registrationId)
	const address = new ProtocolAddress(input.aliceName || 'alice', input.aliceDeviceId || 1)
	const cipher = new SessionCipher(store, address)
	const out = []
	for (const text of input.texts) {
		const msg = await cipher.encrypt(Buffer.from(text, 'utf8'))
		out.push({ type: msg.type === 3 ? 'pkmsg' : 'msg', body: b64(msg.body) })
	}
	saveState(state)
	writeFileSync(process.argv[4], JSON.stringify(out, null, 1))
	console.log('bob encrypted', out.length, 'messages')
} else if (mode === 'group') {
	const input = JSON.parse(readFileSync(process.argv[3], 'utf8'))
	const groupName = input.group || '1203630@g.us'
	const senderName = input.sender || 'bob@s.whatsapp.net'
	const keyStore = {}
	const store = {
		loadSenderKey: async name => keyStore[name.toString()] || new SenderKeyRecord(),
		storeSenderKey: async (name, record) => {
			keyStore[name.toString()] = record
		}
	}
	const senderKeyName = new SenderKeyName(groupName, { id: senderName, deviceId: 1 })
	const cipher = new GroupCipher(store, senderKeyName)

	const out = {}
	if (input.action === 'encrypt') {
		const record = new SenderKeyRecord()
		record.setSenderKeyState(generateSenderKeyId(), 0, generateSenderKey(), generateSenderSigningKey())
		const state = record.getSenderKeyState()
		store.loadSenderKey = async () => record
		const skdm = new SenderKeyDistributionMessage(
			state.getKeyId(), state.getSenderChainKey().getIteration(),
			state.getSenderChainKey().getSeed(), state.getSigningKeyPublic()
		)
		const ciphertext = await cipher.encrypt(Buffer.from(input.text, 'utf8'))
		const ciphertext2 = await cipher.encrypt(Buffer.from(input.text2 || 'second', 'utf8'))
		out.skdm = b64(skdm.serialize())
		out.messages = [b64(ciphertext), b64(ciphertext2)]
	} else if (input.action === 'decrypt') {
		const skdm = new SenderKeyDistributionMessage(null, null, null, null, unb64(input.skdm))
		const record = new SenderKeyRecord()
		record.addSenderKeyState(skdm.getId(), skdm.getIteration(), skdm.getChainKey(), skdm.getSignatureKey())
		keyStore[senderKeyName.toString()] = record
		const plaintexts = []
		for (const body of input.messages) {
			plaintexts.push(Buffer.from(await cipher.decrypt(unb64(body))).toString('utf8'))
		}
		out.plaintexts = plaintexts
	}
	writeFileSync(process.argv[4], JSON.stringify(out, null, 1))
	console.log('group', input.action, 'ok')
} else {
	throw new Error('unknown mode')
}
