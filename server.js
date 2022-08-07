const crypto = require("crypto");
const { createServer } = require("http");
const fs = require("fs");

const HANDSHAKE_MAGIC_STRING = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"; //https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers#server_handshake_response

const PAYLOAD_MARKER_7_BIT = 125;
const PAYLOAD_MARKER_16_BIT = 126;
const PAYLOAD_MARKER_64_BIT = 127;

const MAX_SUPPORTED_LENGTH = Math.pow(2, 16) - 1;

const server = createServer((req, res) => {
	fs.readFile("./index.html", (err, data) => {
		if (err) {
			res.writeHead(500);
			res.end(err);
		}
		res.setHeader("Content-Type", "text/html");
		res.writeHead(200);
		res.end(data.toString("utf8"));
	});
});

const clients = new Map();

server.on("upgrade", (req, socket, head) => {
	const { "sec-websocket-key": webSocketKey } = req.headers;

	// Create a valid handshake key
	const hash = crypto.createHash("sha1");
	hash.update(webSocketKey + HANDSHAKE_MAGIC_STRING);
	const acceptKey = hash.digest("base64");
	const headers = [
		"HTTP/1.1 101 Switching Protocols",
		"Upgrade: websocket",
		"Connection: Upgrade",
		`Sec-WebSocket-Accept: ${acceptKey}`,
		"\r\n",
	].join("\r\n");

	// Setup persistant user
	const user = req.url.split("=")[1];
	if (typeof user === "string" && !user === "null") {
		socket.userId = user;
	} else {
		socket.userId = `u_${crypto.randomBytes(4).toString("hex")}`;
	}

	clients.set(socket.userId, socket);

	// Fullfil handshake request
	socket.write(headers);

	socket.on("close", () => {
		console.log("Closing socket for", socket.userId);
		clients.delete(socket.userId);
	});

	socket.on("readable", () => {
		const recieve = new MessageReciever(socket);

		if (recieve._opcode === 0x08) {
			console.log("Op code is 0x08, closing connection");
			socket.destroy();
		}

		const message = recieve.decode();

		switch (message.type) {
			case "login":
				{
					new MessageSender(socket, { type: "login", userId: socket.userId }).send();
				}
				break;
			case "chat": {
				const { data } = message;
				new MessageSender(socket, { type: "chat", data, userId: socket.userId }).sendToAll();
			}
		}
	});
});

class MessageSender {
	constructor(socket, message) {
		this._socket = socket;
		if (typeof message === "object") {
			message = JSON.stringify(message);
		}
		this._message = message;
	}

	sendToAll() {
		const message = this.encode();
		clients.forEach((socket, userId) => {
			if (userId !== this._socket.userId) {
				socket.write(message);
			}
		});
	}

	send() {
		const message = this.encode();
		this._socket.write(message);
	}

	encode() {
		const messageBuffer = Buffer.from(this._message);
		const payloadLength = messageBuffer.length;
		let offset = 2;

		if (payloadLength >= MAX_SUPPORTED_LENGTH) {
			throw new RangeError("Max supported length reached");
		} else if (payloadLength >= PAYLOAD_MARKER_7_BIT) {
			offset += 2;
		}

		const target = Buffer.allocUnsafe(offset);

		target[0] = 0x80 | 0x01;

		target[1] = payloadLength;

		if (payloadLength === PAYLOAD_MARKER_16_BIT) {
			target.writeUInt16BE(payloadLength, 2);
		}

		const frame = Buffer.allocUnsafe(target.byteLength + messageBuffer.length);
		frame.set(target, 0);
		frame.set(messageBuffer, target.byteLength);
		return frame;
	}
}

class MessageReciever {
	constructor(socket) {
		this._socket = socket;
		const firstFrame = socket.read(1);
		this._fin = (firstFrame[0] & 0x80) === 0x80;
		this._opcode = firstFrame[0] & 0x0f;
		this._payloadLength = this._getPayloadLength();
		this._mask = socket.read(4);
	}

	_getPayloadLength() {
		const [payloadLength] = this._socket.read(1);
		let messageLength = payloadLength & PAYLOAD_MARKER_64_BIT;
		if (messageLength == PAYLOAD_MARKER_16_BIT) {
			messageLength = this._socket.read(2).readUInt16BE(0);
		} else if (messageLength == PAYLOAD_MARKER_64_BIT) {
			throw new RangeError("Max payload length is only 16bits");
		}

		return messageLength;
	}

	_unmask(payload) {
		const PayloadBuffer = Buffer.from(payload);
		for (let i = 0; i < PayloadBuffer.length; i++) {
			PayloadBuffer[i] ^= this._mask[i & 3];
		}
		return PayloadBuffer;
	}

	decode() {
		if (!this._decoded) {
			const payload = this._socket.read(this._payloadLength);
			const buff = this._unmask(payload);
			this._decoded = buff.toString("utf-8");
		}

		try {
			return JSON.parse(this._decoded);
		} catch (error) {
			return {};
		}
	}
}

process.on("unhandledRejection", (e) => {
	console.log("An error occured", e);
});
process.on("uncaughtException", (e) => {
	console.log("An error occured", e);
});

server.listen("4000", () => {
	console.info("Server started at", 4000);
});
