const net = require('node:net');
const fs = require('node:fs');
const crypto = require('node:crypto');
const readline = require('node:readline');
const {symmetricEncrypt, symmetricDecrypt, deriveSessionKey} = require('./crypto-helpers');
const {sendFragmented} = require('./send-fragmented');

const args = process.argv.slice(2);
if (args.length < 3) {
  console.error('Використання: node node.js <PORT> <KEY_FILE> <CERT_FILE>');
  process.exit(1);
}

const MY_PORT = parseInt(args[0], 10);
const MY_KEY_FILE = args[1];
const MY_CERT_FILE = args[2];
const MY_NAME = `Node-${MY_PORT}`;

const CA_SERVER_PORT = 9000;
const CA_SERVER_HOST = 'localhost';

const activePeers = new Map();
const seenMessages = new Set();

let serverPrivateKey;
let serverCertificatePem;

try {
  serverPrivateKey = fs.readFileSync(MY_KEY_FILE, 'utf8');
  serverCertificatePem = fs.readFileSync(MY_CERT_FILE, 'utf8');
  console.log(`[${MY_NAME}] Активи завантажено. Порт: ${MY_PORT}`);
} catch (e) {
  console.error(`[${MY_NAME}] Помилка завантаження файлів:`, e.message);
  process.exit(1);
}

function broadcastMessage(originalMsgObj, excludeSocket = null) {
  if (!seenMessages.has(originalMsgObj.id)) {
    seenMessages.add(originalMsgObj.id);
  }

  console.log(`[${MY_NAME}] Маршрутизація повідомлення ${originalMsgObj.id} до ${activePeers.size} пірів...`);

  for (const [peerSocket, peerData] of activePeers) {
    if (peerSocket === excludeSocket) continue;

    try {
      const encryptedContent = symmetricEncrypt(JSON.stringify(originalMsgObj), peerData.key);

      const packet = JSON.stringify({type: 'broadcast', message: encryptedContent}) + '\n';

      sendFragmented(peerSocket, packet, `[${MY_NAME}->${peerData.name}]`);
    } catch (e) {
      console.error(`Помилка відправки до ${peerData.name}:`, e.message);
    }
  }
}

const server = net.createServer((socket) => {
  const session = {clientRandom: null, serverRandom: null, premasterSecret: null, sessionKey: null};

  socket.once('data', (data) => { // Етап 1: Client Hello
    try {
      const hello = JSON.parse(data.toString());
      session.clientRandom = Buffer.from(hello.clientRandom, 'base64');

      session.serverRandom = crypto.randomBytes(32);
      socket.write(JSON.stringify({
        serverRandom: session.serverRandom.toString('base64'),
        certificatePem: serverCertificatePem
      })); // Етап 2

      socket.once('data', (premasterData) => { // Етап 4: Premaster
        const msg = JSON.parse(premasterData.toString());
        session.premasterSecret = crypto.privateDecrypt(serverPrivateKey, Buffer.from(msg.encryptedPremaster, 'base64'));
        session.sessionKey = deriveSessionKey(session.clientRandom, session.serverRandom, session.premasterSecret); // Етап 5

        const readyMsg = symmetricEncrypt(`${MY_NAME}: Finished`, session.sessionKey);
        socket.write(JSON.stringify({type: 'ready', message: readyMsg})); // Етап 6

        // Етап 7: Чат
        setupSecureChannel(socket, session.sessionKey, 'Inbound');
      });
    } catch (e) {
      console.error('Server Handshake Error:', e.message);
      socket.destroy();
    }
  });
});

server.listen(MY_PORT, () => console.log(`[${MY_NAME}] Сервер слухає...`));

// --- ЛОГІКА КЛІЄНТА ---
function connectToPeer(host, port) {
  const client = new net.Socket();
  const session = {clientRandom: null, serverRandom: null, premasterSecret: null, sessionKey: null};

  client.connect(port, host, () => {
    session.clientRandom = crypto.randomBytes(32);
    client.write(JSON.stringify({clientRandom: session.clientRandom.toString('base64')})); // Етап 1

    client.once('data', (data) => { // Етап 2: Server Hello
      const hello = JSON.parse(data.toString());
      session.serverRandom = Buffer.from(hello.serverRandom, 'base64');

      // Етап 3: Перевірка через CA
      const caSocket = new net.Socket();
      caSocket.connect(CA_SERVER_PORT, CA_SERVER_HOST, () => caSocket.write(hello.certificatePem));

      caSocket.once('data', (validity) => {
        caSocket.end();
        if (validity.toString() !== 'VALID') {
          client.destroy();
          return console.error('CA validation failed');
        }

        // Етап 4
        session.premasterSecret = crypto.randomBytes(32);
        const srvCert = new crypto.X509Certificate(hello.certificatePem);
        const encPremaster = crypto.publicEncrypt(srvCert.publicKey, session.premasterSecret);
        client.write(JSON.stringify({encryptedPremaster: encPremaster.toString('base64')}));

        // Етап 5
        session.sessionKey = deriveSessionKey(session.clientRandom, session.serverRandom, session.premasterSecret);

        // Етап 6
        client.once('data', (readyData) => {
          const readyMsg = JSON.parse(readyData.toString());
          const decrypted = symmetricDecrypt(readyMsg.message, session.sessionKey);

          if (decrypted.endsWith(': Finished')) {
            const peerName = decrypted.split(':')[0];

            console.log(`\n [${MY_NAME}] З'єднання встановлено з ${peerName} (Outbound)`);
            activePeers.set(client, {key: session.sessionKey, name: peerName});

            const myReady = symmetricEncrypt(`${MY_NAME}: Finished`, session.sessionKey);
            sendFragmented(client, JSON.stringify({type: 'ready', message: myReady}) + '\n', '[Me]');

            setupSecureChannel(client, session.sessionKey, 'Outbound');
          }
        });
      });
    });
  });
}

function setupSecureChannel(socket, key, type) {
  let buffer = '';
  let peerName = 'Unknown Peer';

  socket.on('data', (chunk) => {
    buffer += chunk.toString();
    let idx;
    while ((idx = buffer.indexOf('\n')) !== -1) {
      const jsonStr = buffer.substring(0, idx);
      buffer = buffer.substring(idx + 1);
      if (!jsonStr) continue;

      try {
        const packet = JSON.parse(jsonStr);
        const decrypted = symmetricDecrypt(packet.message, key);

        // Обробка рукостискання "Finished" для отримання імені
        if (packet.type === 'ready') {
          if (decrypted.includes(': Finished')) {
            peerName = decrypted.split(':')[0];
            console.log(`\n [${MY_NAME}] З'єднання встановлено з ${peerName} (${type})`);
            // Додаємо в активні піри
            activePeers.set(socket, {key: key, name: peerName});
          }
        }
        // Обробка звичайного чату
        else if (packet.type === 'chat') {
          console.log(`[Chat from ${peerName}]: ${decrypted}`);
        } else if (packet.type === 'broadcast') {
          const broadcastObj = JSON.parse(decrypted);

          if (seenMessages.has(broadcastObj.id)) {
            return;
          }

          seenMessages.add(broadcastObj.id);
          console.log(`\n [BROADCAST від ${broadcastObj.origin}]: ${broadcastObj.text}`);

          broadcastMessage(broadcastObj, socket);
        }

      } catch (e) {
        console.error('Decryption/Parsing error:', e.message);
      }
    }
  });

  socket.on('close', () => {
    console.log(`З'єднання з ${peerName} розірвано.`);
    activePeers.delete(socket);
  });

  socket.on('error', () => {
  });
}

const rl = readline.createInterface({input: process.stdin, output: process.stdout});
rl.on('line', (line) => {
  const [cmd, arg1, ...rest] = line.trim().split(' ');

  if (cmd === 'connect' && arg1) {
    connectToPeer('localhost', parseInt(arg1));
  } else if (cmd === 'broadcast') {
    const msgId = crypto.randomUUID();
    const text = [arg1, ...rest].join(' ');

    const broadcastObj = {
      id: msgId,
      origin: MY_NAME,
      text: text
    };

    console.log(`[${MY_NAME}] Починаю бродкаст: "${text}"`);
    broadcastMessage(broadcastObj);
  }
});

console.log(`[${MY_NAME}] Готовий. Команди: 'connect <port>', 'broadcast <text>'`);