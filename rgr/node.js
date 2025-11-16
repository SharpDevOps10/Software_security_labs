const net = require('node:net');
const fs = require('node:fs');
const crypto = require('node:crypto');
const readline = require('node:readline');
const {symmetricEncrypt, symmetricDecrypt, deriveSessionKey} = require('./crypto-helpers.js');

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

let serverPrivateKey;
let serverCertificatePem;

try {
  serverPrivateKey = fs.readFileSync(MY_KEY_FILE, 'utf8');
  serverCertificatePem = fs.readFileSync(MY_CERT_FILE, 'utf8');
  console.log(`[${MY_NAME}] Активи ${MY_KEY_FILE} / ${MY_CERT_FILE} завантажено.`);
} catch (e) {
  console.error(`[${MY_NAME}] Не вдалося завантажити файли ключів/сертифікатів.`, e.message);
  process.exit(1);
}

const server = net.createServer((socket) => {
  const remoteName = `${socket.remoteAddress}:${socket.remotePort}`;
  console.log(`\n[${MY_NAME}] Нове вхідне з'єднання від ${remoteName}`);

  const session = {
    clientRandom: null, serverRandom: null, premasterSecret: null, sessionKey: null,
  };

  // ЕТАП 1: Отримання "Client Hello"
  socket.once('data', (clientHelloData) => {
    try {
      const clientHello = JSON.parse(clientHelloData.toString());
      session.clientRandom = Buffer.from(clientHello.clientRandom, 'base64');
      console.log(`[${MY_NAME} <- ${remoteName}] Отримав Client Hello.`);

      // ЕТАП 2: Надсилання "Server Hello" + Сертифікат
      session.serverRandom = crypto.randomBytes(32);
      const serverHelloPayload = {
        serverRandom: session.serverRandom.toString('base64'),
        certificatePem: serverCertificatePem,
      };
      socket.write(JSON.stringify(serverHelloPayload));
      console.log(`[${MY_NAME} -> ${remoteName}] Надіслав Server Hello + Cert.`);

      // ЕТАП 4: Отримання "Premaster Secret"
      socket.once('data', (premasterData) => {
        try {
          const premasterMessage = JSON.parse(premasterData.toString());
          const encryptedPremaster = Buffer.from(premasterMessage.encryptedPremaster, 'base64');

          session.premasterSecret = crypto.privateDecrypt(serverPrivateKey, encryptedPremaster);
          console.log(`[${MY_NAME} <- ${remoteName}] Отримав та розшифрував Premaster.`);

          // ЕТАП 5: Генерація ключа сеансу
          session.sessionKey = deriveSessionKey(
            session.clientRandom, session.serverRandom, session.premasterSecret
          );
          console.log(`[${MY_NAME}] Ключ сеансу з ${remoteName} згенеровано.`);

          // ЕТАП 6: "Server Ready"
          const serverReadyMsg = symmetricEncrypt(`${MY_NAME}: Finished`, session.sessionKey);
          socket.write(JSON.stringify({type: 'ready', message: serverReadyMsg}));

          // ЕТАП 7: Захищений канал
          console.log(`\n*** [${MY_NAME}] Рукостискання з ${remoteName} ЗАВЕРШЕНО (Сервер) ***\n`);

          let chatBuffer = '';
          socket.on('data', (encryptedChatData) => {
            chatBuffer += encryptedChatData.toString();

            let newlineIndex;
            while ((newlineIndex = chatBuffer.indexOf('\n')) !== -1) {
              const jsonString = chatBuffer.substring(0, newlineIndex);
              chatBuffer = chatBuffer.substring(newlineIndex + 1);

              if (jsonString) {
                try {
                  const chatMsg = JSON.parse(jsonString);
                  const decrypted = symmetricDecrypt(chatMsg.message, session.sessionKey);
                  console.log(`[${MY_NAME} | ${remoteName} (Зашифровано)] >> ${decrypted}`);

                  const reply = symmetricEncrypt(`${MY_NAME} отримав: "${decrypted}"`, session.sessionKey);
                  socket.write(JSON.stringify({type: 'chat', message: reply}) + '\n');

                } catch (e) {
                  console.error(`[${MY_NAME}] Помилка парсингу JSON з буфера:`, e.message, 'Дані:', jsonString);
                }
              }
            }
          });

        } catch (e) {
          console.error(`[${MY_NAME}] Помилка на етапі 4/5:`, e.message);
          socket.destroy();
        }
      });
    } catch (e) {
      console.error(`[${MY_NAME}] Помилка на етапі 1/2:`, e.message);
      socket.destroy();
    }
  });

  socket.on('error', (err) => console.error(`[${MY_NAME}] Помилка сокета (сервер):`, err.message));
  socket.on('close', () => console.log(`[${MY_NAME}] З'єднання (сервер) з ${remoteName} закрито.`));
});

server.listen(MY_PORT, () => {
  console.log(`[${MY_NAME}] Cервер слухає на порту ${MY_PORT}`);
});

const connectToPeer = (host, port) => {
  const targetName = `${host}:${port}`;
  console.log(`\n[${MY_NAME}] Ініціюю з'єднання з ${targetName}...`);

  const client = new net.Socket();
  const session = {
    clientRandom: null, serverRandom: null, premasterSecret: null, sessionKey: null,
  };

  client.connect(port, host, () => {
    console.log(`[${MY_NAME} -> ${targetName}] TCP-з'єднання встановлено.`);

    // ЕТАП 1: "Client Hello"
    session.clientRandom = crypto.randomBytes(32);
    const clientHello = {clientRandom: session.clientRandom.toString('base64')};
    client.write(JSON.stringify(clientHello));
    console.log(`[${MY_NAME} -> ${targetName}] Надіслав Client Hello.`);

    // ЕТАП 2: Отримання "Server Hello"
    client.once('data', (serverHelloData) => {
      const serverHello = JSON.parse(serverHelloData.toString());
      session.serverRandom = Buffer.from(serverHello.serverRandom, 'base64');
      const certificateFromPeer = serverHello.certificatePem;
      console.log(`[${MY_NAME} <- ${targetName}] Отримав Server Hello + Cert.`);

      // ЕТАП 3: АВТЕНТИФІКАЦІЯ (Звернення до CA-Сервера)
      console.log(`[${MY_NAME}] Починаю ЕТАП 3 (Автентифікація через CA-Сервер)...`);

      const caSocket = new net.Socket();

      caSocket.connect(CA_SERVER_PORT, CA_SERVER_HOST, () => {
        console.log(`[${MY_NAME} -> CA] Підключився до CA-Сервера (порт ${CA_SERVER_PORT}).`);
        caSocket.write(certificateFromPeer);
      });

      caSocket.once('data', (caResponseData) => {
        const caResponse = caResponseData.toString();
        console.log(`[${MY_NAME} <- CA] Отримав відповідь від CA: "${caResponse}"`);
        caSocket.end();

        if (caResponse !== 'VALID') {
          console.error(`[${MY_NAME}] !!! ПЕРЕВІРКА ПРОВАЛЕНА: CA-Сервер відхилив сертифікат ${targetName}. !!!`);
          client.destroy();
          return;
        }

        console.log(`[${MY_NAME}] ...Успіх! CA-Сервер підтвердив сертифікат ${targetName}.`);

        // ЕТАП 4: "Premaster Secret"
        session.premasterSecret = crypto.randomBytes(32);
        const serverCert = new crypto.X509Certificate(certificateFromPeer); // Все одно потрібен для public key

        const encryptedPremaster = crypto.publicEncrypt(
          serverCert.publicKey, session.premasterSecret
        );
        client.write(JSON.stringify({encryptedPremaster: encryptedPremaster.toString('base64')}));
        console.log(`[${MY_NAME} -> ${targetName}] Надіслав зашифрований Premaster.`);

        // ЕТАП 5: Генерація ключа сеансу
        session.sessionKey = deriveSessionKey(
          session.clientRandom, session.serverRandom, session.premasterSecret
        );
        console.log(`[${MY_NAME}] Ключ сеансу з ${targetName} згенеровано.`);

        // ЕТАП 6: Отримання "Server Ready"
        client.once('data', (serverReadyData) => {
          const serverReady = JSON.parse(serverReadyData.toString());
          const decryptedMsg = symmetricDecrypt(serverReady.message, session.sessionKey);

          if (decryptedMsg.endsWith(': Finished')) {
            console.log(`[${MY_NAME} <- ${targetName}] Отримав "Finished": "${decryptedMsg}"`);

            const clientReadyMsg = symmetricEncrypt(`${MY_NAME}: Finished`, session.sessionKey);
            client.write(JSON.stringify({type: 'ready', message: clientReadyMsg}) + '\n');

            console.log(`\n*** [${MY_NAME}] Рукостискання з ${targetName} ЗАВЕРШЕНО (Клієнт) ***\n`);

            const chatMessage = symmetricEncrypt(`Привіт від ${MY_NAME}!`, session.sessionKey);
            client.write(JSON.stringify({type: 'chat', message: chatMessage}) + '\n');

            let chatBuffer = '';
            client.on('data', (encryptedChatData) => {
              chatBuffer += encryptedChatData.toString();

              let newlineIndex;

              while ((newlineIndex = chatBuffer.indexOf('\n')) !== -1) {
                const jsonString = chatBuffer.substring(0, newlineIndex);
                chatBuffer = chatBuffer.substring(newlineIndex + 1);

                if (jsonString) {
                  try {
                    const chatMsg = JSON.parse(jsonString);
                    const decrypted = symmetricDecrypt(chatMsg.message, session.sessionKey);
                    console.log(`[Клієнт] Отримав відповідь: "${decrypted}"`);

                    if (decrypted.includes('Привіт, Сервер!')) {
                      client.end();
                    }
                  } catch (e) {
                    console.error('[Клієнт] Помилка парсингу JSON з буфера:', e.message, 'Дані:', jsonString);
                  }
                }
              }
            });
          } else {
            console.error('[Клієнт] Помилка: Повідомлення "Server Ready" не правильне.');
            client.destroy();
          }
        });
      });

      caSocket.on('error', (err) => {
        console.error(`[${MY_NAME}] !!! ПЕРЕВІРКА ПРОВАЛЕНА: Не вдалося підключитися до CA-Сервера: ${err.message} !!!`);
        client.destroy();
      });
    });
  });

  client.on('error', (err) => console.error(`[${MY_NAME}] Помилка сокета (клієнт):`, err.message));
  client.on('close', () => console.log(`[${MY_NAME}] З'єднання (клієнт) з ${targetName} закрито.`));
};

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

rl.on('line', (input) => {
  const parts = input.trim().split(' ');
  const command = parts[0];
  const targetHost = parts[1] || 'localhost';
  const targetPort = parseInt(parts[2], 10);

  let finalHost = targetHost;
  let finalPort = targetPort;
  if (command === 'connect' && parts.length === 2) {
    finalHost = 'localhost';
    finalPort = parseInt(parts[1], 10);
  }

  if (command === 'connect' && finalPort) {
    connectToPeer(finalHost, finalPort);
  } else if (command === 'exit') {
    console.log(`[${MY_NAME}] Завершую роботу...`);
    process.exit(0);
  } else {
    console.log('Використовуйте: connect <port> (або connect <host> <port>)');
  }
});

console.log(`[${MY_NAME}] Нода запущена. Введіть 'connect <port>' для з'єднання.`);