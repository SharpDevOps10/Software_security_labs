const net = require('node:net');
const fs = require('node:fs');
const crypto = require('node:crypto');
const { symmetricEncrypt, symmetricDecrypt, deriveSessionKey } = require('./crypto-helpers');

const PORT = 8443;

const serverPrivateKey = fs.readFileSync('server.key', 'utf8');
const serverCertificatePem = fs.readFileSync('server.crt', 'utf8');

console.log('Сервер завантажив свій ключ та сертифікат.');

const server = net.createServer((socket) => {
  console.log('\n[Сервер] Клієнт підключився.');

  const session = {
    clientRandom: null,
    serverRandom: null,
    premasterSecret: null,
    sessionKey: null,
  };

  // ЕТАП 1: Отримання "Client Hello"
  socket.once('data', (clientHelloData) => {
    try {
      const clientHello = JSON.parse(clientHelloData.toString());
      session.clientRandom = Buffer.from(clientHello.clientRandom, 'base64');
      console.log('[Сервер] Отримав ЕТАП 1 (Client Hello).');

      session.serverRandom = crypto.randomBytes(32);

      const serverHelloPayload = {
        serverRandom: session.serverRandom.toString('base64'),
        certificatePem: serverCertificatePem,
      };

      socket.write(JSON.stringify(serverHelloPayload));
      console.log('[Сервер] Надіслав ЕТАП 2 (Server Hello + Cert).');

      // ЕТАП 4: Отримання та розшифровка "Premaster Secret"
      socket.once('data', (premasterData) => {
        try {
          const premasterMessage = JSON.parse(premasterData.toString());
          const encryptedPremaster = Buffer.from(premasterMessage.encryptedPremaster, 'base64');

          console.log('[Сервер] Отримав ЕТАП 4 (Encrypted Premaster).');

          // Розшифровуємо нашим приватним ключем
          session.premasterSecret = crypto.privateDecrypt(
            serverPrivateKey,
            encryptedPremaster
          );

          // ЕТАП 5: Генерація ключа сеансу
          session.sessionKey = deriveSessionKey(
            session.clientRandom,
            session.serverRandom,
            session.premasterSecret
          );
          console.log('[Сервер] Згенерував ключ сеансу (ЕТАП 5).');

          // ЕТАП 6: Надсилання "Server Ready"
          const serverReadyMsg = symmetricEncrypt('Server: Finished', session.sessionKey);
          socket.write(JSON.stringify({type: 'ready', message: serverReadyMsg}));
          console.log('[Сервер] Надіслав ЕТАП 6 (Server Ready).');

          // ЕТАП 7: Початок захищеного чату
          console.log('\n*** [Сервер] Рукостискання завершено. Канал безпечний. ***\n');

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
                  console.log(`[Сервер] Отримав повідомлення: "${decrypted}"`);

                  const reply = symmetricEncrypt(`Сервер отримав твоє: "${decrypted}"`, session.sessionKey);
                  socket.write(JSON.stringify({type: 'chat', message: reply}) + '\n');
                } catch (e) {
                  console.error('[Сервер] Помилка парсингу JSON з буфера:', e.message, 'Дані:', jsonString);
                }
              }
            }
          });

        } catch (e) {
          console.error('[Сервер] Помилка на етапі 4:', e.message);
          socket.destroy();
        }
      });

    } catch (e) {
      console.error('[Сервер] Помилка на етапі 1:', e.message);
      socket.destroy();
    }
  });

  socket.on('close', () => {
    console.log('[Сервер] Клієнт відключився.');
  });

  socket.on('error', (err) => {
    console.error('[Сервер] Помилка сокета:', err.message);
  });
});

server.listen(PORT, () => {
  console.log(`TCP Cервер (імітація TLS) слухає на порті ${PORT}`);
});