const net = require('node:net');
const fs = require('node:fs');
const crypto = require('node:crypto');
const {symmetricEncrypt, symmetricDecrypt, deriveSessionKey} = require('./crypto-helpers');
const {sendFragmented} = require('./send-fragmented');

const PORT = 8443;
const HOST = 'localhost';
const CA_SERVER_PORT = 9000;
const CA_SERVER_HOST = 'localhost';

console.log('[Клієнт] Запуск...');

const client = new net.Socket();
const session = {
  clientRandom: null,
  serverRandom: null,
  premasterSecret: null,
  sessionKey: null,
};

client.connect(PORT, HOST, () => {
  console.log('[Клієнт] Успішно підключився до сервера.');

  // ЕТАП 1: Надсилання "Client Hello"
  session.clientRandom = crypto.randomBytes(32);
  const clientHello = {clientRandom: session.clientRandom.toString('base64')};

  client.write(JSON.stringify(clientHello));
  console.log('[Клієнт] Надіслав ЕТАП 1 (Client Hello).');

  // ЕТАП 2: Отримання "Server Hello"
  client.once('data', (serverHelloData) => {
    const serverHello = JSON.parse(serverHelloData.toString());
    session.serverRandom = Buffer.from(serverHello.serverRandom, 'base64');
    const certificateFromMainServer = serverHello.certificatePem;
    console.log('[Клієнт] Отримав ЕТАП 2 (Server Hello + Cert).');

    // ЕТАП 3: Автентифікація (Перевірка сертифіката, звернення до CA-Сервера)
    console.log('[Клієнт] Починаю ЕТАП 3 (Автентифікація через CA-Сервер)...');
    const caSocket = new net.Socket();

    caSocket.connect(CA_SERVER_PORT, CA_SERVER_HOST, () => {
      console.log(`[Клієнт -> CA] Підключився до CA-Сервера (порт ${CA_SERVER_PORT}).`);
      caSocket.write(certificateFromMainServer);
    });

    caSocket.once('data', (caResponseData) => {
      const caResponse = caResponseData.toString();
      console.log(`[Клієнт <- CA] Отримав відповідь від CA: "${caResponse}"`);
      caSocket.end();

      if (caResponse !== 'VALID') {
        console.error(`[Клієнт] !!! ПЕРЕВІРКА ПРОВАЛЕНА (ЕТАП 3): CA-Сервер відхилив сертифікат. !!!`);
        client.destroy();
        return;
      }

      console.log('[Клієнт] ...Успіх! CA-Сервер підтвердив сертифікат.');

      // ЕТАП 4: Створення та відправка "Premaster Secret"
      session.premasterSecret = crypto.randomBytes(32);

      const serverCert = new crypto.X509Certificate(certificateFromMainServer);
      const encryptedPremaster = crypto.publicEncrypt(
        serverCert.publicKey,
        session.premasterSecret
      );

      const premasterMessage = {
        encryptedPremaster: encryptedPremaster.toString('base64')
      };
      client.write(JSON.stringify(premasterMessage));
      console.log('[Клієнт] Надіслав ЕТАП 4 (Encrypted Premaster).');

      // ЕТАП 5: Генерація ключа сеансу
      session.sessionKey = deriveSessionKey(
        session.clientRandom,
        session.serverRandom,
        session.premasterSecret
      );
      console.log('[Клієнт] Згенерував ключ сеансу (ЕТАП 5).');

      // ЕТАП 6: Отримання "Server Ready"
      client.once('data', (serverReadyData) => {
        const serverReady = JSON.parse(serverReadyData.toString());
        const decryptedMsg = symmetricDecrypt(serverReady.message, session.sessionKey);

        if (decryptedMsg === 'Server: Finished') {
          console.log(`[Клієнт] Отримав ЕТАП 6 (Server Ready): "${decryptedMsg}"`);

          const clientReadyMsg = symmetricEncrypt('Client: Finished', session.sessionKey);
          sendFragmented(client, JSON.stringify({ type: 'ready', message: clientReadyMsg }) + '\n', '[Клієнт]');

          console.log('\n*** [Клієнт] Рукостискання завершено. Канал безпечний. ***\n');

          // ЕТАП 7: Початок захищеного чату

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

                  if (decrypted.includes('Client: Finished')) {
                    console.log('[Клієнт] > надсилаю "Привіт, Сервер!"');
                    const chatMessage = symmetricEncrypt('Привіт, Сервер! Як справи?', session.sessionKey);
                    sendFragmented(client, JSON.stringify({ type: 'chat', message: chatMessage }) + '\n', '[Клієнт]');

                  } else if (decrypted.includes('Привіт, Сервер!')) {
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
      console.error(`[Клієнт] !!! ПЕРЕВІРКА ПРОВАЛЕНА (ЕТАП 3): Не вдалося підключитися до CA-Сервера: ${err.message} !!!`);
      client.destroy();
    });
  });
});

client.on('close', () => {
  console.log('[Клієнт] Зв\'язок закрито.');
});

client.on('error', (err) => {
  console.error('[Клієнт] Помилка:', err.message);
});