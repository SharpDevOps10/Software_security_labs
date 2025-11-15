const net = require('node:net');
const fs = require('node:fs');
const crypto = require('node:crypto');
const { symmetricEncrypt, symmetricDecrypt, deriveSessionKey } = require('./crypto-helpers');

const PORT = 8443;
const HOST = 'localhost';

const trustedCaCertificatePem = fs.readFileSync('ca.crt', 'utf8');
const caCert = new crypto.X509Certificate(trustedCaCertificatePem);
console.log('[Клієнт] Завантажив довірений сертифікат CA.');

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
    console.log('[Клієнт] Отримав ЕТАП 2 (Server Hello + Cert).');

    // ЕТАП 3: Автентифікація (Перевірка сертифіката)
    console.log('[Клієнт] Починаю ЕТАП 3 (Автентифікація)...');
    try {
      const serverCert = new crypto.X509Certificate(serverHello.certificatePem);

      if (!serverCert.verify(caCert.publicKey)) {
        throw new Error('Сертифікат сервера НЕ підписаний довіреним CA!');
      }

      console.log('[Клієнт] ...Успіх! Сертифікат сервера дійсний');

      // ЕТАП 4: Створення та відправка "Premaster Secret"
      session.premasterSecret = crypto.randomBytes(32);

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
          client.write(JSON.stringify({type: 'ready', message: clientReadyMsg}));

          console.log('\n*** [Клієнт] Рукостискання завершено. Канал безпечний. ***\n');

          // ЕТАП 7: Початок захищеного чату
          const chatMessage = symmetricEncrypt('Привіт, Сервер! Як справи?', session.sessionKey);
          client.write(JSON.stringify({type: 'chat', message: chatMessage}));

          client.on('data', (encryptedChatData) => {
            const chatMsg = JSON.parse(encryptedChatData.toString());
            const decrypted = symmetricDecrypt(chatMsg.message, session.sessionKey);
            console.log(`[Клієнт] Отримав відповідь: "${decrypted}"`);

            client.end();
          });

        } else {
          console.error('[Клієнт] Помилка: Повідомлення "Server Ready" невірне.');
          client.destroy();
        }
      });

    } catch (e) {
      console.error(`[Клієнт] !!! ПЕРЕВІРКА ПРОВАЛЕНА (ЕТАП 3): ${e.message} !!!`);
      client.destroy();
    }
  });
});

client.on('close', () => {
  console.log('[Клієнт] Зв\'язок закрито.');
});

client.on('error', (err) => {
  console.error('[Клієнт] Помилка:', err.message);
});