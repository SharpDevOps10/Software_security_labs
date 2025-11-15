const net = require('node:net');
const fs = require('node:fs');
const crypto = require('node:crypto');

const CA_PORT = 9000;

let caCert;
try {
  const caCertPem = fs.readFileSync('ca.crt', 'utf8');
  caCert = new crypto.X509Certificate(caCertPem);
  console.log('[CA-Сервер] Root CA сертифікат завантажено.');
} catch (e) {
  console.error('[CA-Сервер] Не вдалося завантажити ca.crt!', e.message);
  process.exit(1);
}

const server = net.createServer((socket) => {
  console.log('[CA-Сервер] Отримано запит на перевірку...');

  socket.once('data', (data) => {
    try {
      const pemToVerify = data.toString();

      const certToVerify = new crypto.X509Certificate(pemToVerify);

      const isValid = certToVerify.verify(caCert.publicKey);

      if (isValid) {
        console.log('[CA-Сервер] Перевірка успішна. Сертифікат ДІЙСНИЙ.');
        socket.write('VALID');
      } else {
        console.log('[CA-Сервер] Перевірка ПРОВАЛЕНА. Сертифікат НЕ ДІЙСНИЙ.');
        socket.write('INVALID');
      }
    } catch (err) {
      console.error('[CA-Сервер] Помилка під час перевірки:', err.message);
      socket.write('ERROR: Invalid certificate format');
    } finally {
      socket.end();
    }
  });

  socket.on('error', (err) => {
    console.error('[CA-Сервер] Помилка сокета:', err.message);
  });
});

server.listen(CA_PORT, () => {
  console.log(`[CA-Сервер] Сервер перевірки сертифікатів слухає на порті ${CA_PORT}`);
});