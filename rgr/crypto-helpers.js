const crypto = require('node:crypto');

const ALGORITHM = 'aes-256-cbc';
const IV_LENGTH = 16;

const symmetricEncrypt = (text, key) => {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  return iv.toString('hex') + ':' + encrypted;
};

const symmetricDecrypt = (hash, key) => {
  try {
    const parts = hash.split(':');
    const iv = Buffer.from(parts.shift(), 'hex');
    const encryptedText = parts.join(':');

    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  } catch (error) {
    return '!!! ПОМИЛКА РОЗШИФРУВАННЯ !!!';
  }
};

const deriveSessionKey = (clientRand, serverRand, premaster) => {
  const seed = Buffer.concat([clientRand, serverRand, premaster]);

  return crypto.createHash('sha256').update(seed).digest();
};

module.exports = {
  symmetricEncrypt,
  symmetricDecrypt,
  deriveSessionKey,
};