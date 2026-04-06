const crypto = require('crypto');
const { promisify } = require('util');
const pbkdf2 = promisify(crypto.pbkdf2);

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const SALT_LENGTH = 32;
const TAG_LENGTH = 16;
const KEY_LENGTH = 32;
const PBKDF2_ITERATIONS = 310000; // OWASP recommended

class CryptoManager {
  // Generate a random AES key for conversation
  static generateConversationKey() {
    return crypto.randomBytes(KEY_LENGTH);
  }
  
  // Derive key from shared secret with salt
  static async deriveKey(sharedSecret, salt) {
    const key = await pbkdf2(sharedSecret, salt, PBKDF2_ITERATIONS, KEY_LENGTH, 'sha256');
    return key;
  }
  
  // Encrypt message with AES-256-GCM
  static encryptMessage(plaintext, key) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    
    const encrypted = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final()
    ]);
    
    const tag = cipher.getAuthTag();
    
    return {
      encrypted: encrypted.toString('base64'),
      iv: iv.toString('base64'),
      tag: tag.toString('base64')
    };
  }
  
  // Decrypt message
  static decryptMessage(encryptedData, key) {
    const { encrypted, iv, tag } = encryptedData;
    const decipher = crypto.createDecipheriv(
      ALGORITHM,
      key,
      Buffer.from(iv, 'base64')
    );
    
    decipher.setAuthTag(Buffer.from(tag, 'base64'));
    
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(encrypted, 'base64')),
      decipher.final()
    ]);
    
    return decrypted.toString('utf8');
  }
  
  // Generate message hash for integrity
  static hashMessage(content) {
    return crypto.createHash('sha256').update(content).digest('hex');
  }
  
  // RSA encryption for key exchange
  static rsaEncrypt(data, publicKeyPem) {
    const encrypted = crypto.publicEncrypt(
      {
        key: publicKeyPem,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      Buffer.from(data)
    );
    return encrypted.toString('base64');
  }
  
  static rsaDecrypt(encryptedData, privateKeyPem) {
    const decrypted = crypto.privateDecrypt(
      {
        key: privateKeyPem,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      Buffer.from(encryptedData, 'base64')
    );
    return decrypted;
  }
  
  // Generate user key pair
  static generateUserKeyPair() {
    return crypto.generateKeyPairSync('rsa', {
      modulusLength: 3072, // Stronger than 2048
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
        cipher: 'aes-256-cbc',
        passphrase: 'will-be-replaced' // Will be re-encrypted with user password
      }
    });
  }
  
  // Encrypt private key with user's password
  static encryptPrivateKey(privateKeyPem, password) {
    const salt = crypto.randomBytes(SALT_LENGTH);
    const key = crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, KEY_LENGTH, 'sha256');
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    
    let encrypted = cipher.update(privateKeyPem, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    
    return {
      encryptedKey: encrypted,
      iv: iv.toString('base64'),
      salt: salt.toString('base64')
    };
  }
  
  // Decrypt private key
  static decryptPrivateKey(encryptedData, password) {
    const { encryptedKey, iv, salt } = encryptedData;
    const key = crypto.pbkdf2Sync(password, Buffer.from(salt, 'base64'), PBKDF2_ITERATIONS, KEY_LENGTH, 'sha256');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, Buffer.from(iv, 'base64'));
    
    let decrypted = decipher.update(encryptedKey, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }
  
  // Generate secure random token
  static generateSecureToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
  }
  
  // Verify message integrity
  static verifyIntegrity(message, hash) {
    const computedHash = this.hashMessage(message);
    return crypto.timingSafeEqual(Buffer.from(computedHash), Buffer.from(hash));
  }
}

module.exports = CryptoManager;