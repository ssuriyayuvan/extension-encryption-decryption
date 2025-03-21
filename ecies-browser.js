/**
 * Simple ECIES implementation using the Web Crypto API
 * Note: This is a simplified version for demonstration purposes
 */
class ECIES {
  constructor() {
    this.publicKey = null;
    this.privateKey = null;
  }

  /**
   * Generate a new ECDH key pair
   */
  async generateKeyPair() {
    try {
      const keyPair = await window.crypto.subtle.generateKey(
        {
          name: "ECDH",
          namedCurve: "P-256"
        },
        true,
        ["deriveKey", "deriveBits"]
      );
      
      this.publicKey = keyPair.publicKey;
      this.privateKey = keyPair.privateKey;
      
      // Export public key for storage
      const exportedPublicKey = await window.crypto.subtle.exportKey(
        "spki",
        this.publicKey
      );
      
      // Export private key for storage
      const exportedPrivateKey = await window.crypto.subtle.exportKey(
        "pkcs8",
        this.privateKey
      );
      
      return {
        publicKey: this._arrayBufferToBase64(exportedPublicKey),
        privateKey: this._arrayBufferToBase64(exportedPrivateKey)
      };
    } catch (error) {
      console.error("Error generating key pair:", error);
      throw error;
    }
  }

  /**
   * Import keys from storage
   */
  async importKeys(publicKeyBase64, privateKeyBase64) {
    try {
      if (publicKeyBase64) {
        const publicKeyBuffer = this._base64ToArrayBuffer(publicKeyBase64);
        this.publicKey = await window.crypto.subtle.importKey(
          "spki",
          publicKeyBuffer,
          {
            name: "ECDH",
            namedCurve: "P-256"
          },
          true,
          []
        );
      }
      
      if (privateKeyBase64) {
        const privateKeyBuffer = this._base64ToArrayBuffer(privateKeyBase64);
        this.privateKey = await window.crypto.subtle.importKey(
          "pkcs8",
          privateKeyBuffer,
          {
            name: "ECDH",
            namedCurve: "P-256"
          },
          true,
          ["deriveKey", "deriveBits"]
        );
      }
      
      return true;
    } catch (error) {
      console.error("Error importing keys:", error);
      throw error;
    }
  }

  /**
   * Encrypt a message using ECIES
   */
  async encrypt(message) {
    try {
      if (!this.publicKey) {
        throw new Error("Public key not set");
      }
      
      // Generate a random ephemeral key pair for this message
      const ephemeralKeyPair = await window.crypto.subtle.generateKey(
        {
          name: "ECDH",
          namedCurve: "P-256"
        },
        true,
        ["deriveKey", "deriveBits"]
      );
      
      // Export the ephemeral public key to include in the ciphertext
      const ephemeralPublicKey = await window.crypto.subtle.exportKey(
        "spki",
        ephemeralKeyPair.publicKey
      );
      
      // Derive a shared secret using recipient's public key and ephemeral private key
      const sharedSecret = await window.crypto.subtle.deriveBits(
        {
          name: "ECDH",
          public: this.publicKey
        },
        ephemeralKeyPair.privateKey,
        256 // derive 256 bits
      );
      
      // Derive encryption key from the shared secret
      const encryptionKey = await window.crypto.subtle.importKey(
        "raw",
        sharedSecret,
        {
          name: "AES-GCM",
          length: 256
        },
        false,
        ["encrypt"]
      );
      
      // Generate random IV
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      
      // Encrypt the message
      const encodedMessage = new TextEncoder().encode(message);
      const encryptedData = await window.crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: iv
        },
        encryptionKey,
        encodedMessage
      );
      
      // Combine ephemeral public key, IV, and encrypted data
      const combinedData = new Uint8Array(
        ephemeralPublicKey.byteLength + iv.byteLength + encryptedData.byteLength
      );
      combinedData.set(new Uint8Array(ephemeralPublicKey), 0);
      combinedData.set(iv, ephemeralPublicKey.byteLength);
      combinedData.set(
        new Uint8Array(encryptedData),
        ephemeralPublicKey.byteLength + iv.byteLength
      );
      
      // Return as Base64
      return this._arrayBufferToBase64(combinedData);
    } catch (error) {
      console.error("Encryption error:", error);
      throw error;
    }
  }

  /**
   * Decrypt a message using ECIES
   */
  async decrypt(encryptedMessageBase64) {
    try {
      if (!this.privateKey) {
        throw new Error("Private key not set");
      }
      
      // Convert from Base64 to ArrayBuffer
      const encryptedData = this._base64ToArrayBuffer(encryptedMessageBase64);
      
      // Extract components from combined data
      // First 91 bytes are typically the ephemeral public key in spki format
      const ephemeralPublicKeyBuffer = encryptedData.slice(0, 91);
      const iv = new Uint8Array(encryptedData.slice(91, 91 + 12));
      const ciphertext = new Uint8Array(encryptedData.slice(91 + 12));
      
      // Import the ephemeral public key
      const ephemeralPublicKey = await window.crypto.subtle.importKey(
        "spki",
        ephemeralPublicKeyBuffer,
        {
          name: "ECDH",
          namedCurve: "P-256"
        },
        true,
        []
      );
      
      // Derive the same shared secret using recipient's private key and ephemeral public key
      const sharedSecret = await window.crypto.subtle.deriveBits(
        {
          name: "ECDH",
          public: ephemeralPublicKey
        },
        this.privateKey,
        256 // derive 256 bits
      );
      
      // Derive the same encryption key from the shared secret
      const decryptionKey = await window.crypto.subtle.importKey(
        "raw",
        sharedSecret,
        {
          name: "AES-GCM",
          length: 256
        },
        false,
        ["decrypt"]
      );
      
      // Decrypt the message
      const decryptedData = await window.crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: iv
        },
        decryptionKey,
        ciphertext
      );
      
      // Decode to string
      return new TextDecoder().decode(decryptedData);
    } catch (error) {
      console.error("Decryption error:", error);
      throw error;
    }
  }

  /**
   * Convert ArrayBuffer to Base64 string
   */
  _arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  }

  /**
   * Convert Base64 string to ArrayBuffer
   */
  _base64ToArrayBuffer(base64) {
    const binaryString = window.atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  }
}

// Export the class
window.ECIES = ECIES;