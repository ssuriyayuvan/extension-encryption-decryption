console.log('Background script started');

// Simple ECIES implementation
class ECIES {
  constructor() {
    this.publicKey = null;
    this.privateKey = null;
  }
  
  async generateKeyPair() {
    try {
      const keyPair = await crypto.subtle.generateKey(
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
      const exportedPublicKey = await crypto.subtle.exportKey(
        "spki",
        this.publicKey
      );
      
      // Export private key for storage
      const exportedPrivateKey = await crypto.subtle.exportKey(
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
  
  async importKeys(publicKeyBase64, privateKeyBase64) {
    try {
      if (publicKeyBase64) {
        const publicKeyBuffer = this._base64ToArrayBuffer(publicKeyBase64);
        this.publicKey = await crypto.subtle.importKey(
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
        this.privateKey = await crypto.subtle.importKey(
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
  
  async encrypt(message) {
    try {
      if (!this.publicKey) {
        throw new Error("Public key not set");
      }
      
      // Generate a random ephemeral key pair for this message
      const ephemeralKeyPair = await crypto.subtle.generateKey(
        {
          name: "ECDH",
          namedCurve: "P-256"
        },
        true,
        ["deriveKey", "deriveBits"]
      );
      
      // Export the ephemeral public key to include in the ciphertext
      const ephemeralPublicKey = await crypto.subtle.exportKey(
        "spki",
        ephemeralKeyPair.publicKey
      );
      
      // Derive a shared secret using recipient's public key and ephemeral private key
      const sharedSecret = await crypto.subtle.deriveBits(
        {
          name: "ECDH",
          public: this.publicKey
        },
        ephemeralKeyPair.privateKey,
        256 // derive 256 bits
      );
      
      // Derive encryption key from the shared secret
      const encryptionKey = await crypto.subtle.importKey(
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
      const iv = crypto.getRandomValues(new Uint8Array(12));
      
      // Encrypt the message
      const encodedMessage = new TextEncoder().encode(message);
      const encryptedData = await crypto.subtle.encrypt(
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
      const ephemeralPublicKey = await crypto.subtle.importKey(
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
      const sharedSecret = await crypto.subtle.deriveBits(
        {
          name: "ECDH",
          public: ephemeralPublicKey
        },
        this.privateKey,
        256 // derive 256 bits
      );
      
      // Derive the same encryption key from the shared secret
      const decryptionKey = await crypto.subtle.importKey(
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
      const decryptedData = await crypto.subtle.decrypt(
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
  
  _arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    const binary = bytes.reduce((acc, byte) => acc + String.fromCharCode(byte), '');
    return btoa(binary);
  }
  
  _base64ToArrayBuffer(base64) {
    // Convert URL-safe base64 to standard base64
    const standardBase64 = base64
      .replace(/-/g, '+')
      .replace(/_/g, '/')
      .replace(/\s/g, '');
    
    // Add padding if needed
    const padding = standardBase64.length % 4;
    const paddedBase64 = padding ? 
      standardBase64 + '='.repeat(4 - padding) : 
      standardBase64;
    
    const binaryString = atob(paddedBase64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  }
}

// Create ECIES instance
const ecies = new ECIES();

// Initialize
async function initialize() {
  try {
    console.log('Initializing ECIES');
    // Check if keys exist in storage
    const data = await chrome.storage.local.get(['publicKey', 'privateKey', 'keyPairExists']);
    
    if (data.keyPairExists && data.publicKey && data.privateKey) {
      try {
        // Try to import existing keys
        await ecies.importKeys(data.publicKey, data.privateKey);
        console.log('Keys loaded from storage');
      } catch (error) {
        console.log('Error loading existing keys, generating new ones:', error);
        // If import fails, generate new keys
        const keys = await ecies.generateKeyPair();
        await chrome.storage.local.set({
          publicKey: keys.publicKey,
          privateKey: keys.privateKey,
          keyPairExists: true
        });
        console.log('New keys generated and saved');
      }
    } else {
      console.log('No keys found in storage, generating new ones');
      // Generate new keys if none exist
      const keys = await ecies.generateKeyPair();
      await chrome.storage.local.set({
        publicKey: keys.publicKey,
        privateKey: keys.privateKey,
        keyPairExists: true
      });
      console.log('New keys generated and saved');
    }
  } catch (error) {
    console.error('Initialization failed:', error);
    // Try to recover by generating new keys
    try {
      const keys = await ecies.generateKeyPair();
      await chrome.storage.local.set({
        publicKey: keys.publicKey,
        privateKey: keys.privateKey,
        keyPairExists: true
      });
      console.log('Recovered by generating new keys');
    } catch (recoveryError) {
      console.error('Recovery failed:', recoveryError);
    }
  }
}

// Listen for messages
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
  console.log('Background received message:', request.action);
  
  // Handle different message types
  if (request.action === 'generateKeys') {
    // Handle key generation
    console.log('Processing generateKeys request');
    
    // Use async function but maintain message port
    (async function() {
      try {
        const keys = await ecies.generateKeyPair();
        
        // Save keys to storage
        await chrome.storage.local.set({
          publicKey: keys.publicKey,
          privateKey: keys.privateKey,
          keyPairExists: true
        });
        
        console.log('Keys generated and saved');
        sendResponse({ 
          success: true, 
          message: 'Keys generated successfully' 
        });
      } catch (error) {
        console.error('Key generation error:', error);
        sendResponse({ 
          success: false, 
          message: error.message 
        });
      }
    })();
    
    // Keep message port open for async response
    return true;
  }
  
  else if (request.action === 'encrypt') {
    console.log('Processing encrypt request');
    
    (async function() {
      try {
        if (!request.data) {
          throw new Error('No data provided for encryption');
        }
        
        const encryptedData = await ecies.encrypt(request.data);
        sendResponse({ 
          success: true, 
          result: encryptedData 
        });
      } catch (error) {
        console.error('Encryption error:', error);
        sendResponse({ 
          success: false, 
          message: error.message 
        });
      }
    })();
    
    // Keep message port open for async response
    return true;
  }
  
  else if (request.action === 'decrypt') {
    console.log('Processing decrypt request');
    
    (async function() {
      try {
        if (!request.data) {
          throw new Error('No data provided for decryption');
        }
        
        const decryptedData = await ecies.decrypt(request.data);
        sendResponse({ 
          success: true, 
          result: decryptedData 
        });
      } catch (error) {
        console.error('Decryption error:', error);
        sendResponse({ 
          success: false, 
          message: error.message 
        });
      }
    })();
    
    // Keep message port open for async response
    return true;
  }
  
  // For unknown actions
  else {
    console.log('Unknown action:', request.action);
    sendResponse({ success: false, message: 'Unknown action' });
  }
  
  // Return true by default to keep message port open
  return true;
});

// Initialize when service worker starts
initialize();
console.log('Background initialization complete');