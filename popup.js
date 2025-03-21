document.addEventListener('DOMContentLoaded', function() {
    const genKeysBtn = document.getElementById('genKeysBtn');
    const encryptBtn = document.getElementById('encryptBtn');
    const decryptBtn = document.getElementById('decryptBtn');
    const plaintextInput = document.getElementById('plaintextInput');
    const encryptedInput = document.getElementById('encryptedInput');
    const resultOutput = document.getElementById('resultOutput');
    const statusDiv = document.getElementById('status');
    
    // Check if keys exist
    chrome.storage.local.get(['keyPairExists'], function(result) {
      if (result.keyPairExists) {
        statusDiv.textContent = 'Status: Keys are ready to use';
        statusDiv.style.color = '#34a853';  // Green
      } else {
        statusDiv.textContent = 'Status: No keys yet - click Generate New Keys';
        statusDiv.style.color = '#ea4335';  // Red
      }
    });
    
    // Generate keys
    genKeysBtn.addEventListener('click', function() {
      statusDiv.textContent = 'Status: Generating keys...';
      statusDiv.style.color = '#f4b400';  // Yellow
      
      chrome.runtime.sendMessage(
        { action: 'generateKeys' },
        function(response) {
          if (chrome.runtime.lastError) {
            statusDiv.textContent = 'Status: Error - ' + chrome.runtime.lastError.message;
            statusDiv.style.color = '#ea4335';  // Red
            return;
          }
          
          if (response && response.success) {
            statusDiv.textContent = 'Status: Keys generated successfully!';
            statusDiv.style.color = '#34a853';  // Green
          } else {
            const errorMsg = response && response.message ? response.message : 'Unknown error';
            statusDiv.textContent = 'Status: Failed - ' + errorMsg;
            statusDiv.style.color = '#ea4335';  // Red
          }
        }
      );
    });
    
    // Encrypt
    encryptBtn.addEventListener('click', function() {
      const plaintext = plaintextInput.value.trim();
      if (!plaintext) {
        resultOutput.value = 'Please enter text to encrypt';
        return;
      }
      
      statusDiv.textContent = 'Status: Encrypting...';
      
      chrome.runtime.sendMessage(
        { 
          action: 'encrypt',
          data: plaintext
        },
        function(response) {
          if (chrome.runtime.lastError) {
            resultOutput.value = 'Error: ' + chrome.runtime.lastError.message;
            statusDiv.textContent = 'Status: Encryption failed';
            return;
          }
          
          if (response && response.success) {
            encryptedInput.value = response.result;
            resultOutput.value = 'Encryption successful!';
            statusDiv.textContent = 'Status: Encryption complete';
          } else {
            const errorMsg = response && response.message ? response.message : 'Unknown error';
            resultOutput.value = 'Encryption failed: ' + errorMsg;
            statusDiv.textContent = 'Status: Encryption failed';
          }
        }
      );
    });
    
    // Decrypt
    decryptBtn.addEventListener('click', function() {
      const encrypted = encryptedInput.value.trim();
      if (!encrypted) {
        resultOutput.value = 'Please enter text to decrypt';
        return;
      }
      
      statusDiv.textContent = 'Status: Decrypting...';
      
      chrome.runtime.sendMessage(
        { 
          action: 'decrypt',
          data: encrypted
        },
        function(response) {
          if (chrome.runtime.lastError) {
            resultOutput.value = 'Error: ' + chrome.runtime.lastError.message;
            statusDiv.textContent = 'Status: Decryption failed';
            return;
          }
          
          if (response && response.success) {
            resultOutput.value = response.result;
            statusDiv.textContent = 'Status: Decryption complete';
          } else {
            const errorMsg = response && response.message ? response.message : 'Unknown error';
            resultOutput.value = 'Decryption failed: ' + errorMsg;
            statusDiv.textContent = 'Status: Decryption failed';
          }
        }
      );
    });
  });