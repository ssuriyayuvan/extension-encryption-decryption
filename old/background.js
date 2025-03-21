importScripts("crypto-js.js");

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "encrypt") {
    console.log("Received message in background.js:", message.text); // Debugging log
    const encrypted = CryptoJS.AES.encrypt(message.text, "secret-key").toString();
    sendResponse({ encrypted });
  }
  return true; // Required for async response handling
});
