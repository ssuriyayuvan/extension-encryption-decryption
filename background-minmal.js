// background-minimal.js
console.log("Minimal Service Worker: Script started."); // Log on startup

chrome.runtime.onStartup.addListener(() => {
  console.log("Minimal Service Worker: onStartup event."); // Log on startup event
});

chrome.runtime.onInstalled.addListener(() => {
  console.log("Minimal Service Worker: onInstalled event."); // Log on install event
});

chrome.runtime.onMessage.addListener(
  (request, sender, sendResponse) => {
    console.log("Minimal Service Worker: Message received:", request); // Log any message
    if (request.type === 'testMinimal') {
      sendResponse({ status: 'Minimal Worker Responding' });
      return true;
    }
  }
);

console.log("Minimal Service Worker: Message listeners set up."); // Log after listeners