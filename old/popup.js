document.getElementById("encrypt").addEventListener("click", () => {
    const text = document.getElementById("text").value;
  
    chrome.runtime.sendMessage({ type: "encrypt", text }, (response) => {
      if (chrome.runtime.lastError) {
        console.error("Error:", chrome.runtime.lastError.message);
        return;
      }
      console.log("Response from background.js:", response);
      document.getElementById("result").innerText = response?.encrypted || "Error encrypting text";
    });
  });
  