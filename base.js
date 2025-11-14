const PBKDF2_ITERATIONS = 10000;
const KEY_BYTES = 32; 
const IV_BYTES  = 16;
const SALT_BYTES = 8; 
const PREFIX = "";
const SUFFIX = "";


document.getElementById('fileInput').addEventListener('change', function (e) {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = function(ev) {
    document.getElementById('originalText').value = ev.target.result;
  };
  reader.readAsText(file);
});

function showToast(message, type='info') {
  const container = document.getElementById('toastContainer');
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  container.appendChild(toast);

  // trigger animation
  setTimeout(() => toast.classList.add('show'), 50);

  // remove after 3 seconds
  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 300); // wait for fade-out transition
  }, 3000);
}


function encryptText() {
  const text = document.getElementById('originalText').value;
  const rawPass = document.getElementById('password').value || '';
  if (!text || !rawPass) return showToast("Please enter both text and password.", "error");

  const applyPrefix = document.getElementById('applyPrefix').checked;
  const pass = applyPrefix ? (PREFIX + rawPass + SUFFIX) : rawPass;

  const salt = CryptoJS.lib.WordArray.random(SALT_BYTES);
  const totalBytes = KEY_BYTES + IV_BYTES;
  const derived = CryptoJS.PBKDF2(pass, salt, {
    keySize: totalBytes / 4,
    iterations: PBKDF2_ITERATIONS,
    hasher: CryptoJS.algo.SHA256
  });

  const keyWords = CryptoJS.lib.WordArray.create(derived.words.slice(0, KEY_BYTES/4), KEY_BYTES);
  const ivWords  = CryptoJS.lib.WordArray.create(derived.words.slice(KEY_BYTES/4, (KEY_BYTES+IV_BYTES)/4), IV_BYTES);

  const encrypted = CryptoJS.AES.encrypt(text, keyWords, { iv: ivWords, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });

  const saltedPrefix = CryptoJS.enc.Utf8.parse("Salted__");
  const combined = saltedPrefix.concat(salt).concat(encrypted.ciphertext);
  const b64 = CryptoJS.enc.Base64.stringify(combined);
  document.getElementById('resultText').value = b64;
  showToast("Encryption successful!", "success");
}

function decryptText() {
  const rawInput = document.getElementById('originalText').value.trim();
  const rawPass = document.getElementById('password').value || '';
  if (!rawInput || !rawPass) return showToast("Please enter both encrypted text and password.", "error");

  const applyPrefix = document.getElementById('applyPrefix').checked;
  const pass = applyPrefix ? (PREFIX + rawPass + SUFFIX) : rawPass;

  try {
    const lines = rawInput.split(/\r?\n/).filter(l => l.trim() !== '');
    const results = lines.map(b64 => {
      const rawWA = CryptoJS.enc.Base64.parse(b64.trim());

      const prefixWA = CryptoJS.lib.WordArray.create(rawWA.words.slice(0, 2), 8);
      const prefixStr = CryptoJS.enc.Utf8.stringify(prefixWA);
      if (prefixStr !== "Salted__") throw new Error("Data is not OpenSSL salted format");

      const saltWA = CryptoJS.lib.WordArray.create(rawWA.words.slice(2, 4), SALT_BYTES);
      const cipherWords = rawWA.words.slice(4);
      const cipherBytes = rawWA.sigBytes - 16;
      const ciphertextWA = CryptoJS.lib.WordArray.create(cipherWords, cipherBytes);

      const totalBytes = KEY_BYTES + IV_BYTES;
      const derived = CryptoJS.PBKDF2(pass, saltWA, {
        keySize: totalBytes / 4, iterations: PBKDF2_ITERATIONS, hasher: CryptoJS.algo.SHA256
      });

      const keyWords = CryptoJS.lib.WordArray.create(derived.words.slice(0, KEY_BYTES/4), KEY_BYTES);
      const ivWords  = CryptoJS.lib.WordArray.create(derived.words.slice(KEY_BYTES/4, (KEY_BYTES+IV_BYTES)/4), IV_BYTES);

      const decrypted = CryptoJS.AES.decrypt({ ciphertext: ciphertextWA }, keyWords, { iv: ivWords, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
      const plaintext = decrypted.toString(CryptoJS.enc.Utf8);
      if (!plaintext) throw new Error("Bad password or corrupted data");
      return plaintext;
    });

    document.getElementById('resultText').value = results.join('\n');
    showToast("Decryption successful!", "success");
  } catch (err) {
    showToast("Decryption failed: " + err.message, "error");
  }
}

function saveFile() {
  const text = document.getElementById('resultText').value;
  if (!text) return showToast("Nothing to save.", "info");
  const filename = document.getElementById('downloadFilename').value.trim() || 'output.txt';
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  showToast(`File saved as ${filename}`, "success");
}

function copyResult() {
  const text = document.getElementById('resultText').value;
  if (!text) return showToast("Nothing to copy.", "info");
  navigator.clipboard.writeText(text)
    .then(() => showToast("Copied!", "success"))
    .catch(() => showToast("Copy failed.", "error"));
}

// --- Add this block at the very end of base.js ---

// Global object to expose encryption/decryption for external scripts
const base = {
  encryptText: function(text, password, applyPrefix = true) {
    const pass = applyPrefix ? (PREFIX + password + SUFFIX) : password;

    const salt = CryptoJS.lib.WordArray.random(SALT_BYTES);
    const totalBytes = KEY_BYTES + IV_BYTES;
    const derived = CryptoJS.PBKDF2(pass, salt, {
      keySize: totalBytes / 4,
      iterations: PBKDF2_ITERATIONS,
      hasher: CryptoJS.algo.SHA256
    });

    const keyWords = CryptoJS.lib.WordArray.create(derived.words.slice(0, KEY_BYTES / 4), KEY_BYTES);
    const ivWords  = CryptoJS.lib.WordArray.create(derived.words.slice(KEY_BYTES / 4, (KEY_BYTES + IV_BYTES) / 4), IV_BYTES);

    const encrypted = CryptoJS.AES.encrypt(text, keyWords, { iv: ivWords, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
    const saltedPrefix = CryptoJS.enc.Utf8.parse("Salted__");
    const combined = saltedPrefix.concat(salt).concat(encrypted.ciphertext);
    return CryptoJS.enc.Base64.stringify(combined);
  },

  decryptText: function(b64, password, applyPrefix = true) {
    const pass = applyPrefix ? (PREFIX + password + SUFFIX) : password;
    const rawWA = CryptoJS.enc.Base64.parse(b64.trim());

    const prefixWA = CryptoJS.lib.WordArray.create(rawWA.words.slice(0, 2), 8);
    const prefixStr = CryptoJS.enc.Utf8.stringify(prefixWA);
    if (prefixStr !== "Salted__") throw new Error("Data is not OpenSSL salted format");

    const saltWA = CryptoJS.lib.WordArray.create(rawWA.words.slice(2, 4), SALT_BYTES);
    const cipherWords = rawWA.words.slice(4);
    const cipherBytes = rawWA.sigBytes - 16;
    const ciphertextWA = CryptoJS.lib.WordArray.create(cipherWords, cipherBytes);

    const totalBytes = KEY_BYTES + IV_BYTES;
    const derived = CryptoJS.PBKDF2(pass, saltWA, {
      keySize: totalBytes / 4,
      iterations: PBKDF2_ITERATIONS,
      hasher: CryptoJS.algo.SHA256
    });

    const keyWords = CryptoJS.lib.WordArray.create(derived.words.slice(0, KEY_BYTES / 4), KEY_BYTES);
    const ivWords  = CryptoJS.lib.WordArray.create(derived.words.slice(KEY_BYTES / 4, (KEY_BYTES + IV_BYTES) / 4), IV_BYTES);

    const decrypted = CryptoJS.AES.decrypt({ ciphertext: ciphertextWA }, keyWords, { iv: ivWords, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
    const plaintext = decrypted.toString(CryptoJS.enc.Utf8);
    if (!plaintext) throw new Error("Bad password or corrupted data");
    return plaintext;
  }
};

// --- PIN modal reusable functions start here ---

async function unlockWithPIN(pinInputId, keyInputId, modalId, errorId) {
    const pinInput = document.getElementById(pinInputId);
    const keyInputEl = document.getElementById(keyInputId);
    const pinModal = document.getElementById(modalId);
    const pinError = document.getElementById(errorId);

    const pin = pinInput.value.trim();
    const keyInput = keyInputEl.value.trim();

    if (!keyInput) {
        pinError.style.display = 'block';
        pinError.textContent = "Enter key first.";
        return;
    }

    try {
        const combinedPIN = keyInput + pin + keyInput;
        PREFIXS = base.decryptText(ENCRYPTED_PREFIX, combinedPIN);
        POSTFIXS = base.decryptText(ENCRYPTED_POSTFIX, combinedPIN);

        pinModal.style.display = 'none';
        document.body.classList.remove('blur');
    } catch(err) {
        pinError.style.display = 'block';
        pinError.textContent = "Incorrect PIN or key.";
        pinInput.value = '';
        pinInput.focus();
    }
}

function setupPINModal({ pinInputId, keyInputId, modalId, pinSubmitId, errorId, autoUnlock = true }) {
    const pinInput = document.getElementById(pinInputId);
    const pinSubmit = document.getElementById(pinSubmitId);

    document.body.classList.add('blur');
    pinInput.focus();

    pinSubmit.addEventListener('click', () => unlockWithPIN(pinInputId, keyInputId, modalId, errorId));
    pinInput.addEventListener('keyup', function(e){
        if (e.key === 'Enter') unlockWithPIN(pinInputId, keyInputId, modalId, errorId);
    });

    if (autoUnlock) {
        // debounce timer
        let timer;
        pinInput.addEventListener('input', () => {
            clearTimeout(timer);
            timer = setTimeout(() => {
                unlockWithPIN(pinInputId, keyInputId, modalId, errorId);
            }, 300); // wait 300ms after typing stops
        });
    }
}


function setupUploadButton(buttonId, inputId) {
    document.getElementById(buttonId).addEventListener('click', () => {
        const fileInput = document.createElement('input');
        fileInput.type = 'file';
        fileInput.accept = '.txt';
        fileInput.onchange = e => {
            const file = e.target.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = evt => {
                document.getElementById(inputId).value = evt.target.result.trim();
            };
            reader.readAsText(file);
        };
        fileInput.click();
    });
}

function setupFetchButton(buttonId, inputId, showToast) {
    document.getElementById(buttonId).addEventListener('click', async () => {
        const inputValue = document.getElementById(inputId).value.trim();
        if (!inputValue) {
            showToast("Enter link first", "error");
            return;
        }
        try {
            const response = await fetch(inputValue);
            if (!response.ok) throw new Error("Failed to link");
            const content = await response.text();
            document.getElementById(inputId).value = content.trim();
            showToast("Fetched successfully.", "success");
        } catch (err) {
            showToast(err.message, "error");
        }
    });
}
// --- PIN modal reusable functions start here ---

