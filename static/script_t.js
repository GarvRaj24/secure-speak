const socket = io();
let room = null;
let myKeyPair = null;     
let peerPublicKey = null; 
let mediaRecorder = null;
let audioChunks = [];
let currentRecordingModeViewOnce = false;

// --- INITIALIZATION ---
window.onload = function() {
    console.log("SecureSpeak System Online");
    
    const params = new URLSearchParams(window.location.search);
    const urlRoom = params.get('room');
    if (urlRoom) {
        document.getElementById('room-id').value = urlRoom;
    }

    // Attach Click Listeners
    document.getElementById('btn-create').addEventListener('click', generateRoom);
    document.getElementById('btn-join').addEventListener('click', joinChat);
    document.getElementById('btn-copy').addEventListener('click', copyId);
    
    // --- ENTER KEY LOGIC ---
    document.getElementById('room-id').addEventListener('keyup', (e) => { 
        if(e.key === 'Enter') joinChat(); 
    });

    const msgInput = document.getElementById('message-input');
    msgInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault(); 
            sendTextMessage();
        }
    });
};

// --- MODAL FUNCTIONS ---
function openModal(src) {
    const modal = document.getElementById('image-modal');
    const modalImg = document.getElementById('full-image');
    modal.classList.add('modal-active');
    modalImg.src = src;
}

function closeModal() {
    const modal = document.getElementById('image-modal');
    modal.classList.remove('modal-active');
    setTimeout(() => {
        const img = document.getElementById('full-image');
        if(img) img.src = ''; // Clear memory
    }, 300);
}

// --- CORE LOGIC ---
function generateRoom() {
    const randomId = Array.from(window.crypto.getRandomValues(new Uint8Array(4)))
        .map(b => b.toString(16).padStart(2, '0')).join('');
    
    document.getElementById('room-id').value = randomId;
    document.getElementById('share-link-text').innerText = randomId;
    document.getElementById('share-area').classList.remove('hidden');
}

function copyId() {
    const text = document.getElementById('share-link-text').innerText;
    if(text) {
        navigator.clipboard.writeText(text);
        alert("ACCESS CODE COPIED");
    }
}

async function joinChat() {
    room = document.getElementById('room-id').value.trim();
    if (!room) return alert("ACCESS DENIED: Room ID Required");

    console.log("Initializing Crypto Module...");
    try {
        myKeyPair = await window.crypto.subtle.generateKey(
            { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
            true, ["encrypt", "decrypt"]
        );
        
        document.getElementById('login-screen').classList.add('hidden');
        document.getElementById('chat-screen').classList.remove('hidden');
        document.getElementById('display-room').innerText = room;
        
        socket.emit('join', { room: room });

    } catch (e) {
        console.error(e);
        alert("CRYPTO ERROR: Browser incompatible");
    }
}

socket.on('user_joined', async () => {
    console.log("Peer Connection Detected");
    const exportedKey = await window.crypto.subtle.exportKey("jwk", myKeyPair.publicKey);
    socket.emit('signal_public_key', { room: room, key: exportedKey, request_reply: true });
});

socket.on('receive_public_key', async (data) => {
    console.log("Handshake Received");
    peerPublicKey = await window.crypto.subtle.importKey(
        "jwk", data.key, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"]
    );
    
    document.getElementById('status-text').innerHTML = "<span style='color:#00f3ff'>SECURE UPLINK ESTABLISHED</span>";
    document.getElementById('connection-dot').classList.add('active');

    if (data.request_reply) {
        const myExportedKey = await window.crypto.subtle.exportKey("jwk", myKeyPair.publicKey);
        socket.emit('signal_public_key', { room: room, key: myExportedKey, request_reply: false });
    }
});

async function encryptAndSend(dataBuffer, type, isViewOnce = false) {
    if (!peerPublicKey) return alert("UPLINK OFFLINE: Wait for peer.");

    try {
        const aesKey = await window.crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        
        const encryptedData = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, aesKey, dataBuffer);
        
        const rawAesKey = await window.crypto.subtle.exportKey("raw", aesKey);
        const encryptedKey = await window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, peerPublicKey, rawAesKey);

        socket.emit('encrypted_message', {
            room: room, 
            type: type,
            iv: arrayBufferToBase64(iv),
            encryptedKey: arrayBufferToBase64(encryptedKey),
            encryptedData: arrayBufferToBase64(encryptedData),
            isViewOnce: isViewOnce
        });

        if (isViewOnce && (type === 'image' || type === 'audio')) {
            renderMessage(null, 'notification', 'sent', `SENT SELF-DESTRUCTING ${type.toUpperCase()}`);
        } else {
            renderMessage(dataBuffer, type, 'sent', null, isViewOnce);
        }
    } catch (err) {
        console.error("Encryption Error:", err);
    }
}

socket.on('receive_message', async (data) => {
    try {
        const iv = base64ToArrayBuffer(data.iv);
        const encKey = base64ToArrayBuffer(data.encryptedKey);
        const encData = base64ToArrayBuffer(data.encryptedData);
        
        const rawAesKey = await window.crypto.subtle.decrypt({ name: "RSA-OAEP" }, myKeyPair.privateKey, encKey);
        const aesKey = await window.crypto.subtle.importKey("raw", rawAesKey, { name: "AES-GCM" }, false, ["decrypt"]);
        const decryptedData = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, aesKey, encData);

        renderMessage(decryptedData, data.type, 'received', null, data.isViewOnce);
    } catch (e) { console.error("Decryption Error:", e); }
});

function sendTextMessage() {
    const input = document.getElementById('message-input');
    if (input.value) {
        encryptAndSend(new TextEncoder().encode(input.value), 'text');
        input.value = '';
        input.focus(); 
    }
}

function triggerImageUpload(isViewOnce) {
    const fileInput = document.getElementById('image-input');
    fileInput.value = ''; 
    fileInput.onchange = null; 
    fileInput.onchange = function(e) {
        const file = fileInput.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = (evt) => encryptAndSend(evt.target.result, 'image', isViewOnce);
            reader.readAsArrayBuffer(file);
        }
    };
    fileInput.click();
}

async function startRecording(isViewOnce) {
    currentRecordingModeViewOnce = isViewOnce;
    const btn = isViewOnce ? document.getElementById('record-btn-vo') : document.getElementById('record-btn');
    
    try {
        const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        mediaRecorder = new MediaRecorder(stream);
        audioChunks = [];
        mediaRecorder.ondataavailable = e => audioChunks.push(e.data);
        mediaRecorder.onstop = async () => {
            const blob = new Blob(audioChunks, { type: 'audio/webm' });
            encryptAndSend(await blob.arrayBuffer(), 'audio', currentRecordingModeViewOnce);
            btn.classList.remove('recording');
        };
        mediaRecorder.start();
        btn.classList.add('recording');
    } catch (e) {
        console.error(e);
        alert("AUDIO HARDWARE BLOCKED");
    }
}

function stopRecording() {
    if (mediaRecorder && mediaRecorder.state !== 'inactive') mediaRecorder.stop();
}

// --- UPDATED RENDER MESSAGE ---
function renderMessage(buffer, type, source, customText = null, isViewOnce = false) {
    const div = document.createElement('div');
    div.className = `message ${source}`;
    
    if (customText) {
        div.innerHTML = `<i class="fas fa-info-circle"></i> ${customText}`;
        div.style.fontFamily = "var(--font-code)";
        div.style.fontSize = "0.8rem";
    }
    else if (type === 'text') {
        div.innerText = new TextDecoder().decode(buffer);
    } 
    else if (type === 'image') {
        const blob = new Blob([buffer]);
        const url = URL.createObjectURL(blob);
        
        if (isViewOnce && source === 'received') {
            // View Once Logic: Button -> Instant Popup
            div.innerHTML = `
                <div class="vo-container">
                    <div style="font-size:1rem; color:var(--neon-red); margin-bottom:5px">HIDDEN DATA</div>
                    <button class="vo-btn">REVEAL (10s)</button>
                </div>`;
            
            div.querySelector('button').onclick = function() {
                // 1. Open the Modal IMMEDIATELY
                openModal(url);
                
                // 2. Change the bubble text to indicate it's active
                div.innerHTML = `<span style="color:var(--neon-blue); font-family:var(--font-code)">[ VIEWING DATA... ]</span>`;
                
                // 3. Start Timer (true = close the modal when time is up)
                startDestructTimer(div, url, "[ IMAGE SCRUBBED ]", true); 
            };
        } else {
            // Standard Image Logic: Thumbnail -> Click to Popup
            div.innerHTML = `<div class="media-content"><img src="${url}" onclick="openModal('${url}')" style="cursor: pointer;"></div>`;
        }
    } 
    else if (type === 'audio') {
        const blob = new Blob([buffer]);
        const url = URL.createObjectURL(blob);
        
        if (isViewOnce && source === 'received') {
            div.innerHTML = `
                <div class="vo-container">
                    <div style="font-size:1rem; color:var(--neon-red); margin-bottom:5px">AUDIO LOG</div>
                    <button class="vo-btn">PLAY</button>
                </div>`;
            div.querySelector('button').onclick = function() {
                div.innerHTML = `<audio controls autoplay controlsList="nodownload" src="${url}"></audio>`;
                div.querySelector('audio').onended = function() {
                      startDestructTimer(div, url, "[ AUDIO SCRUBBED ]");
                };
            };
        } else {
            div.innerHTML = `<audio controls controlsList="nodownload" src="${url}"></audio>`;
        }
    }
    
    document.getElementById('messages').appendChild(div);
    document.getElementById('messages').scrollTop = document.getElementById('messages').scrollHeight;
}

function startDestructTimer(div, url, msg, closeActiveModal = false) {
    setTimeout(() => {
        div.innerHTML = `<span style="color:#555; font-family:var(--font-code)">${msg}</span>`;
        if(url) URL.revokeObjectURL(url);
        
        // Security: Force close the popup if it's still open
        if(closeActiveModal) {
            closeModal();
        }
    }, 10000); 
}

// Utils
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    const chunkSize = 8192; 
    for (let i = 0; i < len; i += chunkSize) {
        binary += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + chunkSize, len)));
    }
    return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary = window.atob(base64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

// Expose functions globally
window.generateRoom = generateRoom;
window.joinChat = joinChat;
window.copyId = copyId;
window.triggerImageUpload = triggerImageUpload;
window.startRecording = startRecording;
window.stopRecording = stopRecording;
window.sendTextMessage = sendTextMessage;
window.closeModal = closeModal;
window.openModal = openModal;