// Force WebSocket transport to ensure internet-wide connectivity on Render
const socket = io({
    transports: ['websocket']
});

let room = null;
let myKeyPair = null;
let peerPublicKey = null;
let mediaRecorder = null;
let audioChunks = [];
let currentRecordingModeViewOnce = false;
let myUsername = "Anonymous";
let peerUsername = "Unknown";

// CN Panel state
let pendingRttMap = {};
let msgIdCounter  = 0;
let handshakeStart = null;
let hsTimings = {};

// --- SECURITY ENFORCERS ---
document.addEventListener('contextmenu', event => event.preventDefault());
document.addEventListener('keydown', (e) => {
    if (e.keyCode === 123 || (e.ctrlKey && e.shiftKey && (e.keyCode === 73 || e.keyCode === 74))) {
        e.preventDefault(); return false;
    }
    if (e.ctrlKey && e.keyCode === 85) { e.preventDefault(); return false; }
    if (e.ctrlKey && (e.keyCode === 83 || e.keyCode === 80)) { e.preventDefault(); return false; }
    if (e.ctrlKey && e.keyCode === 67) {
        if (document.activeElement.tagName !== 'INPUT') {
            e.preventDefault();
            alert("SECURE TERMINAL: COPY DISABLED");
        }
    }
});
document.addEventListener('dragstart', (e) => e.preventDefault());

window.onload = function() {
    console.log("SecureSpeak System Online");
    const params = new URLSearchParams(window.location.search);
    const urlRoom = params.get('room');
    if (urlRoom) {
        document.getElementById('room-id').value = urlRoom;
        document.getElementById('share-area').classList.remove('hidden');
        document.getElementById('share-link-text').innerText = urlRoom;
        document.getElementById('share-full-url').innerText = window.location.href;
    }

    document.getElementById('btn-create').addEventListener('click', generateRoom);
    document.getElementById('btn-join').addEventListener('click', joinChat);
    document.getElementById('btn-copy').addEventListener('click', copyId);
    document.getElementById('btn-copy-link').addEventListener('click', copyFullLink);
    document.getElementById('room-id').addEventListener('keyup', (e) => { if (e.key === 'Enter') joinChat(); });
    document.getElementById('username-input').addEventListener('keyup', (e) => { if (e.key === 'Enter') document.getElementById('room-id').focus(); });
    document.getElementById('message-input').addEventListener('keydown', (e) => {
        if (e.key === 'Enter') { e.preventDefault(); sendTextMessage(); }
    });
    document.getElementById('toggle-cn-panel').addEventListener('click', toggleCnPanel);
};

function generateRoom() {
    const randomId = Array.from(window.crypto.getRandomValues(new Uint8Array(4)))
        .map(b => b.toString(16).padStart(2, '0')).join('');
    document.getElementById('room-id').value = randomId;
    document.getElementById('share-link-text').innerText = randomId;
    const fullUrl = `${window.location.origin}${window.location.pathname}?room=${randomId}`;
    document.getElementById('share-full-url').innerText = fullUrl;
    document.getElementById('share-area').classList.remove('hidden');
}

async function joinChat() {
    room = document.getElementById('room-id').value.trim();
    const nameInput = document.getElementById('username-input').value.trim();
    myUsername = nameInput.length > 0 ? nameInput : "Anonymous";
    if (!room) return alert("ACCESS DENIED: Room ID Required");

    document.getElementById('display-username').innerText = myUsername.toUpperCase();

    try {
        handshakeStart = performance.now();
        hsTimings = { start: 0 };
        updateHandshakeTimeline();

        myKeyPair = await window.crypto.subtle.generateKey(
            { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
            true, ["encrypt", "decrypt"]
        );
        hsTimings.rsa_keygen = Math.round(performance.now() - handshakeStart);
        updateHandshakeTimeline();

        const newUrl = `${window.location.pathname}?room=${room}`;
        window.history.pushState({}, '', newUrl);

        document.getElementById('login-screen').classList.add('hidden');
        document.getElementById('chat-screen').classList.remove('hidden');
        document.getElementById('display-room').innerText = room;

        socket.emit('join', { room, username: myUsername });
        hsTimings.tcp_connect = Math.round(performance.now() - handshakeStart);
        updateHandshakeTimeline();

    } catch (e) {
        console.error(e);
        alert("CRYPTO ERROR: Browser incompatible");
    }
}

// --- Chat Signaling ---

socket.on('user_joined', async (data) => {
    peerUsername = data.username || "Unknown";
    document.getElementById('status-text').innerHTML = `<span style='color:#bc13fe'>DETECTED: ${peerUsername}</span>`;
    const exportedKey = await window.crypto.subtle.exportKey("jwk", myKeyPair.publicKey);
    socket.emit('signal_public_key', { room, key: exportedKey, request_reply: true, username: myUsername });
    hsTimings.key_exchange_sent = Math.round(performance.now() - handshakeStart);
    updateHandshakeTimeline();
});

socket.on('receive_public_key', async (data) => {
    if (data.username) peerUsername = data.username;
    peerPublicKey = await window.crypto.subtle.importKey(
        "jwk", data.key, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"]
    );
    hsTimings.aes_session = Math.round(performance.now() - handshakeStart);
    updateHandshakeTimeline();

    document.getElementById('status-text').innerHTML = `<span style='color:#00f3ff'>SECURE UPLINK: ${peerUsername}</span>`;
    document.getElementById('connection-dot').classList.add('active');

    if (data.request_reply) {
        const myExportedKey = await window.crypto.subtle.exportKey("jwk", myKeyPair.publicKey);
        socket.emit('signal_public_key', { room, key: myExportedKey, request_reply: false, username: myUsername });
    }
});

// --- Encryption ---

async function encryptAndSend(dataBuffer, type, isViewOnce = false) {
    if (!peerPublicKey) return alert("UPLINK OFFLINE: Wait for peer.");
    try {
        const msgId = ++msgIdCounter;
        const sentAt = performance.now();
        const label = type === 'text'
            ? `"${new TextDecoder().decode(dataBuffer).substring(0, 28)}${dataBuffer.byteLength > 28 ? '…' : ''}"`
            : `[${type}: ${Math.round(dataBuffer.byteLength / 1024)}KB]`;

        const aesKey = await window.crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encryptedData = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, dataBuffer);
        const rawAesKey = await window.crypto.subtle.exportKey("raw", aesKey);
        const encryptedKey = await window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, peerPublicKey, rawAesKey);

        const ivB64  = arrayBufferToBase64(iv);
        const keyB64 = arrayBufferToBase64(encryptedKey);
        const datB64 = arrayBufferToBase64(encryptedData);

        logPacket('OUT', 'encrypted_message', type, ivB64, keyB64, datB64,
                  iv.byteLength + encryptedKey.byteLength + encryptedData.byteLength);

        socket.emit('encrypted_message', {
            room, type, msgId,
            iv: ivB64, encryptedKey: keyB64, encryptedData: datB64,
            isViewOnce, username: myUsername
        });

        pendingRttMap[msgId] = { label, sentAt };

        const msg = isViewOnce && (type === 'image' || type === 'audio') ? `SENT SELF-DESTRUCTING ${type.toUpperCase()}` : null;
        renderMessage(dataBuffer, type, 'sent', msg, isViewOnce, myUsername);
    } catch (err) { console.error("Encryption Error:", err); }
}

socket.on('receive_message', async (data) => {
    try {
        const iv      = base64ToArrayBuffer(data.iv);
        const encKey  = base64ToArrayBuffer(data.encryptedKey);
        const encData = base64ToArrayBuffer(data.encryptedData);

        logPacket('IN', 'receive_message', data.type, data.iv, data.encryptedKey, data.encryptedData,
                  iv.byteLength + encKey.byteLength + encData.byteLength);

        const rawAesKey = await window.crypto.subtle.decrypt({ name: "RSA-OAEP" }, myKeyPair.privateKey, encKey);
        const aesKey = await window.crypto.subtle.importKey("raw", rawAesKey, { name: "AES-GCM" }, false, ["decrypt"]);
        const decryptedData = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, encData);

        renderMessage(decryptedData, data.type, 'received', null, data.isViewOnce, data.username);

        if (data.msgId) socket.emit('rtt_echo', { room, echoMsgId: data.msgId });
    } catch (e) { console.error("Decryption Error:", e); }
});

socket.on('rtt_echo', (data) => {
    const recvAt = performance.now();
    if (data.echoMsgId && pendingRttMap[data.echoMsgId]) {
        const p = pendingRttMap[data.echoMsgId];
        logRtt(p.label, Math.round(recvAt - p.sentAt));
        delete pendingRttMap[data.echoMsgId];
    }
});

// --- Messaging ---

function sendTextMessage() {
    const input = document.getElementById('message-input');
    if (input.value) { encryptAndSend(new TextEncoder().encode(input.value), 'text'); input.value = ''; input.focus(); }
}

function triggerImageUpload(isViewOnce) {
    const fileInput = document.getElementById('image-input');
    fileInput.value = ''; fileInput.onchange = null;
    fileInput.onchange = function() {
        const file = fileInput.files[0];
        if (file) { const reader = new FileReader(); reader.onload = (evt) => encryptAndSend(evt.target.result, 'image', isViewOnce); reader.readAsArrayBuffer(file); }
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
            stream.getTracks().forEach(t => t.stop());
            btn.classList.remove('recording');
        };
        mediaRecorder.start(); btn.classList.add('recording');
    } catch (e) { alert("AUDIO HARDWARE BLOCKED"); }
}

function stopRecording() { if (mediaRecorder && mediaRecorder.state !== 'inactive') mediaRecorder.stop(); }

function renderMessage(buffer, type, source, customText = null, isViewOnce = false, senderName = "Anonymous") {
    const div = document.createElement('div');
    div.className = `message ${source}`;
    const nameLabel = document.createElement('div');
    nameLabel.className = 'sender-name';
    nameLabel.innerText = senderName;
    div.appendChild(nameLabel);

    if (customText) {
        div.innerHTML += `<i class="fas fa-info-circle"></i> ${customText}`;
        div.style.fontFamily = "var(--font-code)"; div.style.fontSize = "0.8rem";
    } else if (type === 'text') {
        div.innerHTML += new TextDecoder().decode(buffer);
    } else if (type === 'image') {
        const blob = new Blob([buffer]); const url = URL.createObjectURL(blob);
        if (isViewOnce && source === 'received') {
            div.innerHTML += `<div class="vo-container"><div style="font-size:1rem;color:var(--neon-red);margin-bottom:5px">HIDDEN DATA</div><button class="vo-btn">REVEAL (10s)</button></div>`;
            div.querySelector('button').onclick = function() {
                openModal(url);
                div.innerHTML = `<span class="sender-name">${senderName}</span><span style="color:var(--neon-blue);font-family:var(--font-code)">[ VIEWING DATA... ]</span>`;
                startDestructTimer(div, url, "[ IMAGE SCRUBBED ]", true);
            };
        } else {
            div.innerHTML += `<div class="media-content"><img src="${url}" onclick="openModal('${url}')" style="cursor:pointer;"></div>`;
        }
    } else if (type === 'audio') {
        const blob = new Blob([buffer]); const url = URL.createObjectURL(blob);
        if (isViewOnce && source === 'received') {
            div.innerHTML += `<div class="vo-container"><div style="font-size:1rem;color:var(--neon-red);margin-bottom:5px">AUDIO LOG</div><button class="vo-btn">PLAY</button></div>`;
            div.querySelector('button').onclick = function() {
                div.innerHTML = `<span class="sender-name">${senderName}</span><audio controls autoplay controlsList="nodownload" src="${url}"></audio>`;
                div.querySelector('audio').onended = function() { startDestructTimer(div, url, "[ AUDIO SCRUBBED ]"); };
            };
        } else { div.innerHTML += `<audio controls controlsList="nodownload" src="${url}"></audio>`; }
    }
    document.getElementById('messages').appendChild(div);
    document.getElementById('messages').scrollTop = document.getElementById('messages').scrollHeight;
}

function startDestructTimer(div, url, msg, closeActiveModal = false) {
    setTimeout(() => {
        div.innerHTML = `<span style="color:#555;font-family:var(--font-code)">${msg}</span>`;
        if (url) URL.revokeObjectURL(url);
        if (closeActiveModal) closeModal();
    }, 10000);
}

function openModal(src) { document.getElementById('image-modal').classList.add('modal-active'); document.getElementById('full-image').src = src; }
function closeModal() { document.getElementById('image-modal').classList.remove('modal-active'); setTimeout(() => { document.getElementById('full-image').src = ''; }, 300); }
function copyId() { const t = document.getElementById('share-link-text').innerText; if (t) { navigator.clipboard.writeText(t); alert("ROOM ID COPIED"); } }
function copyFullLink() { const t = document.getElementById('share-full-url').innerText; if (t) { navigator.clipboard.writeText(t); alert("SHARE LINK COPIED — Send this to your peer!"); } }

// --- CN Panel ---

let cnPanelVisible = false;
let packetLog = [];
let rttLog = [];

function toggleCnPanel() {
    cnPanelVisible = !cnPanelVisible;
    document.getElementById('cn-panel').classList.toggle('hidden', !cnPanelVisible);
    document.getElementById('toggle-cn-panel').style.color = cnPanelVisible ? 'var(--neon-blue)' : '';
    document.getElementById('toggle-cn-panel').style.borderColor = cnPanelVisible ? 'var(--neon-blue)' : '';
}

function logPacket(dir, event, type, ivB64, keyB64, datB64, totalBytes) {
    packetLog.unshift({ dir, event, type, ivB64, keyB64, datB64, totalBytes });
    if (packetLog.length > 20) packetLog.pop();
    renderPacketInspector();
}

function renderPacketInspector() {
    const container = document.getElementById('pkt-list');
    if (!container) return;
    container.innerHTML = packetLog.slice(0, 6).map(p => {
        const dirClass = p.dir === 'OUT' ? 'pkt-out' : 'pkt-in';
        const badge = p.dir === 'OUT'
            ? `<span class="cn-badge cn-badge-green">AES-GCM</span>`
            : `<span class="cn-badge cn-badge-blue">DECRYPTED ✓</span>`;
        const hexPreview = p.datB64.replace(/[^A-Za-z0-9]/g, '').substring(0, 40);
        const kb = (p.totalBytes / 1024).toFixed(1);
        return `<div class="pkt-row">
            <div class="pkt-meta">
                <span class="pkt-dir ${dirClass}">${p.dir}</span>
                <span class="pkt-event">${p.event} ${badge}</span>
                <span class="pkt-size">${kb}KB</span>
            </div>
            <div class="pkt-hex">
                <span class="hex-key">iv:</span> ${p.ivB64.substring(0,16)}…
                &nbsp;<span class="hex-key">key:</span> ${p.keyB64.substring(0,12)}…<br>
                <span class="hex-key">data:</span> ${hexPreview}…
            </div>
        </div>`;
    }).join('') || '<div class="cn-empty">No packets yet — send a message</div>';
}

function logRtt(label, rttMs) {
    rttLog.unshift({ label, rttMs });
    if (rttLog.length > 10) rttLog.pop();
    renderRttPanel();
}

function renderRttPanel() {
    const container = document.getElementById('rtt-list');
    if (!container) return;
    const maxRtt = Math.max(...rttLog.map(r => r.rttMs), 1);
    container.innerHTML = rttLog.slice(0, 6).map(r => {
        const pct = Math.min(Math.round((r.rttMs / maxRtt) * 100), 100);
        const color = r.rttMs < 100 ? 'var(--neon-green)' : r.rttMs < 300 ? 'var(--neon-blue)' : 'var(--neon-red)';
        return `<div class="rtt-row">
            <span class="rtt-label">${r.label}</span>
            <div class="rtt-bar-wrap"><div class="rtt-bar" style="width:${pct}%;background:${color}"></div></div>
            <span class="rtt-val" style="color:${color}">${r.rttMs}ms</span>
        </div>`;
    }).join('') || '<div class="cn-empty">RTT appears after first message exchange</div>';
}

const HS_STEPS = [
    { key: 'start',             label: 'TCP connect',     sub: 'Socket.IO WS',   color: 'var(--neon-blue)' },
    { key: 'rsa_keygen',        label: 'RSA-2048 keygen', sub: 'Web Crypto API', color: 'var(--neon-purple)' },
    { key: 'tcp_connect',       label: 'Room join',       sub: 'Socket.IO emit', color: 'var(--neon-purple)' },
    { key: 'key_exchange_sent', label: 'Key exchange',    sub: 'RSA-OAEP wrap',  color: 'var(--neon-purple)' },
    { key: 'aes_session',       label: 'AES session',     sub: '256-bit GCM',    color: 'var(--neon-green)' },
];

function updateHandshakeTimeline() {
    const container = document.getElementById('hs-steps');
    if (!container) return;
    container.innerHTML = HS_STEPS.map((step, i) => {
        const ms = hsTimings[step.key];
        const done = ms !== undefined;
        const borderStyle = done ? `0.5px solid ${step.color}` : '0.5px solid var(--hs-border)';
        const numBg    = done ? step.color : 'transparent';
        const numColor = done ? '#000' : 'var(--hs-num-color)';
        const labelColor = done ? 'var(--hs-label-done)' : 'var(--hs-label-pending)';
        return `<div class="hs-step" style="border:${borderStyle};">
            <div class="hs-num" style="background:${numBg};color:${numColor};">${done ? '✓' : i+1}</div>
            <div>
                <div class="hs-label" style="color:${labelColor}">${step.label}</div>
                <div class="hs-sub">${step.sub}</div>
            </div>
            <div class="hs-ms">${done ? ms + 'ms' : '—'}</div>
        </div>`;
    }).join('');
}

// --- Utilities ---

function arrayBufferToBase64(buffer) {
    let binary = ''; const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i += 8192)
        binary += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + 8192, bytes.byteLength)));
    return window.btoa(binary);
}
function base64ToArrayBuffer(base64) {
    const binary = window.atob(base64); const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

window.generateRoom = generateRoom; window.joinChat = joinChat;
window.copyId = copyId; window.copyFullLink = copyFullLink;
window.triggerImageUpload = triggerImageUpload;
window.startRecording = startRecording; window.stopRecording = stopRecording;
window.sendTextMessage = sendTextMessage;
window.closeModal = closeModal; window.openModal = openModal;