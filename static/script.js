const socket = io();
let room = null;
let myKeyPair = null;
let peerPublicKey = null;
let mediaRecorder = null;
let audioChunks = [];
let currentRecordingModeViewOnce = false;
let myUsername = "Anonymous";
let peerUsername = "Unknown";

// --- WebRTC State ---
let peerConnection = null;
let localStream = null;
let isCallInitiator = false;
let isMuted = false;
let pendingIceCandidates = [];

const ICE_SERVERS = {
    iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' },
        {
            urls: 'turn:openrelay.metered.ca:80',
            username: 'openrelayproject',
            credential: 'openrelayproject'
        },
        {
            urls: 'turn:openrelay.metered.ca:443',
            username: 'openrelayproject',
            credential: 'openrelayproject'
        },
        {
            urls: 'turn:openrelay.metered.ca:443?transport=tcp',
            username: 'openrelayproject',
            credential: 'openrelayproject'
        },
        {
            urls: 'turns:openrelay.metered.ca:443',
            username: 'openrelayproject',
            credential: 'openrelayproject'
        }
    ]
};

// ============================================================
// --- CN PANEL STATE ---
// ============================================================
let pendingRttMap = {};
let msgIdCounter  = 0;
let handshakeStart = null;
let hsTimings = {};
let iceLog = [];

// ============================================================
// --- SECURITY ENFORCERS ---
// ============================================================
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

// ============================================================
// --- INIT ---
// ============================================================
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

// ============================================================
// --- CHAT SIGNALING ---
// ============================================================
socket.on('user_joined', async (data) => {
    peerUsername = data.username || "Unknown";
    document.getElementById('status-text').innerHTML = `<span style='color:#bc13fe'>DETECTED: ${peerUsername}</span>`;

    const exportedKey = await window.crypto.subtle.exportKey("jwk", myKeyPair.publicKey);
    socket.emit('signal_public_key', { room, key: exportedKey, request_reply: true, username: myUsername });

    hsTimings.key_exchange_sent = Math.round(performance.now() - handshakeStart);
    updateHandshakeTimeline();
    showCallBtn(true);
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
    showCallBtn(true);

    if (data.request_reply) {
        const myExportedKey = await window.crypto.subtle.exportKey("jwk", myKeyPair.publicKey);
        socket.emit('signal_public_key', { room, key: myExportedKey, request_reply: false, username: myUsername });
    }
});

// ============================================================
// --- ENCRYPTION + RTT ---
// ============================================================
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
        const recvAt = performance.now();
        const iv      = base64ToArrayBuffer(data.iv);
        const encKey  = base64ToArrayBuffer(data.encryptedKey);
        const encData = base64ToArrayBuffer(data.encryptedData);

        logPacket('IN', 'receive_message', data.type, data.iv, data.encryptedKey, data.encryptedData,
                  iv.byteLength + encKey.byteLength + encData.byteLength);

        const rawAesKey = await window.crypto.subtle.decrypt({ name: "RSA-OAEP" }, myKeyPair.privateKey, encKey);
        const aesKey = await window.crypto.subtle.importKey("raw", rawAesKey, { name: "AES-GCM" }, false, ["decrypt"]);
        const decryptedData = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, encData);

        if (data.echoMsgId && pendingRttMap[data.echoMsgId]) {
            const p = pendingRttMap[data.echoMsgId];
            const rtt = Math.round(recvAt - p.sentAt);
            logRtt(p.label, rtt, data.type);
            delete pendingRttMap[data.echoMsgId];
        }

        renderMessage(decryptedData, data.type, 'received', null, data.isViewOnce, data.username);

        if (data.msgId) {
            socket.emit('rtt_echo', { room, echoMsgId: data.msgId });
        }
    } catch (e) { console.error("Decryption Error:", e); }
});

socket.on('rtt_echo', (data) => {
    const recvAt = performance.now();
    if (data.echoMsgId && pendingRttMap[data.echoMsgId]) {
        const p = pendingRttMap[data.echoMsgId];
        const rtt = Math.round(recvAt - p.sentAt);
        logRtt(p.label, rtt, 'text');
        delete pendingRttMap[data.echoMsgId];
    }
});

// ============================================================
// --- CN PANEL ---
// ============================================================
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
    const entry = { dir, event, type, ivB64, keyB64, datB64, totalBytes };
    packetLog.unshift(entry);
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

function logRtt(label, rttMs, type) {
    rttLog.unshift({ label, rttMs, type });
    if (rttLog.length > 10) rttLog.pop();
    renderRttPanel();
}

function renderRttPanel() {
    const container = document.getElementById('rtt-list');
    if (!container) return;
    const maxRtt = Math.max(...rttLog.map(r => r.rttMs), 1);
    container.innerHTML = rttLog.slice(0, 6).map(r => {
        const pct = Math.min(Math.round((r.rttMs / maxRtt) * 100), 100);
        const color = r.rttMs < 50 ? 'var(--neon-green)' : r.rttMs < 150 ? 'var(--neon-blue)' : 'var(--neon-red)';
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
    { key: 'dtls',              label: 'DTLS-SRTP',       sub: 'E2E voice ready',color: 'var(--neon-green)' },
];

function updateHandshakeTimeline() {
    const container = document.getElementById('hs-steps');
    if (!container) return;
    container.innerHTML = HS_STEPS.map((step, i) => {
        const ms = hsTimings[step.key];
        const done = ms !== undefined;
        const borderStyle = done ? `0.5px solid ${step.color}` : '0.5px solid var(--hs-border)';
        const numBg = done ? step.color : 'transparent';
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

function markDtlsReady() {
    hsTimings.dtls = Math.round(performance.now() - handshakeStart);
    updateHandshakeTimeline();
}

// ============================================================
// --- WebRTC VOICE CALL ---
// ============================================================
async function createPeerConnection() {
    pendingIceCandidates = [];
    peerConnection = new RTCPeerConnection(ICE_SERVERS);
    localStream.getTracks().forEach(track => peerConnection.addTrack(track, localStream));

    peerConnection.ontrack = (event) => {
        const remoteAudio = document.getElementById('remote-audio');
        remoteAudio.srcObject = event.streams[0];
        remoteAudio.play().catch(e => console.error('Audio play error:', e));
    };

    peerConnection.onicecandidate = (event) => {
        if (event.candidate) {
            logIceCandidate(event.candidate);
            socket.emit('webrtc_ice_candidate', { room, candidate: event.candidate });
        }
    };

    peerConnection.onconnectionstatechange = () => {
        const state = peerConnection.connectionState;
        console.log('WebRTC connection state:', state);
        if (state === 'connected') {
            setCallStatus('VOICE ENCRYPTED');
            document.getElementById('call-timer-container').style.display = 'flex';
            startCallTimer();
            markDtlsReady();
        } else if (state === 'disconnected' || state === 'failed' || state === 'closed') {
            endCallCleanup();
        }
    };

    peerConnection.oniceconnectionstatechange = () => {
        console.log('ICE state:', peerConnection.iceConnectionState);
        if (peerConnection.iceConnectionState === 'failed') {
            peerConnection.restartIce();
        }
    };
}

async function addIceCandidate(candidate) {
    if (!peerConnection) return;
    if (!peerConnection.remoteDescription) {
        pendingIceCandidates.push(candidate);
        return;
    }
    try {
        await peerConnection.addIceCandidate(new RTCIceCandidate(candidate));
    } catch (e) {
        console.error('ICE candidate error:', e);
    }
}

async function flushPendingIceCandidates() {
    for (const candidate of pendingIceCandidates) {
        try {
            await peerConnection.addIceCandidate(new RTCIceCandidate(candidate));
        } catch (e) {
            console.error('Flushing ICE error:', e);
        }
    }
    pendingIceCandidates = [];
}

async function initiateCall() {
    if (!peerPublicKey) return alert("UPLINK OFFLINE: Connect to a peer first.");
    if (peerConnection) return;
    try {
        localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
        isMuted = false;
        isCallInitiator = true;
        socket.emit('call_request', { room, username: myUsername });
        showCallOverlay('outgoing');
        setCallStatus('CALLING...');
    } catch (e) {
        alert("MIC ACCESS BLOCKED: Please allow microphone permissions.");
    }
}

socket.on('call_request', (data) => {
    if (peerConnection) return;
    peerUsername = data.username || peerUsername;
    showCallOverlay('incoming');
    setCallStatus(`INCOMING CALL: ${peerUsername}`);
});

async function acceptCall() {
    try {
        localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
        isMuted = false;
        socket.emit('call_accepted', { room });
        showCallOverlay('active');
        await createPeerConnection();
    } catch (e) {
        alert("MIC ACCESS BLOCKED");
        rejectCall();
    }
}

function rejectCall() {
    socket.emit('call_rejected', { room });
    hideCallOverlay();
}

socket.on('call_accepted', async () => {
    showCallOverlay('active');
    await createPeerConnection();
    const offer = await peerConnection.createOffer();
    await peerConnection.setLocalDescription(offer);
    socket.emit('webrtc_offer', { room, sdp: offer });
});

socket.on('call_rejected', () => {
    setCallStatus('CALL REJECTED');
    hideCallOverlay();
    endCallCleanup();
    appendSystemMessage(`${peerUsername} rejected the call.`);
});

socket.on('webrtc_offer', async (data) => {
    if (!peerConnection) return;
    await peerConnection.setRemoteDescription(new RTCSessionDescription(data.sdp));
    await flushPendingIceCandidates();
    const answer = await peerConnection.createAnswer();
    await peerConnection.setLocalDescription(answer);
    socket.emit('webrtc_answer', { room, sdp: answer });
});

socket.on('webrtc_answer', async (data) => {
    if (!peerConnection) return;
    await peerConnection.setRemoteDescription(new RTCSessionDescription(data.sdp));
    await flushPendingIceCandidates();
});

socket.on('webrtc_ice_candidate', async (data) => {
    await addIceCandidate(data.candidate);
});

socket.on('call_ended', () => {
    appendSystemMessage(`${peerUsername} ended the call.`);
    endCallCleanup();
});

function hangUp() { socket.emit('call_ended', { room }); endCallCleanup(); }

function toggleMute() {
    if (!localStream) return;
    isMuted = !isMuted;
    localStream.getAudioTracks().forEach(track => { track.enabled = !isMuted; });
    const btn = document.getElementById('btn-mute');
    btn.innerHTML = isMuted ? '<i class="fas fa-microphone-slash"></i>' : '<i class="fas fa-microphone"></i>';
    btn.style.color = isMuted ? 'var(--neon-red)' : '';
    btn.style.borderColor = isMuted ? 'var(--neon-red)' : '';
}

function endCallCleanup() {
    if (peerConnection) { peerConnection.close(); peerConnection = null; }
    if (localStream) { localStream.getTracks().forEach(t => t.stop()); localStream = null; }
    pendingIceCandidates = [];
    const remoteAudio = document.getElementById('remote-audio');
    if (remoteAudio.srcObject) remoteAudio.srcObject = null;
    stopCallTimer(); hideCallOverlay();
    isCallInitiator = false; isMuted = false;
}

function showCallBtn(show) { document.getElementById('btn-call').style.display = show ? 'flex' : 'none'; }

function showCallOverlay(mode) {
    const overlay = document.getElementById('call-overlay');
    overlay.className = 'call-overlay'; overlay.classList.add(mode);
    overlay.style.display = 'flex';
    document.getElementById('call-peer-name').innerText = peerUsername.toUpperCase();
    document.getElementById('call-accept').style.display = mode === 'incoming' ? 'flex' : 'none';
    document.getElementById('call-reject').style.display  = mode === 'incoming' ? 'flex' : 'none';
    document.getElementById('btn-hangup').style.display   = mode !== 'incoming' ? 'flex' : 'none';
    document.getElementById('btn-mute').style.display     = mode === 'active'   ? 'flex' : 'none';
    document.getElementById('call-timer-container').style.display = 'none';
}

function hideCallOverlay() { document.getElementById('call-overlay').style.display = 'none'; }
function setCallStatus(text) { document.getElementById('call-status').innerText = text; }

let callTimerInterval = null, callSeconds = 0;
function startCallTimer() {
    callSeconds = 0;
    callTimerInterval = setInterval(() => {
        callSeconds++;
        const m = String(Math.floor(callSeconds / 60)).padStart(2, '0');
        const s = String(callSeconds % 60).padStart(2, '0');
        document.getElementById('call-timer').innerText = `${m}:${s}`;
    }, 1000);
}
function stopCallTimer() {
    clearInterval(callTimerInterval); callTimerInterval = null; callSeconds = 0;
    document.getElementById('call-timer').innerText = '00:00';
}

function logIceCandidate(candidate) {
    if (!candidate || !candidate.candidate) return;
    const raw = candidate.candidate;
    let type = 'host';
    if (raw.includes('srflx')) type = 'srflx';
    else if (raw.includes('relay')) type = 'relay';
    const addrMatch = raw.match(/(\d+\.\d+\.\d+\.\d+|\S+?) (\d+) /);
    const addr = addrMatch ? `${addrMatch[1]}:${addrMatch[2]}` : raw.substring(0, 30);
    iceLog.unshift({ type, addr });
}

// ============================================================
// --- MESSAGING ---
// ============================================================
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

function appendSystemMessage(text) {
    const div = document.createElement('div');
    div.style.cssText = 'text-align:center;color:#555;font-family:var(--font-code);font-size:0.7rem;padding:5px;';
    div.innerText = `── ${text} ──`;
    document.getElementById('messages').appendChild(div);
    document.getElementById('messages').scrollTop = document.getElementById('messages').scrollHeight;
}

function openModal(src) { document.getElementById('image-modal').classList.add('modal-active'); document.getElementById('full-image').src = src; }
function closeModal() { document.getElementById('image-modal').classList.remove('modal-active'); setTimeout(() => { document.getElementById('full-image').src = ''; }, 300); }
function copyId() { const t = document.getElementById('share-link-text').innerText; if (t) { navigator.clipboard.writeText(t); alert("ROOM ID COPIED"); } }
function copyFullLink() { const t = document.getElementById('share-full-url').innerText; if (t) { navigator.clipboard.writeText(t); alert("SHARE LINK COPIED — Send this to your peer!"); } }

function arrayBufferToBase64(buffer) {
    let binary = ''; const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i += 8192) binary += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + 8192, bytes.byteLength)));
    return window.btoa(binary);
}
function base64ToArrayBuffer(base64) {
    const binary = window.atob(base64); const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

window.generateRoom = generateRoom; window.joinChat = joinChat; window.copyId = copyId;
window.copyFullLink = copyFullLink; window.triggerImageUpload = triggerImageUpload;
window.startRecording = startRecording; window.stopRecording = stopRecording;
window.sendTextMessage = sendTextMessage; window.closeModal = closeModal; window.openModal = openModal;
window.initiateCall = initiateCall; window.acceptCall = acceptCall; window.rejectCall = rejectCall;
window.hangUp = hangUp; window.toggleMute = toggleMute;