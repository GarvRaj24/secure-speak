from flask import Flask, render_template, request
from flask_socketio import SocketIO, join_room, emit
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'securespeak-secret-key')

# Force eventlet and allow all origins for internet-wide access.
# Explicitly setting async_mode ensures Render handles the socket handshake correctly.
socketio = SocketIO(app,
    cors_allowed_origins="*",
    max_http_buffer_size=50 * 1024 * 1024,
    ping_timeout=60,
    ping_interval=25,
    async_mode='eventlet'
)

@app.route('/')
def index():
    """Renders the original secure chat interface."""
    return render_template('index.html')

@socketio.on('join')
def on_join(data):
    """Handles users joining specific encrypted rooms."""
    room = data['room']
    join_room(room)
    # Notify peer that a new user has entered the secure zone
    emit('user_joined', {
        'sid': request.sid, 
        'username': data.get('username', 'Unknown')
    }, to=room, include_self=False)

@socketio.on('signal_public_key')
def on_signal_public_key(data):
    """Relays RSA public keys between peers for the initial E2EE handshake."""
    emit('receive_public_key', data, to=data['room'], include_self=False)

@socketio.on('encrypted_message')
def on_encrypted_message(data):
    """Relays pre-encrypted AES payloads. The server cannot read the content."""
    room = data['room']
    emit('receive_message', {
        'type':          data['type'],
        'iv':            data['iv'],
        'encryptedKey':  data['encryptedKey'],
        'encryptedData': data['encryptedData'],
        'isViewOnce':    data.get('isViewOnce', False),
        'username':      data.get('username', 'Anonymous'),
        'msgId':         data.get('msgId'),
    }, to=room, include_self=False)

@socketio.on('rtt_echo')
def on_rtt_echo(data):
    """Relays echo signals back to the sender to calculate network latency (RTT)."""
    emit('rtt_echo', {'echoMsgId': data['echoMsgId']}, to=data['room'], include_self=False)

if __name__ == '__main__':
    # Standard Flask runner for local development. 
    # Production uses the gunicorn command in render.yaml.
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, debug=False, port=port, host='0.0.0.0')