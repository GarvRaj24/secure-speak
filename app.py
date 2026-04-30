from flask import Flask, render_template, request
from flask_socketio import SocketIO, join_room, emit
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'securespeak-secret-key-change-in-prod')

socketio = SocketIO(app,
    cors_allowed_origins="*",
    max_http_buffer_size=50 * 1024 * 1024,
    ping_timeout=60,
    ping_interval=25
)

@app.route('/')
def index():
    return render_template('index.html')

# --- Chat Events ---

@socketio.on('join')
def on_join(data):
    room = data['room']
    join_room(room)
    emit('user_joined', {'sid': request.sid, 'username': data.get('username', 'Unknown')}, to=room, include_self=False)

@socketio.on('signal_public_key')
def on_signal_public_key(data):
    room = data['room']
    emit('receive_public_key', data, to=room, include_self=False)

@socketio.on('encrypted_message')
def on_encrypted_message(data):
    room = data['room']
    emit('receive_message', {
        'type': data['type'],
        'iv': data['iv'],
        'encryptedKey': data['encryptedKey'],
        'encryptedData': data['encryptedData'],
        'isViewOnce': data.get('isViewOnce', False),
        'username': data.get('username', 'Anonymous')
    }, to=room, include_self=False)

# --- WebRTC Signaling Events ---

@socketio.on('webrtc_offer')
def on_webrtc_offer(data):
    emit('webrtc_offer', data, to=data['room'], include_self=False)

@socketio.on('webrtc_answer')
def on_webrtc_answer(data):
    emit('webrtc_answer', data, to=data['room'], include_self=False)

@socketio.on('webrtc_ice_candidate')
def on_webrtc_ice_candidate(data):
    emit('webrtc_ice_candidate', data, to=data['room'], include_self=False)

@socketio.on('call_request')
def on_call_request(data):
    emit('call_request', {'username': data.get('username', 'Unknown')}, to=data['room'], include_self=False)

@socketio.on('call_accepted')
def on_call_accepted(data):
    emit('call_accepted', {}, to=data['room'], include_self=False)

@socketio.on('call_rejected')
def on_call_rejected(data):
    emit('call_rejected', {}, to=data['room'], include_self=False)

@socketio.on('call_ended')
def on_call_ended(data):
    emit('call_ended', {}, to=data['room'], include_self=False)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') != 'production'
    socketio.run(app, debug=debug, port=port, host='0.0.0.0')