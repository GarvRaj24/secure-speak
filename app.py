from flask import Flask, render_template, request
from flask_socketio import SocketIO, join_room, emit
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'securespeak-secret-key')

socketio = SocketIO(app,
    cors_allowed_origins="*",
    max_http_buffer_size=50 * 1024 * 1024,
    ping_timeout=60,
    ping_interval=25
)

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('join')
def on_join(data):
    room = data['room']
    join_room(room)
    emit('user_joined', {'sid': request.sid, 'username': data.get('username', 'Unknown')}, to=room, include_self=False)

@socketio.on('signal_public_key')
def on_signal_public_key(data):
    emit('receive_public_key', data, to=data['room'], include_self=False)

@socketio.on('encrypted_message')
def on_encrypted_message(data):
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
    emit('rtt_echo', {'echoMsgId': data['echoMsgId']}, to=data['room'], include_self=False)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') != 'production'
    socketio.run(app, debug=debug, port=port, host='0.0.0.0')