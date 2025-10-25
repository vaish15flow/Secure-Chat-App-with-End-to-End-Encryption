# server.py
from flask import Flask, request
from flask_socketio import SocketIO, emit, join_room, leave_room, close_room
import logging
import json
from datetime import datetime

# Disable verbose logging from libraries
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

app = Flask(__name__)
# In a real app, use a proper secret key
app.config['SECRET_KEY'] = 'a_very_secret_key!' 
socketio = SocketIO(app, cors_allowed_origins="*")

# Dictionary to store user information {username: {'sid': session_id, 'public_key': key}}
users = {}

@socketio.on('connect')
def handle_connect():
    print(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    print(f"Client disconnected: {request.sid}")
    # Find the user and remove them from our list
    username_to_remove = None
    for username, user_data in users.items():
        if user_data['sid'] == request.sid:
            username_to_remove = username
            break
    if username_to_remove:
        del users[username_to_remove]
        print(f"User {username_to_remove} removed.")
        socketio.emit('user_list_update', list(users.keys()))


@socketio.on('register')
def handle_register(data):
    username = data['username']
    public_key = data['public_key']
    if username in users:
        emit('register_fail', {'message': 'Username already taken.'}, room=request.sid)
        return

    users[username] = {'sid': request.sid, 'public_key': public_key}
    print(f"User '{username}' registered with SID {request.sid}")
    # Notify the user of successful registration and send the current user list
    emit('register_success', list(users.keys()), room=request.sid)
    # Notify all other users of the new user
    socketio.emit('user_list_update', list(users.keys()), skip_sid=request.sid)


@socketio.on('request_user_info')
def handle_user_info_request(data):
    target_username = data['username']
    if target_username in users:
        emit('user_info_response', {
            'username': target_username,
            'public_key': users[target_username]['public_key']
        }, room=request.sid)
    else:
        emit('user_info_fail', {'message': 'User not found.'}, room=request.sid)


@socketio.on('private_message')
def handle_private_message(data):
    recipient = data['recipient']
    encrypted_data = data['encrypted_data']
    sender_username = data['sender'] 

    if recipient in users:
        recipient_sid = users[recipient]['sid']
        
        forward_payload = {
            'sender': sender_username,
            'encrypted_data': encrypted_data
        }
        emit('new_private_message', forward_payload, room=recipient_sid)
        print(f"Relayed encrypted message from {sender_username} to {recipient}")

        # --- THIS IS THE ENCRYPTED LOGGING ---
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'sender': sender_username,
            'recipient': recipient,
            'encrypted_data': encrypted_data # The server stores the encrypted blob
        }
        # Save the log to a file
        with open('secure_chat_logs.log', 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
        # ------------------------------------

    else:
        print(f"Failed to relay: recipient {recipient} not found.")


if __name__ == '__main__':
    print("🚀 Starting secure server...")
    socketio.run(app, port=5001, debug=False)