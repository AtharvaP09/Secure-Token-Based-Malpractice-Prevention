from flask_socketio import join_room, leave_room, emit
from app import socketio, con, active_users, request
from datetime import datetime


@socketio.on("create_room")
def handle_create_room(data):
    room_id = data.get("roomId")
    password = data.get("password")
    creator = data.get("creator")  # username from frontend

    # Save room in MySQL -- > start time is set by MySQL
    cursor = con.cursor()
    cursor.execute("""
        INSERT INTO rooms (room_id, password, creator)
        VALUES (%s, %s, %s)
    """, (room_id, password, creator))
    con.commit()
    cursor.close()

    # Add creator to memory
    if room_id not in active_users:
        active_users[room_id] = []
    if creator not in active_users[room_id]:
        active_users[room_id].append(creator) #username(frontend)-->creator(backened)--.creator(frontend)
    join_room(room_id)

    # Confirm room creation to creator
    emit("room_created", {"roomId": room_id, "creator": creator, "password": password}, room=request.sid)


@socketio.on("join_room")
def handle_join(data):
    room_id = data.get("roomId")
    username = data.get("username")
    password = data.get("password")

    # Fetch room from DB
    cursor = con.cursor(dictionary=True)
    cursor.execute("SELECT password, creator FROM rooms WHERE room_id=%s", (room_id,))
    room = cursor.fetchone()
    cursor.close()

    if not room:
        emit("error", {"message": "Room does not exist"})
        return

    # Safe password check
    if (room["password"] or "").strip() != (password or "").strip():
        emit("error", {"message": "Incorrect password"})
        return

    # Join room and update memory
    join_room(room_id)
    if room_id not in active_users:
        active_users[room_id] = []
    if username not in active_users[room_id]:
        active_users[room_id].append(username)

    # Notify joining user
    emit(
        "joined_room",
        {
            "roomId": room_id,
            "creator": room["creator"],
            "users": active_users[room_id],
            "password": password  # echo back password for frontend consistency
        },
        room=request.sid
    )

    # Notify everyone in room
    emit("user_list", {"roomId": room_id, "users": active_users[room_id]}, room=room_id)


@socketio.on("leave_room")
def handle_leave(data):
    room_id = data.get("roomId")
    username = data.get("username")

    leave_room(room_id)

    if room_id in active_users and username in active_users[room_id]:
        active_users[room_id].remove(username)

    # If no users remain, update end_time and delete room
    # Planning to keep it if no creator remains......
    if room_id in active_users and len(active_users[room_id]) == 0:
        cursor = con.cursor()
        cursor.execute(
            "UPDATE rooms SET end_time=%s WHERE room_id=%s",
            (datetime.utcnow(), room_id)
        )
        con.commit()
        cursor.close()
        del active_users[room_id]
    else:
        emit("user_list", {"roomId": room_id, "users": active_users[room_id]}, room=room_id)
