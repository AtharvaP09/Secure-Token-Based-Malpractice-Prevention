import React, { useEffect, useState } from "react";
import io from "socket.io-client";
import { useLocation, useNavigate, useParams } from "react-router-dom";
import "./Styles/Room.css";

const socket = io("http://localhost:5643"); // backend Flask-SocketIO server

function Room() {
  const { roomId } = useParams();
  const location = useLocation();
  const navigate = useNavigate();

  // Data passed from Dashboard
  const { username, password, creator: dashboardCreator } = location.state || {};

  const [creator, setCreator] = useState(dashboardCreator || "");
  const [users, setUsers] = useState([]);

  // Fallback username from sessionStorage
  const currentUsername = username || sessionStorage.getItem("username") || "Guest";

  useEffect(() => {
    if (!roomId || !currentUsername) {
      alert("Missing room details. Redirecting...");
      navigate("/dashboard");
      return;
    }

    const isCreator = currentUsername === creator;

    // Only join room if not the creator
    if (!isCreator) {
      socket.emit("join_room", { roomId, username: currentUsername, password });
    } else {
      // If creator, add self to users list
      setUsers([currentUsername]);
    }

    socket.on("joined_room", (data) => {
      setCreator(data.creator);
      setUsers(data.users);
    });

    socket.on("user_list", (data) => {
      if (data.roomId === roomId) {
        setUsers(data.users);
      }
    });

    socket.on("error", (data) => {
      alert(data.message);
      navigate("/dashboard");
    });

    return () => {
      socket.emit("leave_room", { roomId, username: currentUsername });
      socket.off("joined_room");
      socket.off("user_list");
      socket.off("error");
    };
  }, [roomId, currentUsername, password, creator, navigate]);

  const handleLeave = () => {
    socket.emit("leave_room", { roomId, username: currentUsername });
    navigate("/dashboard");
  };

  return (
    <div className="room-container">
      <h1 className="room-title">RoomID: {roomId}</h1>
      <p className="room-creator">
        <strong>Creator:</strong> {creator}
      </p>

      <h2 className="users-title">Active Users</h2>
      <ul className="users-list">
        {users.map((user, index) => (
          <li key={index}>{user}</li>
        ))}
      </ul>

      <button className="leave-btn" onClick={handleLeave}>
        Leave Room
      </button>
    </div>
  );
}

export default Room;
