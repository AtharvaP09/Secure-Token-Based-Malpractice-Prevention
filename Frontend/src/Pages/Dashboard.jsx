import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import CreateRoomModal from "./Components/CreateRoomModal";
import JoinRoomModal from "./Components/JoinRoomModal";
import socket from "../socket";
import "./Styles/Dashboard.css";

function Dashboard() {
  const [showCreate, setShowCreate] = useState(false);
  const [showJoin, setShowJoin] = useState(false);
  const [users, setUsers] = useState([]);
  const navigate = useNavigate();

  // Get logged-in username from sessionStorage
  const username = sessionStorage.getItem("username") || "Guest";

  useEffect(() => {
    // Room successfully created
    socket.on("room_created", (data) => {
      alert(`Room Created! ID: ${data.roomId}`);
      setUsers([username]); // creator is first user

      navigate(`/room/${data.roomId}`, {
        state: {
          username,
          password: data.password || "", // just for consistency
          creator: username,
        },
      });
    });

    // Successfully joined room
    socket.on("joined_room", (data) => {
      alert(`Joined Room: ${data.roomId}`);
      setUsers(data.users || []);

      navigate(`/room/${data.roomId}`, {
        state: {
          username,
          password: data.password || "",
          creator: data.creator,
        },
      });
    });

    // Update active users list
    socket.on("user_list", (data) => {
      if (data.roomId) {
        setUsers(data.users || []);
      }
    });

    // Handle errors
    socket.on("error", (err) => {
      alert(err.message);
    });

    return () => {
      socket.off("room_created");
      socket.off("joined_room");
      socket.off("user_list");
      socket.off("error");
    };
  }, [navigate, username]);

  const handleCreate = ({ roomId, password, restricted, startTime }) => {

    console.log(restricted);
    console.log(startTime);
    
    

    socket.emit("create_room", {
      roomId,
      password,
      creator: username,
      restricted,
      startTime,
      // startTime: new Date().toISOString(),
    });
  };

  const handleJoin = ({ roomId, password }) => {
    if (!roomId || !password) {
      alert("Please enter room ID and password");
      return;
    }
    socket.emit("join_room", { roomId, password, username });
  };

  return (
    <div className="dashboard-container">
      <h1>Dashboard</h1>
      <div className="btn-group">
        <button className="btn create" onClick={() => setShowCreate(true)}>
          Create Room
        </button>
        <button className="btn join" onClick={() => setShowJoin(true)}>
          Join Room
        </button>
      </div>

      {showCreate && (
        <CreateRoomModal
          onClose={() => setShowCreate(false)}
          onCreate={handleCreate}
        />
      )}
      {showJoin && (
        <JoinRoomModal
          onClose={() => setShowJoin(false)}
          onJoin={handleJoin}
        />
      )}
    </div>
  );
}

export default Dashboard;
