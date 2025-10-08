// src/pages/PairDropRoom.jsx
import React, { useEffect, useState } from "react";
import { useParams, useLocation, useNavigate } from "react-router-dom";
import socket from "../socket";
import "./Styles/PairDrop.css";
import GetToken from "./GetToken";
import Upload from "./Upload";

export default function PairDropRoom() {
  const { roomId } = useParams();
  const location = useLocation();
  const navigate = useNavigate();

  const username = location.state?.username || sessionStorage.getItem("username") || "Guest";
  const password = location.state?.password || "";
  const creatorFromState = location.state?.creator || "";

  const [creator, setCreator] = useState(creatorFromState);
  const [users, setUsers] = useState([]);
  const [joined, setJoined] = useState(false);
  const [joining, setJoining] = useState(false);
  const [infoMsg, setInfoMsg] = useState("");

  // join on mount if this user is not the creator
        useEffect(() => {
        if (!roomId) {
            alert("Missing room id");
            navigate("/dashboard");
            return;
        }

        const isCreator = username === creator;

        // All users now join via socket
        setJoining(true);
        socket.emit("join_room", { roomId, username, password });

        // socket listeners
        socket.on("joined_room", (data) => {
            if (data && data.roomId === roomId) {
            setCreator(data.creator || creator);
            setUsers(data.users || []);
            setJoined(true);
            }
        });

        socket.on("user_list", (data) => {
            if (data && data.roomId === roomId) {
            setUsers(data.users || []);
            }
        });

    socket.on("error", (err) => {
      // show error and redirect back
      if (err && err.message) {
        alert(err.message);
      }
      navigate("/dashboard");
    });

    return () => {
      // leave room when unmounting
      socket.emit("leave_room", { roomId, username });
      socket.off("joined_room");
      socket.off("user_list");
      socket.off("error");
    };
  }, [roomId, username, navigate, creator, password]);

  function handleLeave() {
    socket.emit("leave_room", { roomId, username });
    navigate("/dashboard");
  }

  // copy room id
  function copyRoomId() {
    navigator.clipboard?.writeText(roomId);
    setInfoMsg("Room ID copied");
    setTimeout(() => setInfoMsg(""), 1800);
  }

  return (
    <div className="pd-shell">
      <div className="pd-panel">
        <div className="pd-left">
          <div className="pd-title">
            <div className="logo">PD</div>
            <div>
              <div className="h1">Room • {roomId}</div>
              <div className="h2">Creator: {creator || "—"}</div>
            </div>
          </div>

          <div style={{ marginTop: 12 }}>
            <div style={{ display: 'flex', gap: 8 }}>
              <button className="pd-btn" onClick={copyRoomId}>Copy Room ID</button>
              <button className="pd-btn ghost" onClick={() => navigator.share?.({ title: 'Join Room', text: `Join room ${roomId}`, url: window.location.href })}>Share</button>
            </div>

            <div style={{ marginTop: 12 }}>
              <div style={{ fontSize: 13, color: 'var(--muted)', marginBottom: 8 }}>Your name</div>
              <div className="tag">{username}</div>
            </div>

            <div style={{ marginTop: 16 }}>
              <div style={{ fontSize: 13, color: 'var(--muted)', marginBottom: 8 }}>Actions</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                {/* Get Token Component */}
                <div>
                  <div style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 4 }}>Download Token</div>
                  <GetToken roomid={roomId} />
                </div>

                {/* Upload Component */}
                <div>
                  <div style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 4 }}>Upload File</div>
                  <Upload />
                </div>

                {/* View Submissions */}
                <div>
                  <button 
                    className="pd-btn" 
                    onClick={() => navigate('/submissions/' + roomId)}
                  >
                    View Submissions
                  </button>
                </div>
              </div>
            </div>

            <div style={{ marginTop: 14 }}>
              <div style={{ fontSize: 13, color: 'var(--muted)', marginBottom: 8 }}>Room info</div>
              <div className="room-item" style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <div style={{ flex: 1 }}>
                  <div style={{ fontWeight: 700 }}>{roomId}</div>
                  <div className="room-meta">Creator: {creator || "—"}</div>
                </div>
                <div>
                  <button className="pd-btn ghost" onClick={handleLeave}>Leave</button>
                </div>
              </div>
            </div>
          </div>

          {infoMsg && <div style={{ marginTop: 12, color: 'var(--success)' }}>{infoMsg}</div>}
        </div>

        <div className="pd-stage">
          <div className="stage-head">
            <div className="stage-title">Participants</div>
            <div className="h2">{users.length} online</div>
          </div>

          <div className="bubble-grid">
            {users.map((u, index) => (
              <div key={u + index} className={`participant enter`}>
                <div className="avatar">{String(u).slice(0, 2).toUpperCase()}</div>
                <div className="pname">{u}</div>
                <div className="pmeta">{u === creator ? "creator" : "participant"}</div>
              </div>
            ))}

            {users.length === 0 && (
              <div style={{ color: 'var(--muted)', padding: 16 }}>No participants yet — waiting for users to join</div>
            )}
          </div>

          <div style={{ marginTop: 12, color: 'var(--muted)', fontSize: 13 }}>
            Tip: participants appear in realtime
          </div>
        </div>
      </div>
    </div>
  );
}