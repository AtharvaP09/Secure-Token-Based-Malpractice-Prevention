// src/pages/PairDropDashboard.jsx
import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import socket from "../socket";
import "./Styles/PairDrop.css";

// Inline CreateRoomModal with PairDrop styling
function CreateRoomModal({ onClose, onCreate }) {
  const [roomId, setRoomId] = useState("");
  const [password, setPassword] = useState("");
  const [restricted, setRestricted] = useState([]);
  const [domain, setDomain] = useState("");
  const [date, setDate] = useState("");
  const [time, setTime] = useState("");
  const [hours, setHours] = useState(0);
  const [minutes, setMinutes] = useState(0);
  const [seconds, setSeconds] = useState(0);

  useEffect(() => {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let id = "";
    for (let i = 0; i < 8; i++) {
      id += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    setRoomId(id);
  }, []);

  const addDomain = () => {
    const d = domain.trim();
    if (!d) return;
    setRestricted((r) => [...r, d]);
    setDomain("");
  };

  const removeDomain = (idx) => setRestricted((r) => r.filter((_, i) => i !== idx));

  const totalSeconds = () => Number(hours) * 3600 + Number(minutes) * 60 + Number(seconds);

  const handleCreate = () => {
    if (!password) return alert("Please set a room password");
    if (!date || !time) return alert("Please pick start date & time");
    
    const js = new Date(`${date}T${time}`);
    const now = Date.now();
    
    if (js.getTime() < now) return alert("Start time must be in the future");
    if (js.getTime() - now > 2 * 60 * 60 * 1000) return alert("Start time should be within 2 hours");
    
    const startTime = Math.floor(js.getTime() / 1000);
    const dur = totalSeconds();
    
    if (!dur) return alert("Please set duration");
    
    onCreate({ roomId, password, restricted, startTime, duration: dur });
    onClose();
  };

  return (
    <div className="pd-modal-overlay">
      <div className="pd-modal" style={{ width: '500px', maxHeight: '90vh', overflowY: 'auto' }}>
        <h3 style={{ marginBottom: '16px' }}>Create Room</h3>
        
        <div style={{ marginBottom: '12px' }}>
          <div style={{ fontSize: '13px', color: 'var(--muted)', marginBottom: '6px' }}>Room ID</div>
          <div style={{ fontWeight: 700, fontSize: '16px' }}>{roomId}</div>
        </div>

        <div style={{ marginBottom: '12px' }}>
          <div style={{ fontSize: '13px', color: 'var(--muted)', marginBottom: '6px' }}>Room Password</div>
          <input 
            className="input" 
            type="password"
            placeholder="Enter room password" 
            value={password} 
            onChange={(e) => setPassword(e.target.value)} 
          />
        </div>

        <div style={{ marginBottom: '12px' }}>
          <div style={{ fontSize: '13px', color: 'var(--muted)', marginBottom: '6px' }}>Restricted Domains (Optional)</div>
          <div style={{ display: 'flex', gap: '8px', marginBottom: '8px' }}>
            <input 
              className="input" 
              placeholder="e.g., google.com" 
              value={domain} 
              onChange={(e) => setDomain(e.target.value)} 
              onKeyPress={(e) => e.key === 'Enter' && addDomain()}
            />
            <button className="pd-btn" onClick={addDomain}>Add</button>
          </div>
          {restricted.length > 0 && (
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {restricted.map((d, i) => (
                <div key={i} className="tag">
                  {d} <span className="x" onClick={() => removeDomain(i)}>✕</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div style={{ marginBottom: '12px' }}>
          <div style={{ fontSize: '13px', color: 'var(--muted)', marginBottom: '6px' }}>Start Time</div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <input 
              className="input"
              type="date" 
              value={date} 
              onChange={(e) => setDate(e.target.value)} 
              style={{ flex: 1 }}
            />
            <input 
              className="input"
              type="time" 
              value={time} 
              onChange={(e) => setTime(e.target.value)} 
              style={{ flex: 1 }}
            />
          </div>
        </div>

        <div style={{ marginBottom: '16px' }}>
          <div style={{ fontSize: '13px', color: 'var(--muted)', marginBottom: '6px' }}>Duration</div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <input 
                className="input"
                type="number" 
                min="0" 
                value={hours} 
                onChange={(e) => setHours(e.target.value)} 
                placeholder="0"
                style={{ width: '60px', textAlign: 'center' }}
              />
              <span style={{ fontSize: '12px', color: 'var(--muted)' }}>h</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <input 
                className="input"
                type="number" 
                min="0" 
                max="59" 
                value={minutes} 
                onChange={(e) => setMinutes(e.target.value)} 
                placeholder="0"
                style={{ width: '60px', textAlign: 'center' }}
              />
              <span style={{ fontSize: '12px', color: 'var(--muted)' }}>m</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <input 
                className="input"
                type="number" 
                min="0" 
                max="59" 
                value={seconds} 
                onChange={(e) => setSeconds(e.target.value)} 
                placeholder="0"
                style={{ width: '60px', textAlign: 'center' }}
              />
              <span style={{ fontSize: '12px', color: 'var(--muted)' }}>s</span>
            </div>
            <div style={{ 
              marginLeft: 'auto', 
              padding: '6px 12px', 
              borderRadius: '6px', 
              background: 'rgba(124,58,237,0.1)',
              fontSize: '13px',
              color: 'var(--accent-1)',
              fontWeight: 600
            }}>
              Total: {totalSeconds()}s
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: '20px' }}>
          <button className="pd-btn ghost" onClick={onClose}>Cancel</button>
          <button className="pd-btn primary" onClick={handleCreate}>Create Room</button>
        </div>
      </div>
    </div>
  );
}

// Inline JoinRoomModal with PairDrop styling
function JoinRoomModal({ onClose, onJoin }) {
  const [roomId, setRoomId] = useState("");
  const [password, setPassword] = useState("");

  const handleSubmit = () => {
    if (!roomId || !password) {
      return alert("Please enter both Room ID and Password");
    }
    onJoin({ roomId, password });
    onClose();
  };

  return (
    <div className="pd-modal-overlay">
      <div className="pd-modal">
        <h3 style={{ marginBottom: '16px' }}>Join Room</h3>
        
        <div style={{ marginBottom: '12px' }}>
          <div style={{ fontSize: '13px', color: 'var(--muted)', marginBottom: '6px' }}>Room ID</div>
          <input
            className="input"
            type="text"
            placeholder="Enter 8-character Room ID"
            value={roomId}
            onChange={(e) => setRoomId(e.target.value.toUpperCase())}
            maxLength={8}
          />
        </div>

        <div style={{ marginBottom: '16px' }}>
          <div style={{ fontSize: '13px', color: 'var(--muted)', marginBottom: '6px' }}>Password</div>
          <input
            className="input"
            type="password"
            placeholder="Enter Room Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleSubmit()}
          />
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
          <button className="pd-btn ghost" onClick={onClose}>Cancel</button>
          <button className="pd-btn primary" onClick={handleSubmit}>Join Room</button>
        </div>
      </div>
    </div>
  );
}

// Main Dashboard
export default function PairDropDashboard() {
  const [showCreate, setShowCreate] = useState(false);
  const [showJoin, setShowJoin] = useState(false);
  const [rooms, setRooms] = useState([]);
  const [participantsPreview, setParticipantsPreview] = useState([
    { name: "Alice" }, 
    { name: "Bob" }, 
    { name: "Charlie" }
  ]);

  const navigate = useNavigate();
  const username = sessionStorage.getItem("username") || "Guest";

  useEffect(() => {
    socket.on("room_created", (data) => {
      navigate(`/room/${data.roomId}`, { 
        state: { 
          username, 
          password: data.password || "", 
          creator: username 
        }
      });
    });

    socket.on("user_list", (data) => {
      if (data && data.users) {
        setParticipantsPreview(data.users.map(u => ({ name: u })));
      }
    });

    socket.on("error", (err) => { 
      if (err && err.message) alert(err.message); 
    });

    return () => { 
      socket.off("room_created"); 
      socket.off("user_list"); 
      socket.off("error"); 
    };
  }, [navigate, username]);

  const handleCreate = (payload) => {
    socket.emit("create_room", { 
      roomId: payload.roomId, 
      password: payload.password, 
      creator: username, 
      restricted: payload.restricted, 
      startTime: payload.startTime, 
      duration: payload.duration 
    });
  };

  const handleJoin = ({ roomId, password }) => {
    socket.emit("join_room", { roomId, username, password });
    navigate(`/room/${roomId}`, { state: { username, password } });
  };

  return (
    <div className="pd-shell">
      <div className="pd-panel">
        <div className="pd-left">
          <div className="pd-title">
            <div className="logo">DB</div>
            <div>
              <div className="h1">DeepBlue Rooms</div>
              <div className="h2">Secure exam monitoring</div>
            </div>
          </div>

          <div style={{ marginTop: 16, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <button className="pd-btn primary" onClick={() => setShowCreate(true)}>
              Create Room
            </button>
            <button className="pd-btn" onClick={() => setShowJoin(true)}>
              Join Room
            </button>
          </div>

          <div style={{ marginTop: 14, fontSize: 13, color: 'var(--muted)' }}>
            Logged in as: <strong style={{ color: 'white' }}>{username}</strong>
          </div>

          <div style={{ marginTop: 16 }}>
            <div style={{ fontSize: 13, color: 'var(--muted)', marginBottom: 8 }}>
              Active Rooms
            </div>
            <div className="room-list">
              {rooms.length === 0 && (
                <div className="room-item">
                  <div className="room-meta">No active rooms yet. Create one to get started!</div>
                </div>
              )}
              {rooms.map(r => (
                <div className="room-item" key={r.roomId}>
                  <div>
                    <div style={{ fontWeight: 700 }}>{r.roomId}</div>
                    <div className="room-meta">
                      Creator: {r.creator} • Duration: {r.duration}s
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: 6 }}>
                    <button 
                      className="pd-btn" 
                      onClick={() => navigate(`/room/${r.roomId}`, { 
                        state: { username, password: r.password, creator: r.creator }
                      })}
                    >
                      Enter
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="pd-stage">
          <div className="stage-head">
            <div className="stage-title">Live Preview</div>
            <div className="h2">Recent participants</div>
          </div>
          
          <div className="bubble-grid">
            {participantsPreview.map((p, i) => (
              <div className="participant enter" key={p.name + i}>
                <div className="avatar">{p.name?.slice(0, 2).toUpperCase()}</div>
                <div className="pname">{p.name}</div>
                <div className="pmeta">online</div>
              </div>
            ))}
          </div>

          <div style={{ marginTop: 12, fontSize: 13, color: 'var(--muted)' }}>
            💡 Tip: Create a room to start monitoring exam sessions
          </div>
        </div>
      </div>

      {showCreate && <CreateRoomModal onClose={() => setShowCreate(false)} onCreate={handleCreate} />}
      {showJoin && <JoinRoomModal onClose={() => setShowJoin(false)} onJoin={handleJoin} />}
    </div>
  );
}