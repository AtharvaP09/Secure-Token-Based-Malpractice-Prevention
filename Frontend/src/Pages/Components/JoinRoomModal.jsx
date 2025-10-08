import React, { useState } from "react";
import "../Styles/PairDrop.css";
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
            placeholder="Enter Room ID"
            value={roomId}
            onChange={(e) => setRoomId(e.target.value)}
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
          />
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
          <button className="pd-btn ghost" onClick={onClose}>Cancel</button>
          <button className="pd-btn primary" onClick={handleSubmit}>Join</button>
        </div>
      </div>
    </div>
  );
}
export default JoinRoomModal;