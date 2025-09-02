import React, { useState } from "react";
import "../Styles/Dashboard.css"; 

function JoinRoomModal({ onClose, onJoin }) {
  const [roomId, setRoomId] = useState("");
  const [password, setPassword] = useState("");

  const handleSubmit = () => {
    onJoin({ roomId, password });
    onClose();
  };

  return (
    <div className="modal-overlay">
      <div className="modal-box">
        <h2>Join Room</h2>
        <input
          type="text"
          placeholder="Enter Room ID"
          value={roomId}
          onChange={(e) => setRoomId(e.target.value)}
          className="input-field"
        />
        <input
          type="password"
          placeholder="Enter Room Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="input-field"
        />
        <div className="modal-actions">
          <button className="btn cancel" onClick={onClose}>Cancel</button>
          <button className="btn join" onClick={handleSubmit}>Join</button>
        </div>
      </div>
    </div>
  );
}

export default JoinRoomModal;
