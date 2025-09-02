import React, { useState, useEffect } from "react";
import "../Styles/Dashboard.css";

const generateRoomId = () => {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let id = "";
  for (let i = 0; i < 8; i++) {
    id += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return id;
};

function CreateRoomModal({ onClose, onCreate }) {
  const [roomId, setRoomId] = useState("");
  const [password, setPassword] = useState("");

  useEffect(() => {
    setRoomId(generateRoomId());
  }, []);

  const handleSubmit = () => {
    if (!password) {
      alert("Please enter a room password");
      return;
    }
    onCreate({ roomId, password });
    onClose();
  };

  return (
    <div className="modal-overlay">
      <div className="modal-box">
        <h2>Create Room</h2>
        <p>Room ID: <strong>{roomId}</strong></p>
        <input
          type="password"
          placeholder="Enter Room Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="input-field"
        />
        <div className="modal-actions">
          <button className="btn cancel" onClick={onClose}>Cancel</button>
          <button className="btn create" onClick={handleSubmit}>Create</button>
        </div>
      </div>
    </div>
  );
}

export default CreateRoomModal;
