import React, { useState, useEffect, useRef } from "react";
import "../Styles/PairDrop.css";

const generateRoomId = () => {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let id = "";
  for (let i = 0; i < 8; i++) {
    id += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return id;
};

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
    setRoomId(generateRoomId());
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
      <div className="pd-modal" style={{ width: '500px' }}>
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
          <div style={{ fontSize: '13px', color: 'var(--muted)', marginBottom: '6px' }}>Restricted Domains</div>
          <div style={{ display: 'flex', gap: '8px', marginBottom: '8px' }}>
            <input 
              className="input" 
              placeholder="Add restricted domain" 
              value={domain} 
              onChange={(e) => setDomain(e.target.value)} 
              onKeyPress={(e) => e.key === 'Enter' && addDomain()}
            />
            <button className="pd-btn" onClick={addDomain}>Add</button>
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {restricted.map((d, i) => (
              <div key={i} className="tag">
                {d} <span className="x" onClick={() => removeDomain(i)}>✕</span>
              </div>
            ))}
          </div>
        </div>

        <div style={{ marginBottom: '12px' }}>
          <div style={{ fontSize: '13px', color: 'var(--muted)', marginBottom: '6px' }}>Start Time</div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <input 
              className="input"
              type="date" 
              value={date} 
              onChange={(e) => setDate(e.target.value)} 
            />
            <input 
              className="input"
              type="time" 
              value={time} 
              onChange={(e) => setTime(e.target.value)} 
            />
          </div>
        </div>

        <div style={{ marginBottom: '16px' }}>
          <div style={{ fontSize: '13px', color: 'var(--muted)', marginBottom: '6px' }}>Duration</div>
          <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            <input 
              className="input"
              type="number" 
              min="0" 
              value={hours} 
              onChange={(e) => setHours(e.target.value)} 
              placeholder="Hours"
              style={{ width: '80px' }}
            />
            <span style={{ color: 'var(--muted)' }}>:</span>
            <input 
              className="input"
              type="number" 
              min="0" 
              max="59" 
              value={minutes} 
              onChange={(e) => setMinutes(e.target.value)} 
              placeholder="Minutes"
              style={{ width: '80px' }}
            />
            <span style={{ color: 'var(--muted)' }}>:</span>
            <input 
              className="input"
              type="number" 
              min="0" 
              max="59" 
              value={seconds} 
              onChange={(e) => setSeconds(e.target.value)} 
              placeholder="Seconds"
              style={{ width: '80px' }}
            />
            <span style={{ color: 'var(--muted)', marginLeft: '8px' }}>
              Total: {totalSeconds()}s
            </span>
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

export default CreateRoomModal;