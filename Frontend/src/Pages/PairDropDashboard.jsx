// src/pages/PairDropDashboard.jsx
import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import socket from "../socket";
import "./Styles/PairDrop.css";
import LogoTransparent from '../assets/LogoTransparent.png';

// Inline CreateRoomModal with flashy purple styling
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

    if (d === 'all') {
      return addAllDomains();
    }

    setRestricted((r) => [...r, d]);
    setDomain("");
  };

  function addAllDomains() {
    const domains = [
      "openai", "gemini", "copilot", "claude", "perplexity", 
      "huggingface", "pi", "blackbox", "codeium", "replit", "notebooklm"
    ];
    setRestricted(domains);
  }

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
    <div className="eg-modal-overlay">
      <div className="eg-modal">
        <div className="eg-modal-header">
          <h3>Create Exam Room</h3>
          <button className="eg-close-btn" onClick={onClose}>×</button>
        </div>
        
        <div className="eg-modal-body">
          <div className="eg-form-group">
            <label>Room ID</label>
            <div className="eg-room-id">{roomId}</div>
          </div>

          <div className="eg-form-group">
            <label>Room Password</label>
            <input 
              className="eg-input" 
              type="password"
              placeholder="Enter room password" 
              value={password} 
              onChange={(e) => setPassword(e.target.value)} 
            />
          </div>

          <div className="eg-form-group">
            <label>Restricted AI Websites (Optional)</label>
            <div className="eg-domain-selector">
              <select 
                className="eg-input" 
                value={domain} 
                onChange={(e) => setDomain(e.target.value)}
              >
                <option value="">Select AI website to block</option>
                <option value="all">All AI Websites</option>
                <option value="openai">ChatGPT (OpenAI)</option>
                <option value="gemini">Gemini (Google)</option>
                <option value="copilot">Copilot (Microsoft)</option>
                <option value="claude">Claude (Anthropic)</option>
                <option value="perplexity">Perplexity AI</option>
                <option value="huggingface">Hugging Face</option>
                <option value="pi">Pi AI</option>
                <option value="blackbox">Blackbox AI</option>
                <option value="codeium">Codeium</option>
                <option value="replit">Replit</option>
                <option value="notebooklm">NotebookLM</option>
              </select>
              <button className="eg-add-btn" onClick={addDomain}>Add</button>
            </div>
            
            {restricted.length > 0 && (
              <div className="eg-tags-container">
                {restricted.map((d, i) => (
                  <div key={i} className="eg-tag">
                    {d} <span className="eg-tag-remove" onClick={() => removeDomain(i)}>×</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="eg-form-group">
            <label>Exam Start Time</label>
            <div className="eg-time-inputs">
              <input 
                className="eg-input"
                type="date" 
                value={date} 
                onChange={(e) => setDate(e.target.value)} 
              />
              <input 
                className="eg-input"
                type="time" 
                value={time} 
                onChange={(e) => setTime(e.target.value)} 
              />
            </div>
          </div>

          <div className="eg-form-group">
            <label>Exam Duration</label>
            <div className="eg-duration-inputs">
              <div className="eg-duration-field">
                <input 
                  className="eg-input"
                  type="number" 
                  min="0" 
                  value={hours} 
                  onChange={(e) => setHours(e.target.value)} 
                  placeholder="0"
                />
                <span>Hours</span>
              </div>
              <div className="eg-duration-field">
                <input 
                  className="eg-input"
                  type="number" 
                  min="0" 
                  max="59" 
                  value={minutes} 
                  onChange={(e) => setMinutes(e.target.value)} 
                  placeholder="0"
                />
                <span>Minutes</span>
              </div>
              <div className="eg-duration-field">
                <input 
                  className="eg-input"
                  type="number" 
                  min="0" 
                  max="59" 
                  value={seconds} 
                  onChange={(e) => setSeconds(e.target.value)} 
                  placeholder="0"
                />
                <span>Seconds</span>
              </div>
              <div className="eg-total-duration">
                Total: {totalSeconds()} seconds
              </div>
            </div>
          </div>
        </div>

        <div className="eg-modal-footer">
          <button className="eg-btn eg-btn-secondary" onClick={onClose}>Cancel</button>
          <button className="eg-btn eg-btn-primary" onClick={handleCreate}>Create Exam Room</button>
        </div>
      </div>
    </div>
  );
}

// Inline JoinRoomModal with flashy purple styling
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
    <div className="eg-modal-overlay">
      <div className="eg-modal">
        <div className="eg-modal-header">
          <h3>Join Exam Room</h3>
          <button className="eg-close-btn" onClick={onClose}>×</button>
        </div>
        
        <div className="eg-modal-body">
          <div className="eg-form-group">
            <label>Room ID</label>
            <input
              className="eg-input"
              type="text"
              placeholder="Enter 8-character Room ID"
              value={roomId}
              onChange={(e) => setRoomId(e.target.value.toUpperCase())}
              maxLength={8}
            />
          </div>

          <div className="eg-form-group">
            <label>Password</label>
            <input
              className="eg-input"
              type="password"
              placeholder="Enter Room Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleSubmit()}
            />
          </div>
        </div>

        <div className="eg-modal-footer">
          <button className="eg-btn eg-btn-secondary" onClick={onClose}>Cancel</button>
          <button className="eg-btn eg-btn-primary" onClick={handleSubmit}>Join Room</button>
        </div>
      </div>
    </div>
  );
}

// Main Dashboard
export default function PairDropDashboard() {
  const [showCreate, setShowCreate] = useState(false);
  const [showJoin, setShowJoin] = useState(false);

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

    socket.on("error", (err) => { 
      if (err && err.message) alert(err.message); 
    });

    return () => { 
      socket.off("room_created"); 
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
    <div className="eg-dashboard">
      {/* Animated Background */}
      <div className="eg-bg-animation">
        <div className="eg-floating-element"></div>
        <div className="eg-floating-element"></div>
        <div className="eg-floating-element"></div>
      </div>

      {/* Header */}
      <div className="eg-header">
        <div className="eg-header-left">
          <img src={LogoTransparent} alt="ExamGuard" className="eg-logo" />
          <span className="eg-brand"></span>
        </div>
        <div className="eg-header-right">
          <div className="eg-user-info">Welcome, <strong>{username}</strong></div>
        </div>
      </div>

      {/* Main Content */}
      <div className="eg-main-content">
        <div className="eg-hero-section">
          <div className="eg-hero-content">
            <h1 className="eg-hero-title">
            <span className="eg-gradient-text">Secure Exam Monitoring</span>
            </h1>
            <p className="eg-hero-subtitle">
              Advanced anti-cheating technology with military-grade security and real-time monitoring
            </p>
            
            <div className="eg-action-buttons">
              <button className="eg-primary-btn flashy-btn" onClick={() => setShowCreate(true)}>
                <span className="eg-btn-icon"></span>
                Create New Room
                <div className="eg-btn-glow"></div>
              </button>
              <button className="eg-secondary-btn flashy-btn" onClick={() => setShowJoin(true)}>
                <span className="eg-btn-icon"></span>
                Join Existing Room
                <div className="eg-btn-glow"></div>
              </button>
            </div>

            {/* <div className="eg-features-grid">
              <div className="eg-feature-card">
                <div className="eg-feature-icon">🔒</div>
                <h3>Military-grade Security</h3>
                <p>End-to-end encrypted monitoring with advanced protection</p>
              </div>
              <div className="eg-feature-card">
                <div className="eg-feature-icon">📊</div>
                <h3>Real-time Analytics</h3>
                <p>Live activity tracking & comprehensive reporting</p>
              </div>
              <div className="eg-feature-card">
                <div className="eg-feature-icon">🤖</div>
                <h3>AI Detection</h3>
                <p>Smart cheating prevention with pattern recognition</p>
              </div>
            </div> */}
          </div>
        </div>
      </div>

      {/* Modals */}
      {showCreate && <CreateRoomModal onClose={() => setShowCreate(false)} onCreate={handleCreate} />}
      {showJoin && <JoinRoomModal onClose={() => setShowJoin(false)} onJoin={handleJoin} />}
    </div>
  );
}