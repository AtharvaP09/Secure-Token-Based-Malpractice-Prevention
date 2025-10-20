// src/pages/PairDropRoom.jsx
import React, { useEffect, useState } from "react";
import { useParams, useLocation, useNavigate } from "react-router-dom";
import socket from "../socket";
import "./Styles/room.css";
import GetToken from "./GetToken";
import Upload from "./Upload";
//React Icons
import { IoIosCopy } from "react-icons/io";
import { FaShareAlt } from "react-icons/fa";
import { FaEye } from "react-icons/fa";
import { MdDriveFolderUpload } from "react-icons/md";
import { FaDownload } from "react-icons/fa6";


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

  // Check if current user is the creator
  const isCreator = username === creator;

  useEffect(() => {
    if (!roomId) {
      alert("Missing room id");
      navigate("/dashboard");
      return;
    }

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
      if (err && err.message) {
        alert(err.message);
      }
      navigate("/dashboard");
    });

    return () => {
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

  function copyRoomId() {
    navigator.clipboard?.writeText(roomId);
    setInfoMsg("Room ID copied to clipboard!");
    setTimeout(() => setInfoMsg(""), 1800);
  }

  return (
    <div className="eg-room-container">
      {/* Animated Background */}
      <div className="eg-bg-animation">
        <div className="eg-floating-element"></div>
        <div className="eg-floating-element"></div>
        <div className="eg-floating-element"></div>
      </div>

      {/* Header */}
      <div className="eg-room-header">
        <div className="eg-room-header-left">
          <h1 className="eg-room-title">
            Exam Room: <span className="eg-gradient-text">{roomId}</span>
          </h1>
          <p className="eg-room-creator">Created by: {creator || "—"}</p>
        </div>
        <div className="eg-room-header-right">
          <div className="eg-user-badge">
            Welcome,  <strong>{username}</strong>
            {isCreator && <span className="eg-creator-badge"> (Creator)</span>}
          </div>
          <button className="eg-leave-btn" onClick={handleLeave}>
            Leave Room
          </button>
        </div>
      </div>

      {/* Main Content */}
      <div className="eg-room-content">
        {/* Left Sidebar - Controls */}
        <div className="eg-room-sidebar">
          <div className="eg-room-actions">
            <h3>Room Actions</h3>
            
            <div className="eg-action-group">
              <button className="eg-action-btn eg-primary-btn" onClick={copyRoomId}>
                <span className="eg-btn-icon"><IoIosCopy /></span>
                Copy Room ID
              </button>
              
              <button 
                className="eg-action-btn eg-secondary-btn" 
                onClick={() => navigator.share?.({ 
                  title: 'Join Exam Room', 
                  text: `Join exam room ${roomId} on ExamGuard`, 
                  url: window.location.href 
                })}
              >
                <span className="eg-btn-icon"><FaShareAlt /></span>
                Share Room
              </button>
            </div>

            <div className="eg-features-section">
              {/* Download Token - Only for participants (not creator) */}
              {!isCreator && (
                <div className="eg-feature-item">
                  <div className="eg-feature-icon"><FaDownload />
                </div>
                  <div>
                    <div className="eg-feature-title">Download Token</div>
                    <div className="eg-feature-desc">Get monitoring token for this session</div>
                    <GetToken roomid={roomId} />
                  </div>
                </div>
              )}

              {/* Upload Files - Only for participants (not creator) */}
              {!isCreator && (
                <div className="eg-feature-item">
                  <div className="eg-feature-icon"><MdDriveFolderUpload /></div>
                  <div>
                    <div className="eg-feature-title">Upload Files</div>
                    <div className="eg-feature-desc">Submit exam files and documents</div>
                    <Upload roomid={roomId} username={username} />
                  </div>
                </div>
              )}

              {/* View Submissions - Only for creator */}
              {isCreator && (
                <div className="eg-feature-item">
                  <div className="eg-feature-icon"><FaEye /></div>
                  <div>
                    <div className="eg-feature-title">View Submissions</div>
                    <div className="eg-feature-desc">Monitor all student submissions</div>
                    <button 
                      className="eg-action-btn eg-accent-btn" 
                      onClick={() => navigate('/submissions/' + roomId)}
                    >
                      View Submissions
                    </button>
                  </div>
                </div>
              )}

              {/* Creator Information Message */}
              {/* {isCreator && (
                <div className="eg-info-card">
                  <div className="eg-info-icon">ℹ️</div>
                  <div className="eg-info-content">
                    <strong>Creator Access</strong>
                    <p>As the room creator, you can monitor submissions but don't need download/upload tokens.</p>
                  </div>
                </div>
              )} */}
            </div>
          </div>

          {infoMsg && (
            <div className="eg-info-message">
              ✅ {infoMsg}
            </div>
          )}
        </div>

        {/* Right Side - Participants */}
        <div className="eg-room-main">
          <div className="eg-participants-section">
            <div className="eg-section-header">
              <h2>Live Participants</h2>
              <div className="eg-online-count">
                {users.length} {users.length === 1 ? 'person' : 'people'} online
              </div>
            </div>

            <div className="eg-participants-grid">
              {users.map((user, index) => (
                <div key={user + index} className="eg-participant-card">
                  <div className="eg-participant-avatar">
                    {String(user).slice(0, 2).toUpperCase()}
                  </div>
                  <div className="eg-participant-info">
                    <div className="eg-participant-name">{user}</div>
                    <div className={`eg-participant-role ${user === creator ? 'creator' : 'participant'}`}>
                      {user === creator ? ' Creator' : ' Participant'}
                    </div>
                  </div>
                  <div className="eg-participant-status online"></div>
                </div>
              ))}

              {users.length === 0 && (
                <div className="eg-empty-state">
                  <div className="eg-empty-icon">👥</div>
                  <h3>No participants yet</h3>
                  <p>Waiting for users to join the room...</p>
                </div>
              )}
            </div>

            <div className="eg-room-tip">
              Participants appear in real-time as they join the room
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}