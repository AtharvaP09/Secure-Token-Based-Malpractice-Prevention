import React, { useEffect, useState } from "react";
import { io } from "socket.io-client";
import { useParams } from "react-router-dom";

const socket = io("http://localhost:5643");

function Realtime() {
  const { roomid } = useParams();           // from URL
  const [logs, setLogs] = useState([]);

  // ✅ Get username from sessionStorage
  const username = sessionStorage.getItem("username");

  console.log(username, roomid);
  

  useEffect(() => {
    if (!roomid || !username) return;

    socket.emit("subscribe_logs", {
      roomid,
      username
    });

    socket.on("subscribed_logs", () => {
      console.log("Subscribed to live logs");
    });

    socket.on("live_log", (data) => {
      setLogs((prev) => [data, ...prev]);
    });

    socket.on("error", (err) => {
      console.error(err.message);
    });

    return () => {
      socket.off("live_log");
      socket.off("subscribed_logs");
    };
  }, [roomid, username]);

  // Optional guard if not logged in
  if (!username) {
    return <p>Please log in to view live logs.</p>;
  }

  return (
    <div style={{ padding: "20px" }}>
      <h2>Live Logs — Room {roomid}</h2>

      {logs.length === 0 && (
        <p style={{ opacity: 0.6 }}>Waiting for activity…</p>
      )}

      <div style={{ maxHeight: "70vh", overflowY: "auto" }}>
        {logs.map((log, index) => {
  const isBanned = log.banned === true;

  return (
    <div
      key={index}
      style={{
        padding: "10px",
        marginBottom: "8px",
        borderRadius: "6px",
        background: isBanned ? "#2a0000" : "#111",
        color: isBanned ? "#ff5252" : "#0f0",
        fontFamily: "monospace",
        border: isBanned ? "1px solid red" : "1px solid #222"
      }}
    >
      <div>
        <b>{log.name}</b> (ID: {log.userid})
        {isBanned && (
          <span style={{ marginLeft: "10px", color: "red" }}>
            🚨 BANNED
          </span>
        )}
      </div>

      <div>
        <span style={{ color: isBanned ? "#ff1744" : "#ff9800" }}>
          {log.tag}
        </span>{" "}
        → {log.info}
      </div>

      <div style={{ fontSize: "12px", opacity: 0.7 }}>
        {new Date(log.timestamp * 1000).toLocaleTimeString()}
      </div>
    </div>
  );
})}

      </div>
    </div>
  );
}

export default Realtime;
