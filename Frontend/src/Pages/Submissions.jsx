import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import "./Styles/Submissions.css";

function Submissions() {
  const { roomid } = useParams();
  const [results, setResults] = useState([]);
  const [openUserId, setOpenUserId] = useState(null);

  useEffect(() => {
    async function getResults() {
      try {
        const response = await fetch("http://localhost:5643/results", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ roomid }),
        });

        const data = await response.json();
        setResults(Array.isArray(data) ? data : []);
      } catch (err) {
        console.error("Failed to fetch submissions:", err);
      }
    }

    getResults();
  }, [roomid]);

  // Convert UNIX timestamp → IST
  const formatIST = (timestamp) => {
    if (!timestamp) return "—";
    const date = new Date(Number(timestamp) * 1000);
    return date.toLocaleString("en-IN", {
      timeZone: "Asia/Kolkata",
      dateStyle: "medium",
      timeStyle: "medium",
    });
  };

  const toggleUser = (userid) => {
    setOpenUserId(openUserId === userid ? null : userid);
  };

  return (
    <div className="submissions-container">
      <h1 className="title">Exam Submissions</h1>

      <div className="results-list">
        {results.length === 0 && (
          <p className="no-results">No submissions found</p>
        )}

        {results.map((sub) => {
          let cheats = [];
          try {
            cheats = JSON.parse(sub.cheats || "[]");
          } catch {
            cheats = [];
          }

          const isOpen = openUserId === sub.userid;

          return (
            <div key={sub.userid} className="user-card">
              {/* HEADER */}
              <div
                className="user-header"
                onClick={() => toggleUser(sub.userid)}
              >
                <h2 className="user-id">{sub.name}</h2>

                <div className="user-meta">
                  {cheats.length > 0 && (
                    <span className="cheat-count">
                      🚫 {cheats.length}
                    </span>
                  )}
                  <span className="arrow">{isOpen ? "▲" : "▼"}</span>
                </div>
              </div>

              {/* DROPDOWN */}
              {isOpen && (
                <div className="user-details">
                  <p className="timing-status">
                    {sub.start
                      ? "✅ Started on time"
                      : "❌ Did not start on time"}
                    {" · "}
                    {sub.end
                      ? "✅ Ended properly"
                      : "❌ Did not end properly"}
                  </p>

                  {cheats.length === 0 ? (
                    <p className="no-cheats">
                      ✅ No banned domains visited
                    </p>
                  ) : (
                    <>
                      <h4 className="cheat-warning">
                        🚫 Banned Domains Visited
                      </h4>
                      <div className="cheats-list">
                        {cheats.map((ch, index) => (
                          <div
                            key={index}
                            className="cheat-item banned"
                          >
                            <span className="domain">
                              {ch.domain}
                            </span>
                            <span className="time">
                              {formatIST(ch.time)}
                            </span>
                          </div>
                        ))}
                      </div>
                    </>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default Submissions;
