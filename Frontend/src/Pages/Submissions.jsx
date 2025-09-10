import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import "./Styles/Submissions.css"; // external css

function Submissions() {
  const { roomid } = useParams();
  const [results, setResults] = useState([]);

  useEffect(() => {
    async function getResults() {
      const response = await fetch("http://localhost:5643/results", {
        method: "POST",
        headers: {
          "Content-type": "application/json",
        },
        body: JSON.stringify({
          roomid: roomid,
        }),
      });

      const data = await response.json();
      console.log(data);
      setResults(data);
    }

    getResults();
  }, [roomid]);

  // Function to convert to IST properly
  const formatIST = (timestamp) => {
    const date = new Date(parseFloat(timestamp) * 1000);
    return date.toLocaleString("en-IN", {
      timeZone: "Asia/Kolkata",
      dateStyle: "medium",
      timeStyle: "medium",
    });
  };

  return (
    <div className="submissions-container">
      <h1 className="title">Results</h1>
      <div className="results-list">
        {results.map((sub) => {
          let cheats = JSON.parse(sub.cheats);
          return (
            <div key={sub.userid} className="user-card">
              <h2 className="user-id">User: {sub.name}</h2>
              <p>{sub.start ? "Started on time" : "Could not start on time"}, {sub.start ? "ended on time" : "Did not end properly" }</p>
              <div className="cheats-list">
                {cheats.map((ch, index) => (
                  <div key={index} className="cheat-item">
                    <span className="domain">{ch.domain}</span>
                    <span className="time">{formatIST(ch.time)}</span>
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default Submissions;
