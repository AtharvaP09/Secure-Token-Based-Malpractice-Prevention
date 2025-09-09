import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";

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

  return (
    <div>
        <h1>Results</h1>
      <div className="roll">
        {results.map((sub) => {
            let cheats = JSON.parse(sub.cheats)
          return <div key={sub.userid}>
            <h2>{sub.userid}</h2>
            {cheats.map((ch)=><div key={ch.time}>{ch.domain} --- {ch.time}</div>)}
          </div>;
        })}
      </div>
    </div>
  );
}

export default Submissions;
