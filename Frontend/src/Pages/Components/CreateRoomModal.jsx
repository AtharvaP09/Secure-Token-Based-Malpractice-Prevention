import React, { useState, useEffect , useRef} from "react";
import "../Styles/Dashboard.css";

const generateRoomId = () => {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let id = "";
  for (let i = 0; i < 8; i++) {
    id += chars.charAt(Math.floor(Math.random() * chars.length)).toUpperCase();
  }
  return id;
};

function CreateRoomModal({ onClose, onCreate }) {
  const [roomId, setRoomId] = useState("");
  const [password, setPassword] = useState("");
  const [restricted, setRestricted] = useState([])
  const [starttime, setstarttime] = useState(0)
  const domainref = useRef(0)
    const timeref = useRef(null);
    const dateref = useRef(null);

  const [hours, setHours] = useState(0);
  const [minutes, setMinutes] = useState(0);
  const [seconds, setSeconds] = useState(0);
  const [duration, setduration] = useState(null);

  const handleSave = () => {
    const totalSeconds = Number(hours) * 3600 + Number(minutes) * 60 + Number(seconds);
    setduration(totalSeconds);
    console.log("Total seconds:", totalSeconds);
  };

  useEffect(() => {
    setRoomId(generateRoomId());
  }, []);

  const handleSubmit = () => {
    if (!password || !roomId || !starttime || !duration) {
      alert("Please fill all the details");
      return;
    }  

    onCreate({ roomId, password, restricted , startTime : starttime, duration});
    onClose();
  };

  function addDomain() {
    let domain = domainref.current.value

    if (!domain) {
      return 
    }

    setRestricted(a => [...a, domain])
    domainref.current.value = ''

  }

  function handleStartTime() {
    const date = dateref.current.value;      // yyyy-mm-dd
    const starttime = timeref.current.value; // hh:mm

    if (!date || !starttime) {
      return alert("Please select a date and time");
    }

    const jsdate = new Date(`${date}T${starttime}`);
    const finalEpoch = jsdate.getTime() / 1000 // epoch in seconds
    const now = Date.now();

    console.log("Chosen time:", finalEpoch);
    console.log("Readable:", jsdate.toString());

    // Check if scheduled more than 2 hours in future

    if (jsdate.getTime() < now) {
      return alert("Invalid time");
    }


    if (jsdate.getTime() - now > 2 * 60 * 60 * 1000) {
      return alert("Start time should be within 2 hours");
    }

    setstarttime(finalEpoch)
    return
  }

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

        {
          restricted.map((domain)=>{
            return <div>{domain}</div>
          })
        }

        <input ref={domainref} type="text" className="input-field" placeholder=""/>
        <button onClick={()=>addDomain()}>Add domain</button>

        <div>
          <h3>Test start time</h3>
      <input type="date" ref={dateref} />
      <input type="time" ref={timeref} />
      <button onClick={handleStartTime}>Save</button>
        </div>
        
         <div style={{ padding: "20px", border: "1px solid #ccc", borderRadius: "8px", width: "250px" }}>
      <h3>Select Duration</h3>

      <div style={{ display: "flex", gap: "10px", marginBottom: "15px" }}>
        <div>
          <label>Hours</label>
          <input
            type="number"
            min="0"
            value={hours}
            onChange={(e) => setHours(e.target.value)}
            style={{ width: "60px" }}
          />
        </div>

        <div>
          <label>Minutes</label>
          <input
            type="number"
            min="0"
            max="59"
            value={minutes}
            onChange={(e) => setMinutes(e.target.value)}
            style={{ width: "60px" }}
          />
        </div>

        <div>
          <label>Seconds</label>
          <input
            type="number"
            min="0"
            max="59"
            value={seconds}
            onChange={(e) => setSeconds(e.target.value)}
            style={{ width: "60px" }}
          />
        </div>
      </div>

      <button onClick={handleSave}>Save</button>

      {duration !== null && (
        <p>Total Time: <strong>{duration} seconds</strong></p>
      )}
    </div>

        <div className="modal-actions">
          <button className="btn cancel" onClick={onClose}>Cancel</button>
          <button className="btn create" onClick={handleSubmit}>Create</button>
        </div>
      </div>
    </div>
  );
}

export default CreateRoomModal;
