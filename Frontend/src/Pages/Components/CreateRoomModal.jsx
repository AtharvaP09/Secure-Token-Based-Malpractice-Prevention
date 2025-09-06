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

  useEffect(() => {
    setRoomId(generateRoomId());
  }, []);

  const handleSubmit = () => {
    if (!password) {
      alert("Please enter a room password");
      return;
    }

    onCreate({ roomId, password, restricted , startTime : starttime});
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

        <div className="modal-actions">
          <button className="btn cancel" onClick={onClose}>Cancel</button>
          <button className="btn create" onClick={handleSubmit}>Create</button>
        </div>
      </div>
    </div>
  );
}

export default CreateRoomModal;
