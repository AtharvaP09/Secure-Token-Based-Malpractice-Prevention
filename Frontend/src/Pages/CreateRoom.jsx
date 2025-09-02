import React, { useRef } from "react";

function CreateRoom() {
  const timeref = useRef(null);
  const dateref = useRef(null);
  const durationref = useRef(null);

  function createRoom() {
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

    const data = {
      starttime: finalEpoch,
    };

    console.log("Payload to send:", data);
    
  }

  return (
    <div>
      <h1>Create Room</h1>
      <input type="date" ref={dateref} />
      <input type="time" ref={timeref} />
      <input type="number" />
      <button onClick={createRoom}>Create Room</button>
    </div>
  );
}

export default CreateRoom;
