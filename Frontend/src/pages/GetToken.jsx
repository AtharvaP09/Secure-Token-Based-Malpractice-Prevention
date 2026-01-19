import React, { useState } from 'react';
import './Styles/GetToken.css';
//For git to see the correct path of the file
function GetToken({ roomid }) {
  const [loading, setLoading] = useState(false);

  const getToken = async () => {
    const userid = sessionStorage.getItem('userid');
    const username = sessionStorage.getItem('username');
    const token = sessionStorage.getItem('token');

    console.log(userid, username, token);
    

    if (!userid || !username) {
      alert("Please log in first");
      return;
    }

    if (!roomid) {
      alert("No room ID provided");
      return;
    }

    if (!token) {
      alert("No auth token found. Please log out and log in again.");
      return;
    }

    setLoading(true);

    try {
      const response = await fetch('http://localhost:5643/gettoken', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + token
        },
        body: JSON.stringify({ roomId: roomid })
      });

      if (!response.ok) {
        const text = await response.text();
        alert(`Failed to get token: ${response.status}\n${text}`);
        return;
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${username.toLowerCase()}_${roomid}_${userid}.zip`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);

    } catch (err) {
      alert("Error fetching token: " + err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <button 
      className="download-btn" 
      onClick={getToken}
      disabled={loading}
    >
      {loading ? 'Downloading...' : 'Download Token'}
    </button>
  );
}

export default GetToken;