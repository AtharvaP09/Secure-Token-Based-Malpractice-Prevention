import React, { useState } from 'react';

function GetToken({ roomid }) {
  const [loading, setLoading] = useState(false);

  const getToken = async () => {
    // Get values from sessionStorage
    const userid = sessionStorage.getItem('user_id');
    const username = sessionStorage.getItem('username');
    const token = sessionStorage.getItem('token');

    // Debug logging
    console.log('=== GetToken Debug ===');
    console.log('User ID:', userid);
    console.log('Username:', username);
    console.log('Token exists:', !!token);
    console.log('Token value:', token);
    console.log('Room ID:', roomid);
    console.log('====================');

    // Validation
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
      console.log('Sending request to:', 'http://localhost:5643/gettoken');
      console.log('With body:', { roomId: roomid });
      console.log('With token:', token);

      const response = await fetch('http://localhost:5643/gettoken', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + token
        },
        body: JSON.stringify({ roomId: roomid })
      });

      console.log('Response status:', response.status);
      console.log('Response headers:', [...response.headers.entries()]);

      if (!response.ok) {
        const text = await response.text();
        console.error("Server error response:", text);
        alert(`Failed to get token: ${response.status}\n${text}`);
        return;
      }

      // Check content type
      const contentType = response.headers.get('content-type');
      console.log('Content type:', contentType);

      // Stream zip file
      const blob = await response.blob();
      console.log('Blob size:', blob.size, 'type:', blob.type);

      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${username.toLowerCase()}_${roomid}_${userid}.zip`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);

      console.log('Download initiated successfully');

    } catch (err) {
      console.error('Error:', err);
      alert("Error fetching token: " + err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <button 
      className="pd-btn primary" 
      onClick={getToken}
      disabled={loading}
      style={{
        opacity: loading ? 0.5 : 1,
        cursor: loading ? 'not-allowed' : 'pointer'
      }}
    >
      {loading ? 'Downloading...' : 'Download Token'}
    </button>
  );
}

export default GetToken;
