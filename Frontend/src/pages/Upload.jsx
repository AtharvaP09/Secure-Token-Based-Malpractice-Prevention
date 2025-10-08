// src/Pages/Upload.jsx
import React, { useState } from "react";

export default function Upload() {
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState("");

  async function submit() {
    if (!file) {
      return alert('Please select a file to upload');
    }

    // Get auth token
    const token = sessionStorage.getItem('webtoken');
    const username = sessionStorage.getItem('username');
    const userId = sessionStorage.getItem('user_id');

    console.log('Upload Debug Info:');
    console.log('- File:', file.name, 'Size:', file.size, 'Type:', file.type);
    console.log('- Token exists:', !!token);
    console.log('- Username:', username);
    console.log('- User ID:', userId);

    if (!token) {
      return alert('Not authenticated. Please log in again.');
    }

    setUploading(true);
    setError("");

    try {
      const formdata = new FormData();
      formdata.append('ledger', file);
      
      // Log what we're sending
      console.log('Sending FormData with file:', file.name);

      const response = await fetch('http://localhost:5643/submit', {
        method: 'POST',
        headers: {
          // Don't set Content-Type - let browser set it with boundary for FormData
          'Authorization': 'Bearer ' + token
        },
        body: formdata
      });

      console.log('Response status:', response.status);
      console.log('Response headers:', [...response.headers.entries()]);

      // Try to get response text first
      const responseText = await response.text();
      console.log('Response text:', responseText);

      if (!response.ok) {
        setError(`Server error: ${response.status} - ${responseText}`);
        alert(`Upload failed: ${response.status}\n${responseText}`);
        return;
      }

      // Try to parse as JSON
      let data;
      try {
        data = JSON.parse(responseText);
      } catch (e) {
        console.error('Failed to parse JSON:', e);
        setError('Server returned invalid JSON');
        alert('Server error: Invalid response format');
        return;
      }

      console.log('Parsed data:', data);

      if (data.status && data.status.toLowerCase() === 'success') {
        alert('✅ Upload successful!');
        setFile(null); // Clear file after successful upload
        // Reset file input
        document.querySelector('input[type="file"]').value = '';
      } else {
        setError(data.message || 'Unknown error');
        alert('❌ Upload failed: ' + (data.message || 'Unknown error'));
      }
    } catch (error) {
      console.error('Upload error:', error);
      setError('Network error: ' + error.message);
      alert('❌ Network error: ' + error.message);
    } finally {
      setUploading(false);
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
      <input 
        type="file" 
        onChange={(e) => {
          const selectedFile = e.target.files[0];
          console.log('File selected:', selectedFile);
          setFile(selectedFile);
          setError("");
        }}
        disabled={uploading}
        style={{
          padding: '8px',
          borderRadius: '8px',
          border: '1px solid rgba(255,255,255,0.06)',
          background: 'transparent',
          color: 'var(--muted)',
          fontSize: '13px',
          cursor: uploading ? 'not-allowed' : 'pointer'
        }}
      />
      
      {file && (
        <div style={{ fontSize: '12px', color: 'var(--muted)' }}>
          Selected: {file.name} ({(file.size / 1024).toFixed(2)} KB)
        </div>
      )}

      {error && (
        <div style={{ 
          fontSize: '12px', 
          color: '#ef4444', 
          padding: '6px 8px', 
          borderRadius: '6px',
          background: 'rgba(239, 68, 68, 0.1)'
        }}>
          {error}
        </div>
      )}

      <button 
        className="pd-btn primary" 
        onClick={submit}
        disabled={!file || uploading}
        style={{ 
          opacity: (!file || uploading) ? 0.5 : 1,
          cursor: (!file || uploading) ? 'not-allowed' : 'pointer'
        }}
      >
        {uploading ? 'Uploading...' : 'Upload File'}
      </button>
    </div>
  );
}