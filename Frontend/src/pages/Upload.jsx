import React, { useState } from "react";
import "./Styles/Upload.css";

export default function Upload() {
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState("");

  async function submit() {
    if (!file) {
      return alert('Please select a file to upload');
    }

    const token = sessionStorage.getItem('token');
    if (!token) {
      return alert('Not authenticated. Please log in again.');
    }

    setUploading(true);
    setError("");

    try {
      const formdata = new FormData();
      formdata.append('ledger', file);

      const response = await fetch('http://localhost:5643/submit', {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer ' + token
        },
        body: formdata
      });

      const responseText = await response.text();

      if (!response.ok) {
        setError(`Server error: ${response.status} - ${responseText}`);
        alert(`Upload failed: ${response.status}\n${responseText}`);
        return;
      }

      let data;
      try {
        data = JSON.parse(responseText);
      } catch (e) {
        setError('Server returned invalid JSON');
        alert('Server error: Invalid response format');
        return;
      }

      if (data.status && data.status.toLowerCase() === 'success') {
        alert('✅ Upload successful!');
        setFile(null);
        document.querySelector('input[type="file"]').value = '';
      } else {
        setError(data.message || 'Unknown error');
        alert('❌ Upload failed: ' + (data.message || 'Unknown error'));
      }
    } catch (error) {
      setError('Network error: ' + error.message);
      alert('❌ Network error: ' + error.message);
    } finally {
      setUploading(false);
    }
  }

  return (
    <div className="upload-container">
      <input 
        type="file" 
        onChange={(e) => {
          const selectedFile = e.target.files[0];
          setFile(selectedFile);
          setError("");
        }}
        disabled={uploading}
        className="upload-file-input"
      />
      
      {file && (
        <div className="upload-file-info">
          Selected: {file.name} ({(file.size / 1024).toFixed(2)} KB)
        </div>
      )}

      {error && (
        <div className="upload-error">
          {error}
        </div>
      )}

      <button 
        onClick={submit}
        disabled={!file || uploading}
        className="upload-btn"
      >
        {uploading ? 'Uploading...' : 'Upload File'}
      </button>
    </div>
  );
}