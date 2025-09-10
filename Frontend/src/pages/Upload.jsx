import React, { useState } from "react";

export default function Upload(){

    const [file, setFile] = useState(null)

async function submit() {
    if (!file) {
        return alert('Nothing uploaded');
    }

    try {
        const formdata = new FormData();
        formdata.append('ledger', file);

        const response = await fetch('http://localhost:5643/submit', {
            method: 'POST',
            body: formdata
        });

        if (!response.ok) {
            return alert('Server error: ' + response.status);
        }

        const data = await response.json();
        console.log(data);

        if (data.status && data.status.toLowerCase() === 'success') {
            alert(' Upload successful!');
        } else {
            alert(' Upload failed: ' + (data.message || 'Unknown error'));
        }
    } catch (error) {
        console.error(error);
        alert(' Network error: ' + error.message);
    }
}


    return(<>
    <h1>Upload here</h1>

    <input type="file" onChange={(e)=>setFile(e.target.files[0])}/>
    <button onClick={()=>submit()}>Submit</button>
    </>)
}