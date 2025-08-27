import React, { useState } from "react";

export default function Upload(){

    const [file, setFile] = useState(null)

    async function submit() {
        
        if (!file) {
            return alert('Nothing uploaded')
        }

        const formdata = new FormData()

        formdata.append('ledger', file)

        const response = await fetch('http://localhost:5643/submit', {
            method : 'POST', 
            body : formdata
        });
        

        const data = response.json()

        console.log(data);
        
    }

    return(<>
    <h1>Upload here</h1>

    <input type="file" onChange={(e)=>setFile(e.target.files[0])}/>
    <button onClick={()=>submit()}>Submit</button>
    </>)
}