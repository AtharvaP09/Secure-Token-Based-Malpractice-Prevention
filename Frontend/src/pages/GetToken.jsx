import React, { useState } from 'react'

function GetToken() {
  const [userid, setuserID] = useState()

    async function getToken() {
        
        const response = await fetch('http://localhost:5643/gettoken', {
          method : 'POST', 
          headers : {
            'Content-Type' : 'application/json'
          }, 
          body : JSON.stringify({
            roomid : '12345678', 
            name : 'John', 
            userid : userid
          })
        })
        
       const blob = await response.blob();

// Create a download link
const url = window.URL.createObjectURL(blob);
const a = document.createElement('a');
a.href = url;
a.download = `${userid}.zip`; // <-- filename shown to user
document.body.appendChild(a);
a.click();

// Clean up
a.remove();
window.URL.revokeObjectURL(url);
             

    }

  return (
    <div>
      <input type="text" onChange={(e)=>setuserID(e.target.value)} />
        <button onClick={()=>getToken()}>get Token</button>
    </div>
  )
}

export default GetToken