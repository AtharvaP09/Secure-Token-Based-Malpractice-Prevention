import React, { useState } from 'react'
import Upload from './Upload';

function GetToken({roomid}) {
  const [userid, setuserID] = useState(sessionStorage.getItem('user_id'))
  const [username, setUName] = useState(sessionStorage.getItem('username'))

    async function getToken() {

      if(!userid || !username){
        return alert("Pls log in")
      }

      if (!roomid) {
        return alert("No room id")
      }

      console.log(roomid);
        
        const response = await fetch('http://localhost:5643/gettoken', {
          method : 'POST', 
          headers : {
            'Content-Type' : 'application/json', 
            'Authorization' : 'Bearer '+sessionStorage.getItem('token')
          }, 
          body : JSON.stringify({
            roomid : roomid, 
            name : username, 
            userid : userid
          })
        })
        
       const blob = await response.blob();

// Create a download link
const url = window.URL.createObjectURL(blob);
const a = document.createElement('a');
a.href = url;
a.download = `${username.toLowerCase() + String(userid)}.zip`; // <-- filename shown to user
document.body.appendChild(a);
a.click();

// Clean up
a.remove();
window.URL.revokeObjectURL(url);
             

    }

  return (
    <div>
        <button onClick={()=>getToken()}>get Token</button>
    </div>
  )
}

export default GetToken