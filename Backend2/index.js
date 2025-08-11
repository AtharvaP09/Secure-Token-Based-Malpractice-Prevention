import express from "express"
import crypto from "crypto"

const app = express()
app.use(express.json());

const key = crypto.createHash('sha256').update('my-secret-key').digest();   // 32 bytes
const iv = crypto.createHash('md5').update('Its a fun world').digest(); // 16 bytes

const config = {}
config.iv = 'Its a fun world'
let data = "{\"start\":7687638787,\"id\":\"YGD65363\",\"name\":\"Tom\",\"sessionid\":\"ILU5U\"}"

data = `mobile.events.data.microsoft.com`

const newkey = 'hackathon25'



console.log(createHash(newkey, data));


function createHash(key, data){
const keybuff = Buffer.from(key)
const dataBuff = Buffer.from(data)

const hmac = crypto.createHmac('sha256', keybuff).update(dataBuff).digest('hex')
return hmac
}


app.post('/gettoken', (req, res)=>{
    const body = req.body

    
})

app.listen(5643, ()=>{
    console.log("APP IS RUNNING");
})