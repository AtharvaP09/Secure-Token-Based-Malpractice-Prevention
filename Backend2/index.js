import express from "express";
import crypto from "crypto";
import cors from "cors";
import fs from "fs";
import path from "path";
import archiver from "archiver";
import multer from "multer";
import mysql2 from 'mysql2'

const app = express();
app.use(express.json());
app.use(
  cors({
    origin: "*",
    methods: "GET,POST",
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// const config = {}
// config.iv = 'Its a fun world'
// let data = "{\"start\":7687638787,\"id\":\"YGD65363\",\"name\":\"Tom\",\"sessionid\":\"ILU5U\"}"
// const newkey = 'hackathon25'

const storage = multer.memoryStorage()
const upload = multer({storage})

function deriveKeyAndIv(keyStr, ivStr) {
  const key = crypto.createHash("sha256").update(keyStr).digest(); // 32 bytes
  const iv = crypto.createHash("md5").update(ivStr).digest(); // 16 bytes
  return { key, iv };
}

function encrypt(plaintext, keyStr, ivStr) {
  const { key, iv } = deriveKeyAndIv(keyStr, ivStr);

  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  let encrypted = cipher.update(plaintext, "utf8", "base64");
  encrypted += cipher.final("base64");

  return encrypted;
}

function decrypt(ciphertextB64, keyStr, ivStr) {
  const { key, iv } = deriveKeyAndIv(keyStr, ivStr);

  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  let decrypted = decipher.update(ciphertextB64, "base64", "utf8");
  decrypted += decipher.final("utf8");

  return decrypted;
}

function createHash(key, data) {
  const keybuff = Buffer.from(key);
  const dataBuff = Buffer.from(data);

  const hmac = crypto
    .createHmac("sha256", keybuff)
    .update(dataBuff)
    .digest("hex");
  return hmac;
}


app.post("/gettoken",async (req, res) => {


  const { roomid, name, userid } = req.body;

  const keystring = "hackathon25";
  const key = Buffer.from(keystring, "utf8");

  //data  = "{\"start\":7687638787,\"id\":\"YGD65363\",\"name\":\"Cruise\",\"sessionid\":\"ILU5U\"}"

  //user should take name, sessionid only
  //start time, duration can be derived from the sessionid my looking into db
  //iv string can be auto generated

  const baseDir = path.join(process.cwd(), "temp_tokens");
  if (!fs.existsSync(baseDir)) fs.mkdirSync(baseDir);

  const userDir = path.join(baseDir, String(userid));
  try {
    fs.mkdirSync(userDir);
  } catch (error) {
    console.log(error.message);
  }

  const sourceExe = path.join(process.cwd(), "token", "sniffer.exe");
  const destExe = path.join(userDir, "token.exe");
  fs.copyFileSync(sourceExe, destExe);

  const data = {};
  data.name = name;
  data.roomid = roomid;
  data.userid = userid;

  //get data from sql db

  const iv = "deg83tbd87682r3e2b";

  const config = {};

  const ciphertext = encrypt(JSON.stringify(data), keystring, iv);

  const hmacInput = Buffer.concat([
    Buffer.from(iv, "utf8"),
    Buffer.from(ciphertext, "utf8"),
  ]);

  const hmac = crypto.createHmac("sha256", key).update(hmacInput).digest("hex");

  config.iv = iv;
  config.data = ciphertext;
  config.hmac = hmac;

  console.log(config);

  fs.writeFileSync(
    path.join(userDir, "config.json"),
    JSON.stringify(config, null, 4)
  );

 const zipPath = path.join(baseDir, `${userid}.zip`);
  const output = fs.createWriteStream(zipPath);
  const archive = archiver("zip", { zlib: { level: 9 } });

  output.on("close", () => {
    console.log(`Created zip: ${zipPath} (${archive.pointer()} bytes)`);
    res.download(zipPath, `${userid}.zip`, (err) => {
      if (err) console.error("Download error:", err);
      
      try {
        // remove zip
        if (fs.existsSync(zipPath)) fs.unlinkSync(zipPath);

        // remove folder recursively
        // if (fs.existsSync(userDir)) {
        //   fs.rmSync(userDir, { recursive: true, force: true });
        // }

        console.log(`Cleaned up ${zipPath} and ${userDir}`);
      } catch (cleanupErr) {
        console.error("Cleanup error:", cleanupErr);
      }

    });
  });

  archive.on("error", (err) => {
    throw err;
  });

  archive.pipe(output);
  archive.directory(userDir, false);
  archive.finalize();
});

app.post('/submit', upload.single("ledger"),  (req, res)=>{
  try{

    const fileBuffer = req.file.buffer; // it's a Buffer
    const text = fileBuffer.toString("utf-8"); // read as text

    console.log("Uploaded file content");

    //analyze the text

    console.log('doing something');
    
    const words = text.split(',')
    console.log(words);

    //get meta info about submission

    for (let index = 0; index < words.length; index++) {
      const word = words[index];
      
      let tag = word.split(':')[0]
      let value = word.split(':')[1]

      console.log({tag, value});
     
      
      
    }
    
    res.json({ status: "success", length: text.length });


  }catch{

  }
})

app.listen(5643, () => {
  console.log("APP IS RUNNING");
});
