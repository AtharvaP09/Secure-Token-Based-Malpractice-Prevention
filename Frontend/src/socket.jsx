import { io } from "socket.io-client";

const socket = io("http://localhost:5643", {
  transports: ["websocket"], // ensures WS only, no long polling
});

export default socket;
