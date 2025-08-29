import axios from "axios";

const API = axios.create({
    baseURL: "http://127.0.0.1:5643/"
});

export default API;