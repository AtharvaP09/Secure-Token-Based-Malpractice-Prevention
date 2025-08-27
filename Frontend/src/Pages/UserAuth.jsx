import React, { useState } from "react";
import API from "../api";

function UserAuth() {
  const [form, setForm] = useState({ username: "", email: "", password: "" });
  const [isLogin, setIsLogin] = useState(true);
  const [message, setMessage] = useState("");



  const UserRegistration = async (userData) => {
    try {
      const res = await API.post("/UserRegistration", userData);
      return res.data;
    } catch (err) {
      throw err.response.data;
    }
  };


  const UserLogin = async (userData) => {
    try {
      const res = await API.post("/UserLogin", userData);
      return res.data;
    } catch (err) {
      throw err.response.data;
    }
  };


  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };


  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      let res;
      if (isLogin) {
        res = await UserLogin({ email: form.email, password: form.password });
      } else {
        res = await UserRegistration(form);
      }
      setMessage(res.message);
    } catch (err) {
      setMessage(err.message || "Something went wrong");
    }
  };

  return (
    <div style={{ width: "300px", margin: "auto", marginTop: "50px" }}>
      <h2>{isLogin ? "Login" : "Register"}</h2>
      <form onSubmit={handleSubmit}>
        {!isLogin && (
          <input
            type="text"
            name="username"
            placeholder="Username"
            value={form.username}
            onChange={handleChange}
            required
          />
        )}
        <br />
        <input
          type="email"
          name="email"
          placeholder="Email"
          value={form.email}
          onChange={handleChange}
          required
        />
        <br />
        <input
          type="password"
          name="password"
          placeholder="Password"
          value={form.password}
          onChange={handleChange}
          required
        />
        <br />
        <button type="submit">{isLogin ? "Login" : "Register"}</button>
      </form>

      <p style={{ marginTop: "10px" }}>
        {isLogin ? "Don't have an account?" : "Already have an account?"}{" "}
        <button
          type="button"
          onClick={() => {
            setIsLogin(!isLogin);
            setMessage("");
          }}
        >
          {isLogin ? "Register" : "Login"}
        </button>
      </p>

      {message && <p>{message}</p>}
    </div>
  );
}

export default UserAuth;
