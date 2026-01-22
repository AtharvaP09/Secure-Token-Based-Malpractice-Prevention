import React, { useState } from "react";
import API from "../api";
import { useNavigate } from "react-router-dom";
import "./Styles/UserAuth.css";
import LogoTransparent from '../assets/LogoTransparent.png';
import { FaUserAlt } from "react-icons/fa";
import { MdEmail } from "react-icons/md";
import { FaLock } from "react-icons/fa";

function UserAuth() {
  const [form, setForm] = useState({ username: "", email: "", password: "" });
  const [isLogin, setIsLogin] = useState(true);
  const [message, setMessage] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();

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
    if (message) setMessage("");
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setMessage("");

    try {
      let res;
      if (isLogin) {
        res = await UserLogin({ email: form.email, password: form.password });
        console.log("Login Response:", res);

        // Save user info in session storage
        sessionStorage.setItem("token", JSON.stringify(res.webtoken));
        sessionStorage.setItem("username", res.username);  
        sessionStorage.setItem("userid", res.userid);
        sessionStorage.setItem("role", res.role);  // This should now be 'user' or 'teacher'
        sessionStorage.setItem("userRole", res.role); // Add this for PairDropDashboard
        sessionStorage.setItem("email", res.email);

        console.log("User role stored:", res.role);
        
        // Check role and redirect accordingly
        if (res.role === 'admin') {
          navigate("/admin");
        } else if (res.role === 'teacher') {
          navigate("/dashboard");  // Teachers go to dashboard
        } else if (res.role === 'user') {
          navigate("/dashboard");  // Students also go to dashboard (will see different options)
        } else {
          // Default fallback
          sessionStorage.setItem("userRole", "user");
          navigate("/dashboard");
        }
      } else {
        // Prevent registration with admin email
        if (form.email.toLowerCase() === "admin@apsit.edu.in") {
          setMessage("Cannot register with admin email address");
          setIsLoading(false);
          return;
        }
        
        res = await UserRegistration(form);
        setMessage(res.message);
        setTimeout(() => setIsLogin(true), 2000);
      }
    } catch (err) {
      console.error("Auth error:", err);
      setMessage(err.message || "Something went wrong");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="auth-container">
      {/* Animated Background */}
      <div className="auth-bg">
        <div className="auth-bubble bubble-1"></div>
        <div className="auth-bubble bubble-2"></div>
        <div className="auth-bubble bubble-3"></div>
        <div className="auth-bubble bubble-4"></div>
      </div>

      <div className="auth-card">
        {/* Header */}
        <div className="auth-header">
          <div className="auth-logo">
            <img src={LogoTransparent} alt="" />
          </div>
          <h2 className="auth-title">
            {isLogin ? "Welcome Back!" : "Create Account!"}
          </h2>
          <p className="auth-subtitle">
            {isLogin ? "Sign in to your account" : "Create a new student account"}
          </p>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="auth-form">
          {!isLogin && (
            <div className="input-group">
              <div className="input-icon"><FaUserAlt /></div>
              <input
                type="text"
                name="username"
                placeholder="Username"
                value={form.username}
                onChange={handleChange}
                required
                className="auth-input"
                disabled={isLoading}
              />
            </div>
          )}
          
          <div className="input-group">
            <div className="input-icon"><MdEmail /></div>
            <input
              type="email"
              name="email"
              placeholder="Email address"
              value={form.email}
              onChange={handleChange}
              required
              className="auth-input"
              disabled={isLoading}
            />
          </div>

          <div className="input-group">
            <div className="input-icon"><FaLock /></div>
            <input
              type="password"
              name="password"
              placeholder="Password"
              value={form.password}
              onChange={handleChange}
              required
              className="auth-input"
              disabled={isLoading}
              minLength="6"
            />
          </div>

          <button 
            type="submit" 
            className="auth-button"
            disabled={isLoading}
          >
            {isLoading ? "Processing..." : (isLogin ? "Sign In" : "Create Account")}
          </button>
        </form>

        {/* Message */}
        {message && (
          <div className={`message ${message.includes('wrong') || message.includes('error') || message.includes('Cannot') ? 'error' : 'success'}`}>
            {message}
          </div>
        )}

        {/* Switch Mode */}
        <div className="auth-switch">
          <p>
            {isLogin ? "Don't have an account?" : "Already have an account?"}{" "}
            <button
              type="button"
              onClick={() => {
                setIsLogin(!isLogin);
                setMessage("");
                setForm({ username: "", email: "", password: "" });
              }}
              className="switch-button"
              disabled={isLoading}
            >
              {isLogin ? "Sign Up" : "Sign In"}
            </button>
          </p>
          
          {/* Note about teacher accounts */}
          {/* {isLogin && (
            <p className="auth-note">
              <small>Teacher accounts must be created by administrator</small>
            </p>
          )} */}
        </div>
      </div>
    </div>
  );
}

export default UserAuth;