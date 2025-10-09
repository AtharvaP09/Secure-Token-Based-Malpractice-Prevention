import React, { useState } from "react";
import API from "../api";
import { useNavigate } from "react-router-dom";
import "./Styles/UserAuth.css";
//React Icons Visit this website for more --> https://react-icons.github.io/react-icons/
import { FaUserAlt } from "react-icons/fa";
import { MdEmail } from "react-icons/md";
import { FaLock } from "react-icons/fa";
import { FaShield } from "react-icons/fa6";

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
    // Clear message when user starts typing
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

        // ✅ Save token and username in session storage
        sessionStorage.setItem("token", JSON.stringify(res.webtoken));
        sessionStorage.setItem("username", res.username);  
        sessionStorage.setItem("user_id", res.user_id);    

        // Redirect to dashboard
        navigate("/dashboard");
      } else {
        res = await UserRegistration(form);
        setMessage(res.message);
        // Switch to login after successful registration
        setTimeout(() => setIsLogin(true), 2000);
      }
    } catch (err) {
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
            <span className="logo-icon"><FaShield /></span>
            <span className="logo-text">ExamGaurd</span>
          </div>
          <h2 className="auth-title">
            {isLogin ? "Welcome Back!" : "Create Account!"}
          </h2>
          {/* <p className="auth-subtitle">
            {isLogin 
              ? "Sign in to access your secure dashboard" 
              : "R"
            }
          </p> */}
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
            className={`auth-button ${isLoading ? 'loading' : ''}`}
            disabled={isLoading}
          >
            {isLoading ? (
              <div className="spinner"></div>
            ) : (
              isLogin ? "Sign In" : "Create Account"
            )}
          </button>
        </form>

        {/* Message */}
        {message && (
          <div className={`message ${message.includes('wrong') || message.includes('error') ? 'error' : 'success'}`}>
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
        </div>

        {/* Features */}
        {/* <div className="auth-features">
          <div className="feature-item">
            <span className="feature-icon">🔒</span>
            <span>Secure Authentication</span>
          </div>
          <div className="feature-item">
            <span className="feature-icon">🚀</span>
            <span>Military-grade Security</span>
          </div>
          <div className="feature-item">
            <span className="feature-icon">📊</span>
            <span>Real-time Monitoring</span>
          </div>
        </div> */}
      </div>
    </div>
  );
}

export default UserAuth;