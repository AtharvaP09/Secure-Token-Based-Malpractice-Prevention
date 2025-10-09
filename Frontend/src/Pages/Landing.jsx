import React from 'react';
import './Styles/Landing.css'
import { useNavigate } from "react-router-dom";
import { FaShield } from "react-icons/fa6";

function Landing() {

  const navigate = useNavigate()

  return (
    <div>
 

      <div className="bg-animation">
        <div className="floating-element"></div>
        <div className="floating-element"></div>
        <div className="floating-element"></div>
      </div>

      <header>
        <nav className="container">
          <div className="logo"><FaShield />ExamGaurd</div>
          <ul className="nav-links">
            <li><a href="Dashboard">Dashboard</a></li>
            <li><a href="#features">Features</a></li>
            <li><a href="#how-it-works">How It Works</a></li>
            <li><a href="#contact">Contact</a></li>
          </ul>
        </nav>
      </header>

      <main>
        <section className="hero">
          <div className="container">
            <h1>Secure Online Testing Made Simple</h1>
            <p>Advanced anti-cheating technology that monitors, tracks, and reports all user activity during online examinations with military-grade security.</p>
            <button className="cta-button" onClick={() => navigate('/dashboard')}>Get started</button>
          </div>
        </section>

        <section id="features" className="features">
          <div className="container">
            <h2 className="section-title">Powerful Anti-Cheating Features</h2>
            <div className="features-grid">
              <div className="feature-card">
                <div className="feature-icon">🔒</div>
                <h3>Secure Room Creation</h3>
                <p>Administrators can create secure examination rooms with unique access codes and time-based restrictions for maximum control.</p>
              </div>
              <div className="feature-card">
                <div className="feature-icon">🎫</div>
                <h3>Token-Based Security</h3>
                <p>Each participant receives a unique encrypted token containing monitoring scripts that ensure exam integrity throughout the session.</p>
              </div>
              <div className="feature-card">
                <div className="feature-icon">📊</div>
                <h3>Real-Time Monitoring</h3>
                <p>Advanced packet monitoring and activity logging tracks every website visit and application usage during the examination period.</p>
              </div>
              <div className="feature-card">
                <div className="feature-icon">📁</div>
                <h3>Detailed Activity Reports</h3>
                <p>Comprehensive logs stored in encrypted format capture all user activities, providing complete transparency and audit trails.</p>
              </div>
              <div className="feature-card">
                <div className="feature-icon">🔐</div>
                <h3>Private Key Decryption</h3>
                <p>Activity logs are encrypted and can only be decrypted by administrators using private keys, ensuring data security and privacy.</p>
              </div>
              <div className="feature-card">
                <div className="feature-icon">🚫</div>
                <h3>Cheating Detection</h3>
                <p>Intelligent analysis of user behavior patterns automatically flags suspicious activities and potential cheating attempts.</p>
              </div>
            </div>
          </div>
        </section>

        <section id="how-it-works" className="how-it-works">
          <div className="container">
            <h2 className="section-title">How ExamGuard Works</h2>
            <div className="steps">
              <div className="step">
                <div className="step-number">1</div>
                <h3>Admin Creates Secure Room</h3>
                <p>Administrators set up examination rooms with custom parameters, time limits, and security configurations tailored to their needs.</p>
              </div>
              <div className="step">
                <div className="step-number">2</div>
                <h3>Students Join & Receive Tokens</h3>
                <p>Participants enter the secure room and automatically receive encrypted tokens containing monitoring scripts and unique identifiers.</p>
              </div>
              <div className="step">
                <div className="step-number">3</div>
                <h3>Continuous Activity Monitoring</h3>
                <p>The system monitors network packets, tracks website visits, and logs all user activities in real-time throughout the exam session.</p>
              </div>
              <div className="step">
                <div className="step-number">4</div>
                <h3>Encrypted Report Generation</h3>
                <p>All monitoring data is compiled into encrypted reports that administrators can decrypt using private keys for review and analysis.</p>
              </div>
            </div>
          </div>
        </section>
      </main>

      <footer id="contact">
        <div className="container">
          <div className="footer-content">
            <h3 style={{marginBottom: '20px'}}>Ready to Secure Your Online Exams?</h3>
            <p style={{marginBottom: '30px', opacity: 0.8}}>Join thousands of educators who trust ExamGuard for fair and secure online testing.</p>
            <button className="cta-button" onClick={() => navigate('/dashboard')}>Get started</button>
          </div>
          <div className="footer-links">
            <a href="#" onClick={(e) => e.preventDefault()}>Privacy Policy</a>
            <a href="#" onClick={(e) => e.preventDefault()}>Terms of Service</a>
            <a href="#" onClick={(e) => e.preventDefault()}>Documentation</a>
            <a href="#" onClick={(e) => e.preventDefault()}>Support</a>
          </div>
          <div className="copyright">
            <p>&copy; 2025 ExamGuard. All rights reserved. Securing online education worldwide.</p>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default Landing;