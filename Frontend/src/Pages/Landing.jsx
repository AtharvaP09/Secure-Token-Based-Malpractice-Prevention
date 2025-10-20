import React, { useState, useEffect } from 'react';
import './Styles/Landing.css'
import { useNavigate } from "react-router-dom";
import LogoTransparent from '../assets/LogoTransparent.png';

function Landing() {
  const navigate = useNavigate()
  const [showScrollTop, setShowScrollTop] = useState(false)

  // Show button when page is scrolled down
  useEffect(() => {
    const handleScroll = () => {
      setShowScrollTop(window.scrollY > 400)
    }

    window.addEventListener('scroll', handleScroll)
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])

  // Scroll to top function
  const scrollToTop = () => {
    window.scrollTo({
      top: 0,
      behavior: 'smooth'
    })
  }

  return (
    <div>
      <div className="bg-animation">
        <div className="floating-element"></div>
        <div className="floating-element"></div>
        <div className="floating-element"></div>
      </div>

      {/* Back to Top Button */}
      {showScrollTop && (
        <button className="back-to-top-btn" onClick={scrollToTop}>
          <svg className="svgIcon" viewBox="0 0 384 512">
            <path
              d="M214.6 41.4c-12.5-12.5-32.8-12.5-45.3 0l-160 160c-12.5 12.5-12.5 32.8 0 45.3s32.8 12.5 45.3 0L160 141.2V448c0 17.7 14.3 32 32 32s32-14.3 32-32V141.2L329.4 246.6c12.5 12.5 32.8 12.5 45.3 0s12.5-32.8 0-45.3l-160-160z"
            ></path>
          </svg>
        </button>
      )}

      <header>
        <nav className="nav-container">
          <div className="logo"><img src={LogoTransparent} alt="Logo" /></div>
          <ul className="nav-links">
            <li><a href="#features">Features</a></li>
            <li><a href="#how-it-works">How It Works</a></li>
            <li><a href="#contact">Contact</a></li>
          </ul>
        </nav>
      </header>

      <main>
        <section className="hero">
          <div className="hero-content">
            <h1>Secure Online Testing Made Simple</h1>
            <p>Advanced anti-cheating technology that monitors, tracks, and reports all user activity during online examinations with military-grade security.</p>
            <button className="cta-button" onClick={() => navigate('/dashboard')}>Get started</button>
          </div>
        </section>

        <section id="features" className="features">
          <div className="section-container">
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
          <div className="section-container">
            <h2 className="section-title">How ExamGuard Works</h2>
            <div className="steps-grid">
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
        <div className="footer-content">
          <h3>Ready to Secure Your Online Exams?</h3>
          <p>Join thousands of educators who trust ExamGuard for fair and secure online testing.</p>
          <button className="cta-button" onClick={() => navigate('/dashboard')}>Get started</button>
        </div>
        <div className="footer-bottom">
          <div className="footer-links">
            <a href="#">Privacy Policy</a>
            <a href="#">Terms of Service</a>
            <a href="#">Documentation</a>
            <a href="#">Support</a>
          </div>
          <div className="copyright">
            <p>&copy; 2025 ExamGuard. All rights reserved.</p>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default Landing;