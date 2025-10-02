import './App.css';
import UserAuth from "./pages/UserAuth";
import { Route, Routes, useLocation } from 'react-router-dom';
import { useState, useEffect } from 'react';
import GetToken from './pages/GetToken';
import Dashboard from './pages/Dashboard';
import Landing from './pages/Landing';
import ProtectedRoute from './ProtectedRoute';
import Room from './pages/room';
import Submissions from './pages/Submissions';

function App() {
  const location = useLocation();
  const [displayLocation, setDisplayLocation] = useState(location);
  const [transitionStage, setTransitionStage] = useState('fadeIn');

  useEffect(() => {
    if (location.pathname !== displayLocation.pathname) {
      setTransitionStage('fadeOut');

      // Delay changing the displayed location until transition completes
      const timer = setTimeout(() => {
        setDisplayLocation(location);
        setTransitionStage('fadeIn');
      }, 800); // Half of overlay animation (800ms / 2)

      return () => clearTimeout(timer);
    }
  }, [location, displayLocation]);

  return (
    <div className={`app-content ${transitionStage}`}>
      <Routes location={displayLocation}>
        <Route path="/" element={<Landing />} />
        
        <Route path="/auth" element={<UserAuth />} />
        
        <Route path="/gettoken" element={<GetToken />} />
        
        <Route
          path="/dashboard"
          element={
            <ProtectedRoute>
              <Dashboard />
            </ProtectedRoute>
          }
        />
        
        <Route
          path="/room/:roomId"
          element={
            <ProtectedRoute>
              <Room />
            </ProtectedRoute>
          }
        />
        
        <Route
          path="/submissions/:roomid"
          element={
            <ProtectedRoute>
              <Submissions />
            </ProtectedRoute>
          }
        />
      </Routes>
    </div>
  );
}

export default App;
