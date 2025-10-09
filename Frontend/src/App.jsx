// src/App.js
import './App.css';
import UserAuth from "./pages/UserAuth";
import { Route, Routes, useLocation } from 'react-router-dom';
import { useState, useEffect } from 'react';
import GetToken from './pages/GetToken';
import PairDropDashboard from './Pages/PairDropDashboard'; // <-- new PairDrop dashboard
import Landing from './Pages/Landing';
import ProtectedRoute from './ProtectedRoute';
import PairDropRoom from './pages/PairDropRoom'; // <-- new PairDrop room
import Submissions from './pages/Submissions';

function App() {
  const location = useLocation();
  const [displayLocation, setDisplayLocation] = useState(location);
  const [transitionStage, setTransitionStage] = useState('fadeIn');

  // useEffect(() => {
  //   if (location.pathname !== displayLocation.pathname) {
  //     setTransitionStage('fadeOut');

  //     // Delay changing the displayed location until transition completes
  //     const timer = setTimeout(() => {
  //       setDisplayLocation(location);
  //       setTransitionStage('fadeIn');
  //     }, 800); // Half of overlay animation (800ms / 2)

  //     return () => clearTimeout(timer);
  //   }
  // }, [location, displayLocation]);

  return (
    <div className={`app-content`}>
      <Routes>
        <Route path="/" element={<Landing />} />
        
        <Route path="/auth" element={<UserAuth />} />
        
        <Route path="/gettoken" element={<GetToken />} />
        
        <Route
          path="/dashboard"
          element={
            <ProtectedRoute>
              <PairDropDashboard />
            </ProtectedRoute>
          }
        />
        
        <Route
          path="/room/:roomId"
          element={
            <ProtectedRoute>
              <PairDropRoom />
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
