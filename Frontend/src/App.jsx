import './App.css'
import UserAuth from "./pages/UserAuth";
import { Route, Routes } from 'react-router-dom'
import GetToken from './pages/GetToken'
import Dashboard from './pages/Dashboard';
import Landing from './pages/Landing'; 
import ProtectedRoute from './ProtectedRoute';
import Room from './pages/room';  
import Submissions from './pages/Submissions';

function App() {
  return (
    <>
      <Routes>
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
      
      <Route path='/submissions/:roomid' element={<ProtectedRoute>
        <Submissions/>
      </ProtectedRoute>}/>
          
      </Routes>
    </>
  )
}

export default App
