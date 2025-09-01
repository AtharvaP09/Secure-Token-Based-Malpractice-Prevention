import './App.css'
import UserAuth from "./pages/UserAuth";
import { Route, Routes } from 'react-router-dom'
import GetToken from './pages/GetToken'
import Dashboard from './pages/Dashboard';
import CreateRoom from './pages/CreateRoom';

function App() {

  return (
    <>
    <Routes>
      <Route path= {'/'} element={<h3>Secure Token Based Malpractice Prevention , Hello World!!</h3>}/>
      <Route path= {'/auth'} element={<UserAuth />}/>
      <Route path= {'/gettoken'} element={<GetToken/>}/>
      <Route path='/dashboard' element={<Dashboard/>}/>
      <Route path='/room' element={<CreateRoom/>}/>

    </Routes>
    </>
  )
}

export default App
