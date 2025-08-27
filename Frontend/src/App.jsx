import './App.css'
import UserRegistration from "./Pages/UserRegistration";
import { Route, Routes } from 'react-router-dom'
import GetToken from './pages/GetToken'

function App() {

  return (
    <>
      <h3>Secure Token Based Malpractice Prevention , Hello World!!</h3>
      <UserRegistration />
    <Routes>
      <Route path= {'/gettoken'} element={<GetToken/>}/>
    </Routes>
    </>
  )
}

export default App
