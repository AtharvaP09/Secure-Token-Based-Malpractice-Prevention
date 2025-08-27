import './App.css'
import UserAuth from "./Pages/UserAuth";
import { Route, Routes } from 'react-router-dom'
import GetToken from './pages/GetToken'

function App() {

  return (
    <>
    <Routes>
      <Route path= {'/'} element={<h3>Secure Token Based Malpractice Prevention , Hello World!!</h3>}/>
      <Route path= {'/UserAuth'} element={<UserAuth />}/>
      <Route path= {'/gettoken'} element={<GetToken/>}/>
    </Routes>
    </>
  )
}

export default App
