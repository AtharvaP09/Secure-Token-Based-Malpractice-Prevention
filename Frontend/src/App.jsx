import './App.css'
import { Route, Routes } from 'react-router-dom'
import GetToken from './pages/GetToken'

function App() {

  return (
    <>
    <Routes>
      <Route path= {'/gettoken'} element={<GetToken/>}/>
    </Routes>
    </>
  )
}

export default App
