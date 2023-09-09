import './App.css';
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import LoginPage from './pages/login';
import Register from './pages/register';
import PrivateRoutes from './PrivateRoute/privateRoute';
import WelcomeText from './pages/welcomeText';

function App() {

  return (

    <>

      <BrowserRouter>

        <Routes>

          <Route path='/' element={<LoginPage/>}/>
          <Route path='/register' element={<Register/>}/>

          <Route  element={<PrivateRoutes/>}>

           <Route path='/welcome' element={<WelcomeText/>} exact/>

          </Route>

        </Routes>

      </BrowserRouter>

      
    </>

  );
}

export default App;
