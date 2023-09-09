import { useEffect, useRef, useState } from 'react';
import { Outlet, Navigate } from 'react-router-dom';
import Axios from 'axios';

const PrivateRoutes = () => {

  const [isAuthenticated, setIsAuthenticated] = useState(true);

  const data = useRef()
  

  useEffect(() => {

    Axios.get("https://chat-forte-eoa9so6vp-anonymoushs.vercel.app/LoggedIn").then((response) => {

    console.log(response)
      
    data.current = response.data.Message

    if(data.current === "Authorized") {

      setIsAuthenticated(true)

    } else {

      setIsAuthenticated(false)

    }
   
    })

  
  })

  Axios.defaults.withCredentials = true


  
  return isAuthenticated ? <Outlet /> : <Navigate to='/' />;

};

export default PrivateRoutes
