import { useState, useEffect } from 'react'
import {Link} from 'react-router-dom'
import Axios from 'axios'

const RegisterComponent = () => {

  const [fullName, setFullName] = useState();
  const [emailAddress, setEmailAddress] = useState();
  const [password, setPassword] = useState();
  const [repPass, setRepPass] = useState()

  const RegInfo = {
    full_name: fullName,
    email_address: emailAddress,
    password: password
  }

  const RegisterUser = () => {

    Axios.post("https://apps-akowp4kqp-anonymoushs.vercel.app/registerUser", RegInfo).then(() => {
      console.log("Registered")
    }).catch((error) => {
      console.log(error)
    })

  }
  

  return (

    <>
       <div className="container-md ">

      <div className="mt-5">
        <h2 className="text-center"> <i class="fa-regular fa-comments"></i> ChatForte</h2>
      </div>
      
      <div className="text-center mt-5">
        <h4>Register</h4>
        <p className="sign-in-text">Get your ChatForte account now.</p>
      </div>

      <div className="d-flex justify-content-center mt-5">

          <form className="form-container row d-flex justify-content-center col-lg-5 pb-5 pt-5">

            <div className="d-flex flex-column col-lg-8 mb-3">
              <label className="mb-2" htmlFor="emailLogin">Full Name</label>
              <input  value={fullName} onChange={(e) => {setFullName(e.target.value)}} type="text" className="pt-2 pb-2  col-lg-12" id="emailLogin"/>
            </div>

            <div className="d-flex flex-column col-lg-8 mb-3">
              <label className="mb-2" htmlFor="emailLogin">Email Address</label>
              <input  value={emailAddress} onChange={(e) => {setEmailAddress(e.target.value)}} type="text" className="pt-2 pb-2  col-lg-12" id="emailLogin"/>
            </div>

            <div className="d-flex flex-column col-lg-8 mb-4">
              <label className="mb-2" htmlFor="passLogin">Password</label>
              <input value={password} onChange={(e) => {setPassword(e.target.value)}} type="password" className="pt-2 pb-2" id="passLogin"/>
            </div>

            <div className="d-flex flex-column col-lg-8 mb-4">
              <label className="mb-2" htmlFor="passLogin">Repeat Password</label>
              <input  value={repPass} onChange={(e) => { setRepPass(e.target.value) }} type="password" className="pt-2 pb-2" id="passLogin"/>
            </div>

           

          
            <div className="col-lg-8">
             <button className="pt-2 pb-2 col-lg-12" onClick={RegisterUser}>Register</button>
            </div>

            

          </form>

      </div>

      <div className="d-flex justify-content-center mt-5 ">

        <div>

        <p>Already have an account ? <span><Link className="signup-link" to='/'>Sign in</Link></span></p>
        <p>©2023 ChatForte. Created by Frances</p>

        </div>
        
      </div>

      </div>
    </>

  )

}


export default RegisterComponent
