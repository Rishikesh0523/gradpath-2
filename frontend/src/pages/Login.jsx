import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import axios from '../services/axiosConfig';

const Login = () => {
  const [formData, setFormData] = useState({
    email: '',
    password: ''
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({
      ...formData,
      [name]: value
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    
    try {
      console.log('Attempting login with:', formData.email);
      const response = await axios.post('/api/login', formData);
      console.log('Login successful:', response.data);
      
      // Set authentication data in localStorage
      localStorage.setItem('isAuthenticated', 'true');
      localStorage.setItem('isAdmin', response.data.is_admin);
      
      // Force a page refresh while navigating to ensure state is updated
      if (response.data.is_admin) {
        window.location.href = '/admin/dashboard';
      } else {
        window.location.href = '/';
      }
    } catch (error) {
      console.error('Login error:', error);
      setError(error.response?.data?.message || 'Login failed. Please check your credentials and try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-vh-100 d-flex align-items-center py-5" style={{
      background: 'linear-gradient(to right, #f8f9fa, #ffffff)',
      backgroundImage: 'url("/images/pattern-bg.png")',
      backgroundSize: 'cover',
      backgroundBlendMode: 'overlay'
    }}>
      <div className="container">
        <div className="row justify-content-center">
          <div className="col-md-8 col-lg-6 col-xl-5">
            <div className="text-center mb-4">
              <img 
                src="grad-logo.png" 
                alt="Logo" 
                style={{ height: "150px" }}
                className="mb-2"
                onError={(e) => {
                  e.target.style.display = 'none';
                }}
              />
              <h1 className="h3 fw-light" style={{ color: '#0d6efd', letterSpacing: '-0.5px' }}>
                Higher Applicant <span className="fw-bold">Studies System</span>
              </h1>
            </div>
            
            <div className="card border-0 shadow-sm" style={{
              borderRadius: '16px', 
              overflow: 'hidden'
            }}>
              <div className="card-body p-4 p-md-5">
                <h2 className="fw-light text-center mb-4" style={{ letterSpacing: '-0.5px' }}>
                  Welcome Back
                </h2>
                <p className="text-muted text-center mb-4 ">
                  <strong className="text-danger">This is a free tier. The backend server can shutdown with inactivity.</strong>
                </p>
                
                {error && (
                  <div className="alert alert-danger py-2 px-3" role="alert" style={{
                    borderRadius: '8px',
                    fontSize: '0.9rem',
                    border: 'none',
                    backgroundColor: 'rgba(220, 53, 69, 0.1)'
                  }}>
                    <i className="bi bi-exclamation-circle me-2"></i>
                    {error}
                  </div>
                )}
                
                <form onSubmit={handleSubmit}>
                  <div className="mb-4">
                    <label htmlFor="email" className="form-label small text-muted">
                      Email Address
                    </label>
                    <div className="input-group">
                      <span className="input-group-text bg-white text-muted border-end-0">
                        <i className="bi bi-envelope"></i>
                      </span>
                      <input
                        type="email"
                        className="form-control border-start-0 ps-0"
                        id="email"
                        name="email"
                        placeholder="Enter your email"
                        value={formData.email}
                        onChange={handleChange}
                        required
                        style={{
                          borderRadius: '8px',
                          padding: '0.6rem 1rem',
                          borderTopLeftRadius: '0',
                          borderBottomLeftRadius: '0'
                        }}
                      />
                    </div>
                  </div>
                  
                  <div className="mb-4">
                    <div className="d-flex justify-content-between">
                      <label htmlFor="password" className="form-label small text-muted">
                        Password
                      </label>
                      <Link to="/forgot-password" className="small text-decoration-none">
                        Forgot password?
                      </Link>
                    </div>
                    <div className="input-group">
                      <span className="input-group-text bg-white text-muted border-end-0">
                        <i className="bi bi-lock"></i>
                      </span>
                      <input
                        type="password"
                        className="form-control border-start-0 ps-0"
                        id="password"
                        name="password"
                        placeholder="Enter your password"
                        value={formData.password}
                        onChange={handleChange}
                        required
                        style={{
                          borderRadius: '8px',
                          padding: '0.6rem 1rem',
                          borderTopLeftRadius: '0',
                          borderBottomLeftRadius: '0'
                        }}
                      />
                    </div>
                  </div>
                  
                  <div className="mb-4">
                    <div className="form-check">
                      <input 
                        className="form-check-input" 
                        type="checkbox" 
                        id="rememberMe" 
                        style={{ borderRadius: '4px' }}
                      />
                      <label className="form-check-label small text-muted" htmlFor="rememberMe">
                        Remember me
                      </label>
                    </div>
                  </div>
                  
                  <div className="d-grid mb-4">
                    <button 
                      type="submit" 
                      className="btn btn-primary py-2"
                      disabled={loading}
                      style={{
                        borderRadius: '8px',
                        boxShadow: '0 3px 6px rgba(13, 110, 253, 0.15)'
                      }}
                    >
                      {loading ? (
                        <>
                          <span className="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>
                          Signing in...
                        </>
                      ) : (
                        'Sign in'
                      )}
                    </button>
                  </div>
                </form>
                
                <div className="text-center">
                  <p className="text-muted mb-0">
                    Don't have an account? <Link to="/register" className="text-decoration-none">Register</Link>
                  </p>
                </div>
              </div>
            </div>
            
            <div className="text-center mt-4">
              <p className="small text-muted">
                © 2025 Higher Applicant Studies System
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;