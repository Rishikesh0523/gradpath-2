import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import axios from '../services/axiosConfig';

const Register = () => {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    confirmPassword: '',
    is_admin: false,
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const navigate = useNavigate();
  const currentDateTime = '2025-03-05 20:01:36';

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData({
      ...formData,
      [name]: type === 'checkbox' ? checked : value
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccess('');
    
    // Password validation
    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      setLoading(false);
      return;
    }
    
    if (formData.password.length < 6) {
      setError('Password must be at least 6 characters long');
      setLoading(false);
      return;
    }
    
    try {
      // Only send email and password to the backend
      const dataToSend = {
        email: formData.email,
        password: formData.password,
        is_admin: formData.is_admin  // Include this for testing purposes
      };
      
      console.log('Sending registration data:', dataToSend);
      const response = await axios.post('/api/register', dataToSend);
      
      console.log('Registration successful:', response.data);
      setSuccess('Registration successful! You can now log in.');
      
      // Reset the form
      setFormData({
        email: '',
        password: '',
        confirmPassword: '',
        is_admin: false,
      });
      
      // Redirect to login after 2 seconds
      setTimeout(() => {
        navigate('/login');
      }, 2000);
    } catch (error) {
      console.error('Registration error:', error);
      setError(error.response?.data?.message || 'Registration failed. Please try again.');
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
                src="/grad-logo.png" 
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
                  Create Your Account
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
                
                {success && (
                  <div className="alert alert-success py-2 px-3" role="alert" style={{
                    borderRadius: '8px',
                    fontSize: '0.9rem',
                    border: 'none',
                    backgroundColor: 'rgba(25, 135, 84, 0.1)'
                  }}>
                    <i className="bi bi-check-circle me-2"></i>
                    {success}
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
                    <label htmlFor="password" className="form-label small text-muted">
                      Password
                    </label>
                    <div className="input-group">
                      <span className="input-group-text bg-white text-muted border-end-0">
                        <i className="bi bi-lock"></i>
                      </span>
                      <input
                        type="password"
                        className="form-control border-start-0 ps-0"
                        id="password"
                        name="password"
                        placeholder="Create a password"
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
                    <small className="form-text text-muted ms-1 mt-1">
                      Password must be at least 6 characters long
                    </small>
                  </div>
                  
                  <div className="mb-4">
                    <label htmlFor="confirmPassword" className="form-label small text-muted">
                      Confirm Password
                    </label>
                    <div className="input-group">
                      <span className="input-group-text bg-white text-muted border-end-0">
                        <i className="bi bi-shield-lock"></i>
                      </span>
                      <input
                        type="password"
                        className="form-control border-start-0 ps-0"
                        id="confirmPassword"
                        name="confirmPassword"
                        placeholder="Confirm your password"
                        value={formData.confirmPassword}
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
                  
                  {/* This is just for development purposes */}
                  <div className="mb-4">
                    <div className="form-check">
                      <input
                        type="checkbox"
                        className="form-check-input"
                        id="is_admin"
                        name="is_admin"
                        checked={formData.is_admin}
                        onChange={handleChange}
                        style={{ borderRadius: '4px' }}
                      />
                      <label className="form-check-label small text-muted" htmlFor="is_admin">
                        Admin Account <span className="text-muted">(for development)</span>
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
                          Creating account...
                        </>
                      ) : (
                        'Create Account'
                      )}
                    </button>
                  </div>
                </form>
                
                <div className="text-center">
                  <p className="text-muted mb-0">
                    Already have an account? <Link to="/login" className="text-decoration-none">Sign in</Link>
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

export default Register;