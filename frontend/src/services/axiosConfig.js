// services/axiosConfig.js
import axios from 'axios';

// Create custom axios instance
const instance = axios.create({
  baseURL: 'https://gradpath-2-1.onrender.com',
  timeout: 300000,
  withCredentials: true // Important for cookies/session
});

// Request interceptor
instance.interceptors.request.use(
  (config) => {
    console.log(`Request: ${config.method?.toUpperCase()} ${config.url}`);
    
    // Ensure content type for submission
    if (config.method === 'post' || config.method === 'put') {
      if (!(config.data instanceof FormData)) {
        config.headers['Content-Type'] = 'application/json';
      }
    }
    
    return config;
  },
  (error) => {
    console.error('Request error:', error);
    return Promise.reject(error);
  }
);

// Response interceptor
instance.interceptors.response.use(
  (response) => {
    console.log(`Response: ${response.status} from ${response.config.url}`);
    return response;
  },
  (error) => {
    console.error('Response error:', error.response ? `${error.response.status} - ${error.response.data?.message || 'Unknown error'}` : error.message);
    return Promise.reject(error);
  }
);

export default instance;