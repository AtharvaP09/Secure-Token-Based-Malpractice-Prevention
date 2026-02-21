import axios from 'axios';

const api = axios.create({
    baseURL: 'http://localhost:8000', // Adjust if backend port differs
});

// Add a request interceptor to include the JWT token
api.interceptors.request.use(
    (config) => {
        const token = sessionStorage.getItem('token');
        if (token) {
            config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
    },
    (error) => Promise.reject(error)
);

export default api;
