import React, { useState, useEffect } from 'react';
import './Styles/AdminPanel.css';
import {
  FiUsers,
  FiUserPlus,
  FiTrash2,
  FiSearch,
  FiX,
  FiUser,
  FiMail,
  FiKey,
  FiEye,
  FiEyeOff,
  FiSettings,
  FiLogOut,
  FiBook,
  FiUserCheck,
  FiRefreshCw
} from 'react-icons/fi';
import API from '../api';

const AdminPanel = () => {
    const [users, setUsers] = useState([]);
    const [searchTerm, setSearchTerm] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [formData, setFormData] = useState({
        username: '',
        email: '',
        password: '',
        role_type: 'user' // Default to user
    });

    // Fetch users on component mount
    useEffect(() => {
        fetchUsers();
    }, []);

    const fetchUsers = async () => {
        try {
            const token = JSON.parse(sessionStorage.getItem('token'));
            const response = await API.get('/api/admin/users', {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            
            if (response.data.success) {
                setUsers(response.data.users);
            }
        } catch (error) {
            console.error('Error fetching users:', error);
            window.alert('Error fetching users');
        }
    };

    const handleInputChange = (e) => {
        const { name, value } = e.target;
        setFormData({
            ...formData,
            [name]: value
        });
    };

    const togglePasswordVisibility = () => {
        setShowPassword(!showPassword);
    };

    // Add new user
    const handleAddUser = async (e) => {
        e.preventDefault();
        
        if (!formData.username || !formData.email || !formData.password) {
            window.alert('Please fill all required fields');
            return;
        }

        try {
            const token = JSON.parse(sessionStorage.getItem('token'));
            const response = await API.post('/api/admin/add-user', formData, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            
            if (response.data.success) {
                window.alert('User added successfully!');
                setFormData({ username: '', email: '', password: '', role_type: 'user' });
                fetchUsers(); // Refresh user list
            }
        } catch (error) {
            console.error('Error adding user:', error);
            window.alert(error.response?.data?.error || 'Error adding user');
        }
    };

    // Delete user
    const handleDeleteUser = async (userId) => {
        if (!window.confirm('Are you sure you want to delete this user?')) {
            return;
        }

        try {
            const token = JSON.parse(sessionStorage.getItem('token'));
            const response = await API.delete(`/api/admin/users/${userId}`, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            
            if (response.data.success) {
                window.alert('User deleted successfully!');
                fetchUsers(); // Refresh user list
            }
        } catch (error) {
            console.error('Error deleting user:', error);
            window.alert(error.response?.data?.error || 'Error deleting user');
        }
    };

    // Update user role
    const handleUpdateRole = async (userId, currentRole) => {
        const newRole = currentRole === 'user' ? 'teacher' : 'user';
        const confirmMessage = `Are you sure you want to change this user's role to ${newRole}?`;
        
        if (!window.confirm(confirmMessage)) {
            return;
        }

        try {
            const token = JSON.parse(sessionStorage.getItem('token'));
            const response = await API.put(`/api/admin/users/${userId}/role`, 
                { role_type: newRole },
                {
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                }
            );
            
            if (response.data.success) {
                window.alert(`User role updated to ${newRole}`);
                fetchUsers(); // Refresh user list
            }
        } catch (error) {
            console.error('Error updating role:', error);
            window.alert(error.response?.data?.error || 'Error updating role');
        }
    };

    // Filter users based on search term
    const filteredUsers = users.filter(user =>
        user.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
        user.email.toLowerCase().includes(searchTerm.toLowerCase()) ||
        (user.role_type && user.role_type.toLowerCase().includes(searchTerm.toLowerCase()))
    );

    // Logout
    const handleLogout = () => {
        sessionStorage.clear();
        window.location.href = '/';
    };

    // Get role badge color
    const getRoleBadgeClass = (role) => {
        if (role === 'teacher') return 'role-badge-teacher';
        if (role === 'user') return 'role-badge-user';
        return 'role-badge-user';
    };

    // Get role icon
    const getRoleIcon = (role) => {
        if (role === 'teacher') return <FiBook size={14} />;
        return <FiUser size={14} />;
    };

    // Get button text for role change
    const getRoleButtonText = (role) => {
        if (role === 'teacher') return 'Make User';
        return 'Make Teacher';
    };

    return (
        <>
            {/* Animated Background */}
            <div className="bg-animation">
                <div className="floating-element"></div>
                <div className="floating-element"></div>
                <div className="floating-element"></div>
            </div>

            {/* Main Content */}
            <div className="admin-panel-container">
                {/* Header */}
                <div className="admin-header">
                    <div>
                        <h1>
                            <FiSettings size={28} />
                            Admin Dashboard
                        </h1>
                        <p className="admin-header-subtitle">
                            Manage users and roles in the system
                        </p>
                    </div>
                    
                    <button onClick={handleLogout} className="logout-btn">
                        <FiLogOut size={18} />
                        Logout
                    </button>
                </div>

                {/* Add User Form */}
                <div className="user-management-section">
                    <h2 className="section-title">
                        <FiUserPlus size={22} />
                        Add New User
                    </h2>
                    <form onSubmit={handleAddUser} className="add-user-form">
                        <div className="form-grid">
                            <div className="form-group">
                                <label className="form-label">
                                    <FiUser size={16} />
                                    Username *
                                </label>
                                <input
                                    type="text"
                                    name="username"
                                    value={formData.username}
                                    onChange={handleInputChange}
                                    className="form-input"
                                    placeholder="Enter username"
                                    required
                                />
                            </div>
                            <div className="form-group">
                                <label className="form-label">
                                    <FiMail size={16} />
                                    Email *
                                </label>
                                <input
                                    type="email"
                                    name="email"
                                    value={formData.email}
                                    onChange={handleInputChange}
                                    className="form-input"
                                    placeholder="Enter email"
                                    required
                                />
                            </div>
                            <div className="form-group">
                                <label className="form-label">
                                    <FiKey size={16} />
                                    Password *
                                </label>
                                <div style={{ position: 'relative' }}>
                                    <input
                                        type={showPassword ? "text" : "password"}
                                        name="password"
                                        value={formData.password}
                                        onChange={handleInputChange}
                                        className="form-input"
                                        placeholder="Enter password"
                                        required
                                        style={{ paddingRight: '45px' }}
                                    />
                                    <button
                                        type="button"
                                        onClick={togglePasswordVisibility}
                                        style={{
                                            position: 'absolute',
                                            right: '12px',
                                            top: '50%',
                                            transform: 'translateY(-50%)',
                                            background: 'none',
                                            border: 'none',
                                            color: '#a0aec0',
                                            cursor: 'pointer',
                                            padding: '4px'
                                        }}
                                    >
                                        {showPassword ? <FiEyeOff size={18} /> : <FiEye size={18} />}
                                    </button>
                                </div>
                            </div>
                            <div className="form-group">
                                <label className="form-label">
                                    <FiUserCheck size={16} />
                                    Role
                                </label>
                                <select
                                    name="role_type"
                                    value={formData.role_type}
                                    onChange={handleInputChange}
                                    className="form-select"
                                >
                                    <option value="user">User</option>
                                    <option value="teacher">Teacher</option>
                                </select>
                            </div>
                        </div>
                        <div className="form-buttons">
                            <button type="submit" className="btn btn-primary">
                                <FiUserPlus size={18} />
                                Add User
                            </button>
                            <button 
                                type="button" 
                                className="btn btn-secondary"
                                onClick={() => setFormData({
                                    username: '',
                                    email: '',
                                    password: '',
                                    role_type: 'user'
                                })}
                            >
                                <FiX size={18} />
                                Clear Form
                            </button>
                        </div>
                    </form>
                </div>

                {/* Users List */}
                <div className="user-management-section">
                    <h2 className="section-title">
                        <FiUsers size={22} />
                        User Management ({users.length} users)
                    </h2>
                    
                    {/* Search Bar */}
                    <div className="search-bar">
                        <div className="search-icon">
                            <FiSearch size={20} />
                        </div>
                        <input
                            type="text"
                            placeholder="Search users by Email..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            className="search-input"
                        />
                    </div>

                    {filteredUsers.length === 0 ? (
                        <div className="no-users">
                            <FiUsers className="no-users-icon" />
                            <p>{searchTerm ? 'No users found matching your search.' : 'No users available.'}</p>
                        </div>
                    ) : (
                        <div className="users-table-container">
                            <table className="users-table">
                                <thead>
                                    <tr>
                                        <th>ID</th>
                                        <th>Username</th>
                                        <th>Email</th>
                                        <th>Role</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {filteredUsers.map(user => (
                                        <tr key={user.userid}>
                                            <td>#{user.userid}</td>
                                            <td>
                                                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                                                    <div className="user-avatar">
                                                        {user.username.charAt(0).toUpperCase()}
                                                    </div>
                                                    {user.username}
                                                </div>
                                            </td>
                                            <td>{user.email}</td>
                                            <td>
                                                <span className={`role-badge ${getRoleBadgeClass(user.role_type)}`}>
                                                    {getRoleIcon(user.role_type)}
                                                    {user.role_type || 'user'}
                                                </span>
                                            </td>
                                            <td>
                                                <div className="action-buttons">
                                                    <button
                                                        className="btn-icon btn-icon-change-role"
                                                        onClick={() => handleUpdateRole(user.userid, user.role_type || 'user')}
                                                        title="Change Role"
                                                    >
                                                        <FiRefreshCw size={16} />
                                                        {getRoleButtonText(user.role_type || 'user')}
                                                    </button>
                                                    <button
                                                        className="btn-icon btn-icon-delete"
                                                        onClick={() => handleDeleteUser(user.userid)}
                                                        title="Delete User"
                                                    >
                                                        <FiTrash2 size={16} />
                                                        Delete
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>
            </div>
        </>
    );
};

export default AdminPanel;