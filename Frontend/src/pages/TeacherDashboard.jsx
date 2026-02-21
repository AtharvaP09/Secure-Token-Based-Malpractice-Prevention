import { useState, useEffect } from 'react';
import api from '../api/axios';
import { useAuth } from '../context/AuthContext';
import { Plus, Copy, LogOut, LayoutDashboard, Calendar, Users, Trash2 } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

// Simple Modal Component
const CreateExamModal = ({ isOpen, onClose, onCreate }) => {
    const [formData, setFormData] = useState({
        password: '',
        start_time: '',
        duration_minutes: 60
    });

    if (!isOpen) return null;

    const handleSubmit = (e) => {
        e.preventDefault();
        // Ensure start_time is in UTC or handle timezone. 
        // For simplicity, let's assume local time input and convert to ISO string which backend might interpret as UTC if no offset.
        // Actually best to send ISO string.
        const isoDate = new Date(formData.start_time).toISOString();
        onCreate({
            ...formData,
            start_time: isoDate
        });
    };

    return (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 backdrop-blur-sm">
            <div className="bg-gray-800 rounded-xl border border-gray-700 p-6 w-full max-w-md shadow-2xl">
                <h2 className="text-xl font-bold text-white mb-4">Create New Exam</h2>
                <form onSubmit={handleSubmit} className="space-y-4">
                    <div>
                        <label className="block text-sm font-medium text-gray-400 mb-1">Password</label>
                        <input
                            type="text"
                            required
                            value={formData.password}
                            onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                            className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-blue-500"
                            placeholder="ex. secret123"
                        />
                    </div>
                    <div>
                        <label className="block text-sm font-medium text-gray-400 mb-1">Start Time</label>
                        <input
                            type="datetime-local"
                            required
                            value={formData.start_time}
                            onChange={(e) => setFormData({ ...formData, start_time: e.target.value })}
                            className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-blue-500"
                        />
                    </div>
                    <div>
                        <label className="block text-sm font-medium text-gray-400 mb-1">Duration (Minutes)</label>
                        <input
                            type="number"
                            required
                            min="1"
                            value={formData.duration_minutes}
                            onChange={(e) => setFormData({ ...formData, duration_minutes: e.target.value === '' ? '' : parseInt(e.target.value) })}
                            className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-blue-500"
                        />
                    </div>
                    <div className="flex justify-end space-x-3 mt-6">
                        <button
                            type="button"
                            onClick={onClose}
                            className="px-4 py-2 text-gray-300 hover:text-white transition-colors"
                        >
                            Cancel
                        </button>
                        <button
                            type="submit"
                            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium"
                        >
                            Create Exam
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};

const TeacherDashboard = () => {
    const [exams, setExams] = useState([]);
    const [loading, setLoading] = useState(true);
    const [showCreateModal, setShowCreateModal] = useState(false);
    const { user, logout } = useAuth();
    const navigate = useNavigate();

    useEffect(() => {
        fetchExams();
    }, []);

    const fetchExams = async () => {
        try {
            const response = await api.get('/exams/list');
            setExams(response.data);
        } catch (error) {
            console.error("Failed to fetch exams", error);
        } finally {
            setLoading(false);
        }
    };

    const handleCreateExam = async (examData) => {
        try {
            await api.post('/exams/create', examData);
            setShowCreateModal(false);
            fetchExams();
        } catch (error) {
            console.error("Failed to create exam", error);
            alert("Failed to create exam");
        }
    };

    const deleteExam = async (examId) => {
        if (window.confirm("Are you sure you want to delete this exam room? This action cannot be undone.")) {
            try {
                await api.delete(`/exams/room/${examId}`);
                setExams(exams.filter(exam => exam.id !== examId));
            } catch (error) {
                console.error("Failed to delete exam", error);
                alert("Failed to delete exam");
            }
        }
    };

    const handleLogout = () => {
        logout();
        navigate('/login');
    };

    return (
        <div className="min-h-screen bg-gray-900 text-white font-sans selection:bg-blue-500/30">
            {/* Navbar */}
            <nav className="border-b border-gray-800 bg-gray-900/50 backdrop-blur-md sticky top-0 z-50">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="flex justify-between items-center h-16">
                        <div className="flex items-center space-x-3">
                            <div className="bg-blue-600 p-2 rounded-lg shadow-lg shadow-blue-600/20">
                                <LayoutDashboard className="h-6 w-6 text-white" />
                            </div>
                            <span className="text-xl font-bold tracking-tight">Teacher Portal</span>
                        </div>
                        <div className="flex items-center space-x-4">
                            <div className="text-sm text-gray-400">
                                <span className="text-gray-200 font-medium">{user?.sub}</span>
                            </div>
                            <button
                                onClick={handleLogout}
                                className="p-2 rounded-lg hover:bg-red-500/10 text-gray-400 hover:text-red-400 transition-colors"
                                title="Logout"
                            >
                                <LogOut className="h-5 w-5" />
                            </button>
                        </div>
                    </div>
                </div>
            </nav>

            {/* Main Content */}
            <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">

                {/* Header Section */}
                <div className="flex justify-between items-center mb-8">
                    <div>
                        <h1 className="text-3xl font-bold text-white">Exam Rooms</h1>
                        <p className="text-gray-400 mt-1">Manage your active examination sessions</p>
                    </div>
                    <button
                        onClick={() => setShowCreateModal(true)}
                        className="flex items-center px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg shadow-lg shadow-blue-600/30 transition-all transform hover:scale-105 active:scale-95"
                    >
                        <Plus className="h-5 w-5 mr-2" />
                        Create New Exam
                    </button>
                </div>

                {/* Exam Grid */}
                {loading ? (
                    <div className="flex justify-center py-20">
                        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
                    </div>
                ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                        {exams.length === 0 ? (
                            <div className="col-span-full text-center py-20 bg-gray-800/50 rounded-2xl border border-gray-700 border-dashed">
                                <LayoutDashboard className="mx-auto h-12 w-12 text-gray-600 mb-4" />
                                <h3 className="text-lg font-medium text-gray-300">No exams created yet</h3>
                                <p className="text-gray-500 mt-1">Click the button above to start your first exam session.</p>
                            </div>
                        ) : (
                            exams.map((exam) => (
                                <div key={exam.id} className="bg-gray-800 rounded-xl border border-gray-700 p-6 hover:border-gray-600 transition-colors shadow-lg">
                                    <div className="flex justify-between items-start mb-4">
                                        <div className="bg-gray-700/50 p-2 rounded-lg">
                                            <Calendar className="h-6 w-6 text-blue-400" />
                                        </div>
                                        <span className={`px-2 py-1 text-xs font-semibold rounded-full ${exam.is_active ? 'bg-green-500/20 text-green-300' : 'bg-gray-600 text-gray-300'}`}>
                                            {exam.is_active ? 'Active' : 'Closed'}
                                        </span>
                                    </div>

                                    <h3 className="text-xl font-bold text-white mb-2">Code: <span className="font-mono text-blue-400">{exam.room_code}</span></h3>

                                    {/* Display Time Info */}
                                    <div className="text-xs text-gray-500 mb-4 space-y-1">
                                        <p>Start: {new Date(exam.start_time.endsWith('Z') ? exam.start_time : exam.start_time + 'Z').toLocaleString()}</p>
                                        <p>Duration: {exam.duration_minutes} mins</p>
                                    </div>

                                    <div className="flex items-center text-sm text-gray-400 mb-6">
                                        <span className="flex items-center"><Users className="w-4 h-4 mr-1" /> {exam.student_count || 0} Active</span>
                                        <span className="flex items-center ml-4 text-gray-500"><Users className="w-4 h-4 mr-1" /> {exam.completed_count || 0} Completed</span>
                                    </div>

                                    <div className="flex space-x-3">
                                        <button
                                            onClick={() => navigate(`/room/${exam.id}`)}
                                            className="flex-1 bg-gray-700 hover:bg-gray-600 text-white py-2 rounded-lg text-sm font-medium transition-colors"
                                        >
                                            View Logs
                                        </button>
                                        <button
                                            onClick={() => navigator.clipboard.writeText(exam.room_code)}
                                            className="bg-gray-700 hover:bg-gray-600 text-gray-300 p-2 rounded-lg transition-colors"
                                            title="Copy Code"
                                        >
                                            <Copy className="h-5 w-5" />
                                        </button>
                                        <button
                                            onClick={() => deleteExam(exam.id)}
                                            className="bg-red-500/10 hover:bg-red-500/20 text-red-400 p-2 rounded-lg transition-colors"
                                            title="Delete Room"
                                        >
                                            <Trash2 className="h-5 w-5" />
                                        </button>
                                    </div>
                                </div>

                            ))
                        )}
                    </div>
                )}
            </main>

            <CreateExamModal
                isOpen={showCreateModal}
                onClose={() => setShowCreateModal(false)}
                onCreate={handleCreateExam}
            />
        </div>
    );
};

export default TeacherDashboard;
