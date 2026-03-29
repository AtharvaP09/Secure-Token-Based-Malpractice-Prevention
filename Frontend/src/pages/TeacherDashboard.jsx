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
        end_time: '',
        duration_minutes: 60
    });

    if (!isOpen) return null;

    const handleSubmit = (e) => {
        e.preventDefault();
        // Ensure start_time is in UTC or handle timezone. 
        // For simplicity, let's assume local time input and convert to ISO string which backend might interpret as UTC if no offset.
        // Actually best to send ISO string.
        const isoDate = new Date(formData.start_time).toISOString();
        const endIsoDate = new Date(formData.end_time).toISOString();
        onCreate({
            ...formData,
            start_time: isoDate,
            end_time: endIsoDate
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
                        <label className="block text-sm font-medium text-gray-400 mb-1">End Time</label>
                        <input
                            type="datetime-local"
                            required
                            value={formData.end_time}
                            onChange={(e) => setFormData({ ...formData, end_time: e.target.value })}
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
                            className="px-4 py-2 text-gray-400 hover:text-white transition-colors font-medium"
                        >
                            Cancel
                        </button>
                        <button
                            type="submit"
                            className="px-5 py-2.5 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white rounded-lg font-bold shadow-[0_0_15px_rgba(37,71,244,0.4)] transition-all hover:scale-105 active:scale-95"
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
        <div className="min-h-screen bg-[#0A0F1C] bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-slate-900 via-[#0A0F1C] to-black text-white font-sans selection:bg-blue-500/30">
            {/* Navbar */}
            <nav className="border-b border-indigo-900/30 bg-[#0A0F1C]/70 backdrop-blur-xl sticky top-0 z-50">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="flex justify-between items-center h-16">
                        <div className="flex items-center space-x-3">
                            <div className="bg-gradient-to-br from-blue-500 to-purple-600 p-2 rounded-xl shadow-[0_0_15px_rgba(37,71,244,0.3)]">
                                <LayoutDashboard className="h-6 w-6 text-white" />
                            </div>
                            <span className="text-xl font-bold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-white to-gray-400">Teacher Portal</span>
                        </div>
                        <div className="flex items-center space-x-4">
                            <div className="text-sm text-gray-400">
                                <span className="text-indigo-200 font-medium">{user?.sub}</span>
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
                <div className="flex justify-between items-center mb-10 mt-4">
                    <div>
                        <h1 className="text-4xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-white to-gray-400 tracking-tight">Exam Rooms</h1>
                        <p className="text-indigo-200/60 mt-2 font-medium">Manage your active examination sessions</p>
                    </div>
                    <button
                        onClick={() => setShowCreateModal(true)}
                        className="flex items-center px-5 py-2.5 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white rounded-xl shadow-[0_0_20px_rgba(37,71,244,0.4)] transition-all transform hover:scale-105 active:scale-95 font-bold tracking-wide border border-blue-400/20"
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
                            exams.map((exam) => {
                                const isTimePassed = exam.end_time ? new Date() > new Date(exam.end_time.endsWith('Z') ? exam.end_time : exam.end_time + 'Z') : false;
                                const isEffectivelyActive = exam.is_active && !isTimePassed;

                                return (
                                <div key={exam.id} className="relative group bg-[#131B2F]/60 backdrop-blur-md rounded-2xl border border-indigo-500/10 p-6 hover:border-blue-500/30 transition-all duration-300 shadow-[0_8px_30px_rgb(0,0,0,0.12)] hover:shadow-[0_8px_30px_rgba(37,71,244,0.15)] overflow-hidden">
                                    {/* Glass reflection effect */}
                                    <div className="absolute inset-0 bg-gradient-to-br from-white/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none"></div>
                                    
                                    <div className="flex justify-between items-start mb-5 relative z-10">
                                        <div className="bg-blue-500/10 p-2.5 rounded-xl border border-blue-500/20">
                                            <Calendar className="h-6 w-6 text-blue-400" />
                                        </div>
                                        <span className={`px-3 py-1 text-xs font-bold tracking-wider uppercase rounded-full border ${isEffectivelyActive ? 'bg-green-500/10 text-green-400 border-green-500/20 shadow-[0_0_10px_rgba(34,197,94,0.2)]' : 'bg-gray-800 text-gray-400 border-gray-700'}`}>
                                            {isEffectivelyActive ? 'Active' : 'Closed'}
                                        </span>
                                    </div>

                                    <h3 className="text-2xl font-black text-white mb-3 tracking-tight relative z-10">Code: <span className="font-mono text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-purple-400">{exam.room_code}</span></h3>

                                    {/* Display Time Info */}
                                    <div className="text-sm text-indigo-200/70 mb-5 space-y-1.5 font-medium relative z-10">
                                        <p className="flex items-center"><span className="w-16 text-gray-500 text-xs uppercase tracking-wider">Start</span> <span className="text-gray-300">{new Date(exam.start_time.endsWith('Z') ? exam.start_time : exam.start_time + 'Z').toLocaleString()}</span></p>
                                        <p className="flex items-center"><span className="w-16 text-gray-500 text-xs uppercase tracking-wider">End</span> <span className="text-gray-300">{exam.end_time ? new Date(exam.end_time.endsWith('Z') ? exam.end_time : exam.end_time + 'Z').toLocaleString() : "Not Set"}</span></p>
                                        <p className="flex items-center"><span className="w-16 text-gray-500 text-xs uppercase tracking-wider">Length</span> <span className="text-blue-300 font-semibold">{exam.duration_minutes} mins</span></p>
                                    </div>

                                    <div className="flex items-center text-sm mb-6 bg-black/20 rounded-lg p-3 border border-white/5 relative z-10">
                                        <div className="flex-1 flex flex-col items-center border-r border-white/10">
                                            <span className="text-2xl font-bold text-white">{exam.student_count || 0}</span>
                                            <span className="text-[10px] uppercase tracking-wider text-green-400/80 font-bold mt-1">Active</span>
                                        </div>
                                        <div className="flex-1 flex flex-col items-center">
                                            <span className="text-2xl font-bold text-gray-300">{exam.completed_count || 0}</span>
                                            <span className="text-[10px] uppercase tracking-wider text-blue-400/80 font-bold mt-1">Completed</span>
                                        </div>
                                    </div>

                                    <div className="flex space-x-2 relative z-10">
                                        <button
                                            onClick={() => navigate(`/room/${exam.id}`)}
                                            className="flex-1 bg-blue-600/10 hover:bg-blue-600 border border-blue-500/30 hover:border-blue-500 text-blue-400 hover:text-white py-2.5 rounded-xl text-sm font-bold transition-all shadow-sm hover:shadow-[0_0_15px_rgba(37,71,244,0.4)]"
                                        >
                                            View Logs
                                        </button>
                                        <button
                                            onClick={() => navigator.clipboard.writeText(exam.room_code)}
                                            className="bg-gray-800/80 hover:bg-gray-700 border border-gray-700 text-gray-300 p-2.5 rounded-xl transition-colors"
                                            title="Copy Code"
                                        >
                                            <Copy className="h-5 w-5" />
                                        </button>
                                        <button
                                            onClick={() => deleteExam(exam.id)}
                                            className="bg-red-500/10 hover:bg-red-500 border border-red-500/20 hover:border-red-500 text-red-400 hover:text-white p-2.5 rounded-xl transition-all hover:shadow-[0_0_15px_rgba(239,68,68,0.4)]"
                                            title="Delete Room"
                                        >
                                            <Trash2 className="h-5 w-5" />
                                        </button>
                                    </div>
                                </div>
                                );
                            })
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
