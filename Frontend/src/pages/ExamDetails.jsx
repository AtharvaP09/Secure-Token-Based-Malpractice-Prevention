import { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import api from '../api/axios';
import {
    ArrowLeft,
    AlertTriangle,
    CheckCircle,
    RefreshCw,
    Users,
    Download,
    BarChart3,
    Activity,
    ShieldAlert,
    ShieldCheck,
    AlertCircle,
    Usb,
    Keyboard,
    Mouse,
    FileSpreadsheet,
    HelpCircle,
    Search,
    ExternalLink,
    Clock,
    Lock,
    X,
    Laptop,
    Copy,
    FolderOpen
} from 'lucide-react';
import { saveAs } from 'file-saver';
import {
    PieChart,
    Pie,
    Cell,
    BarChart,
    Bar,
    XAxis,
    YAxis,
    Tooltip,
    ResponsiveContainer,
    AreaChart,
    Area,
    CartesianGrid,
    Legend
} from 'recharts';

const ExamDetails = () => {
    const { roomId } = useParams();
    const navigate = useNavigate();

    // Navigation & Tab State
    const [activeTab, setActiveTab] = useState('analytics'); // 'analytics' | 'logs'
    const [showPowerBIModal, setShowPowerBIModal] = useState(false);

    // Sessions & Logs State
    const [sessions, setSessions] = useState([]);
    const [selectedSessionId, setSelectedSessionId] = useState(null);
    const [logs, setLogs] = useState([]);
    const [loading, setLoading] = useState(true);
    const [autoRefresh, setAutoRefresh] = useState(true);
    const [viewLedgerMode, setViewLedgerMode] = useState(false);
    const [showCriticalOnly, setShowCriticalOnly] = useState(false);
    const [logTypeFilter, setLogTypeFilter] = useState('all');

    // Analytics State
    const [analytics, setAnalytics] = useState(null);
    const [analyticsLoading, setAnalyticsLoading] = useState(true);
    const [studentFilter, setStudentFilter] = useState('all'); // 'all' | 'critical' | 'warning' | 'clean' | 'zero'
    const [searchQuery, setSearchQuery] = useState('');

    const selectedSession = sessions.find(s => s.id === selectedSessionId) || null;

    // Fetch list of students/sessions
    const fetchSessions = async () => {
        try {
            const response = await api.get(`/exams/room/${roomId}/students`);
            setSessions(response.data);
            setLoading(false);
        } catch (error) {
            console.error("Failed to fetch sessions", error);
        }
    };

    // Fetch analytics data
    const fetchAnalytics = async () => {
        try {
            const response = await api.get(`/exams/room/${roomId}/analytics`);
            setAnalytics(response.data);
            setAnalyticsLoading(false);
        } catch (error) {
            console.error("Failed to fetch analytics", error);
            setAnalyticsLoading(false);
        }
    };

    // Fetch logs for selected student
    const fetchLogs = async () => {
        if (!selectedSessionId) return;
        try {
            const params = {};
            if (viewLedgerMode) {
                params.source = 'ledger';
            }
            const response = await api.get(`/exams/${selectedSessionId}/logs`, { params });
            setLogs(response.data);
        } catch (error) {
            console.error("Failed to fetch logs", error);
        }
    };

    const sessionsRef = useRef(sessions);
    useEffect(() => {
        sessionsRef.current = sessions;
    }, [sessions]);

    // Initial load and periodic polling
    useEffect(() => {
        fetchSessions();
        fetchAnalytics();

        const interval = setInterval(() => {
            fetchSessions();
            if (activeTab === 'analytics') {
                fetchAnalytics();
            }

            if (autoRefresh && !viewLedgerMode && selectedSessionId && activeTab === 'logs') {
                const currentSession = sessionsRef.current.find(s => s.id === selectedSessionId);
                if (currentSession && !currentSession.end_time) {
                    fetchLogs();
                }
            }
        }, 3000);

        return () => clearInterval(interval);
    }, [roomId, selectedSessionId, autoRefresh, viewLedgerMode, activeTab]);

    // Fetch logs immediately when selection changes
    useEffect(() => {
        if (selectedSessionId) {
            setLogs([]);
            setShowCriticalOnly(false);
            fetchLogs();
        }
    }, [selectedSessionId, viewLedgerMode]);

    // Export raw logs CSV
    const handleExportCSV = async () => {
        try {
            const response = await api.get(`/exams/room/${roomId}/export_csv`, {
                responseType: 'blob',
            });
            const blob = new Blob([response.data], { type: 'text/csv;charset=utf-8;' });
            saveAs(blob, `exam_room_${roomId}_all_logs.csv`);
        } catch (error) {
            console.error("Export failed", error);
        }
    };

    // Export Power BI specialized CSV
    const handleExportPowerBI = async () => {
        try {
            const response = await api.get(`/exams/room/${roomId}/export_powerbi`, {
                responseType: 'blob',
            });
            const blob = new Blob([response.data], { type: 'text/csv;charset=utf-8;' });
            saveAs(blob, `PowerBI_Exam_Room_${roomId}_Analytics.csv`);
        } catch (error) {
            console.error("Power BI Export failed", error);
        }
    };

    // Navigate to student's live log view directly from analytics table
    const inspectStudent = (sessionId) => {
        setSelectedSessionId(sessionId);
        setActiveTab('logs');
    };

    // Filtered students for Analytics Scorecard Table
    const filteredStudents = (analytics?.students || []).filter(student => {
        const matchesQuery =
            student.username.toLowerCase().includes(searchQuery.toLowerCase()) ||
            student.email.toLowerCase().includes(searchQuery.toLowerCase()) ||
            String(student.session_id).includes(searchQuery);

        if (!matchesQuery) return false;

        if (studentFilter === 'critical') return student.risk_tier === 'CRITICAL';
        if (studentFilter === 'warning') return student.risk_tier === 'WARNING';
        if (studentFilter === 'clean') return student.risk_tier === 'CLEAN';
        if (studentFilter === 'zero') return student.risk_tier === 'ZERO_LOGS';
        return true;
    });

    return (
        <div className="min-h-screen bg-[#0A0F1C] bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-slate-900 via-[#0A0F1C] to-black text-white font-sans flex flex-col h-screen overflow-hidden selection:bg-blue-500/30">
            {/* Top Navigation Bar */}
            <header className="border-b border-indigo-900/30 bg-[#0A0F1C]/80 backdrop-blur-xl px-5 py-3.5 flex justify-between items-center shadow-lg z-20">
                <div className="flex items-center space-x-4">
                    <button
                        onClick={() => navigate('/teacher')}
                        className="p-2 hover:bg-blue-500/10 rounded-full transition-colors text-indigo-300 hover:text-blue-400"
                        title="Back to Dashboard"
                    >
                        <ArrowLeft className="h-5 w-5" />
                    </button>
                    <div>
                        <div className="flex items-center space-x-2.5">
                            <h1 className="text-lg font-bold bg-clip-text text-transparent bg-gradient-to-r from-white via-indigo-100 to-indigo-300">
                                Exam Monitor Room
                            </h1>
                            <span className="px-2.5 py-0.5 bg-blue-500/20 text-blue-400 text-xs rounded-md font-mono font-bold border border-blue-500/30">
                                #{analytics?.room_code || roomId}
                            </span>
                        </div>
                        <p className="text-xs text-indigo-200/60 mt-0.5 flex items-center space-x-2">
                            <span>{sessions.length} Students Enrolled</span>
                            <span>•</span>
                            <span className="text-indigo-400">Duration: {analytics?.duration_minutes || 60}m</span>
                        </p>
                    </div>
                </div>

                {/* View Switcher Tabs (Analytics vs Live Stream) */}
                <div className="flex items-center bg-[#131B2F]/80 p-1 rounded-xl border border-indigo-500/20 shadow-inner">
                    <button
                        onClick={() => setActiveTab('analytics')}
                        className={`flex items-center space-x-2 px-4 py-1.5 rounded-lg text-xs font-bold transition-all ${
                            activeTab === 'analytics'
                                ? 'bg-gradient-to-r from-blue-600 to-indigo-600 text-white shadow-[0_0_15px_rgba(37,71,244,0.4)]'
                                : 'text-gray-400 hover:text-white hover:bg-white/5'
                        }`}
                    >
                        <BarChart3 className="h-4 w-4" />
                        <span>Visual Analytics & BI</span>
                        {analytics?.metrics?.critical_students > 0 && (
                            <span className="px-1.5 py-0.2 bg-red-500 text-white text-[10px] rounded-full font-bold ml-1 animate-pulse">
                                {analytics.metrics.critical_students}
                            </span>
                        )}
                    </button>
                    <button
                        onClick={() => setActiveTab('logs')}
                        className={`flex items-center space-x-2 px-4 py-1.5 rounded-lg text-xs font-bold transition-all ${
                            activeTab === 'logs'
                                ? 'bg-gradient-to-r from-blue-600 to-indigo-600 text-white shadow-[0_0_15px_rgba(37,71,244,0.4)]'
                                : 'text-gray-400 hover:text-white hover:bg-white/5'
                        }`}
                    >
                        <Activity className="h-4 w-4" />
                        <span>Live Logs Stream</span>
                    </button>
                </div>

                {/* Export & Power BI Actions */}
                <div className="flex items-center space-x-2.5">
                    <button
                        onClick={() => setShowPowerBIModal(true)}
                        className="flex items-center space-x-1.5 px-3 py-1.5 bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 rounded-lg text-xs font-bold transition-all"
                        title="Power BI Guide & Templates"
                    >
                        <HelpCircle className="h-3.5 w-3.5" />
                        <span>Power BI Guide</span>
                    </button>

                    <button
                        onClick={handleExportPowerBI}
                        className="flex items-center space-x-1.5 px-3.5 py-1.5 bg-gradient-to-r from-amber-600 to-yellow-600 hover:from-amber-500 hover:to-yellow-500 text-white rounded-lg text-xs font-bold transition-all shadow-[0_0_15px_rgba(245,158,11,0.3)] hover:scale-105 active:scale-95"
                        title="Download Power BI Ready Dataset (CSV with UTF-8 BOM)"
                    >
                        <FileSpreadsheet className="h-3.5 w-3.5" />
                        <span>Export for Power BI</span>
                    </button>

                    <button
                        onClick={handleExportCSV}
                        className="flex items-center space-x-1.5 px-3.5 py-1.5 bg-[#131B2F] hover:bg-[#1C2640] border border-indigo-500/20 text-gray-300 hover:text-white rounded-lg text-xs font-bold transition-all"
                        title="Download Full Event Logs"
                    >
                        <Download className="h-3.5 w-3.5" />
                        <span>All Logs CSV</span>
                    </button>
                </div>
            </header>

            {/* TAB 1: VISUAL ANALYTICS & BI DASHBOARD */}
            {activeTab === 'analytics' && (
                <div className="flex-1 overflow-y-auto p-6 space-y-6 custom-scrollbar">
                    {/* Top KPI Summary Metric Cards */}
                    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
                        {/* 1. Total Enrolled */}
                        <div className="bg-[#131B2F]/60 backdrop-blur-md rounded-2xl border border-indigo-500/15 p-4 relative overflow-hidden shadow-lg">
                            <div className="flex justify-between items-start mb-2">
                                <span className="text-xs font-bold text-gray-400 uppercase tracking-wider">Total Enrolled</span>
                                <div className="p-2 rounded-xl bg-blue-500/10 text-blue-400 border border-blue-500/20">
                                    <Users className="w-4 h-4" />
                                </div>
                            </div>
                            <div className="text-2xl font-black text-white">{analytics?.metrics?.total_students || 0}</div>
                            <p className="text-[11px] text-indigo-300/60 mt-1 font-medium">
                                <span className="text-green-400">{analytics?.metrics?.active_students || 0} Active</span> • {analytics?.metrics?.completed_students || 0} Done
                            </p>
                        </div>

                        {/* 2. Critical Cheating Flags */}
                        <div className="bg-red-950/20 backdrop-blur-md rounded-2xl border border-red-500/30 p-4 relative overflow-hidden shadow-[0_0_20px_rgba(239,68,68,0.1)]">
                            <div className="flex justify-between items-start mb-2">
                                <span className="text-xs font-bold text-red-300 uppercase tracking-wider">Critical Risk</span>
                                <div className="p-2 rounded-xl bg-red-500/20 text-red-400 border border-red-500/40">
                                    <ShieldAlert className="w-4 h-4" />
                                </div>
                            </div>
                            <div className="text-2xl font-black text-red-400">{analytics?.metrics?.critical_students || 0}</div>
                            <p className="text-[11px] text-red-300/70 mt-1 font-medium">
                                {analytics?.metrics?.critical_percentage || 0}% of students flagged
                            </p>
                        </div>

                        {/* 3. Clean Students */}
                        <div className="bg-emerald-950/20 backdrop-blur-md rounded-2xl border border-emerald-500/30 p-4 relative overflow-hidden shadow-[0_0_20px_rgba(16,185,129,0.1)]">
                            <div className="flex justify-between items-start mb-2">
                                <span className="text-xs font-bold text-emerald-300 uppercase tracking-wider">Clean (0 Alerts)</span>
                                <div className="p-2 rounded-xl bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">
                                    <ShieldCheck className="w-4 h-4" />
                                </div>
                            </div>
                            <div className="text-2xl font-black text-emerald-400">{analytics?.metrics?.clean_students || 0}</div>
                            <p className="text-[11px] text-emerald-300/70 mt-1 font-medium">
                                {analytics?.metrics?.clean_percentage || 0}% verified honest
                            </p>
                        </div>

                        {/* 4. Zero Logs / Inactive */}
                        <div className="bg-slate-900/60 backdrop-blur-md rounded-2xl border border-slate-700/50 p-4 relative overflow-hidden shadow-lg">
                            <div className="flex justify-between items-start mb-2">
                                <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">Zero Logs / Disconnect</span>
                                <div className="p-2 rounded-xl bg-slate-700/50 text-slate-300 border border-slate-600">
                                    <AlertCircle className="w-4 h-4" />
                                </div>
                            </div>
                            <div className="text-2xl font-black text-slate-300">{analytics?.metrics?.zero_logs_students || 0}</div>
                            <p className="text-[11px] text-slate-400/80 mt-1 font-medium">
                                Monitor failed or not started
                            </p>
                        </div>

                        {/* 5. Peripheral & Device Tampering */}
                        <div className="bg-amber-950/20 backdrop-blur-md rounded-2xl border border-amber-500/30 p-4 relative overflow-hidden shadow-[0_0_20px_rgba(245,158,11,0.1)]">
                            <div className="flex justify-between items-start mb-2">
                                <span className="text-xs font-bold text-amber-300 uppercase tracking-wider">External Peripherals</span>
                                <div className="p-2 rounded-xl bg-amber-500/20 text-amber-400 border border-amber-500/40">
                                    <Usb className="w-4 h-4" />
                                </div>
                            </div>
                            <div className="text-2xl font-black text-amber-400">
                                {(analytics?.violation_categories?.find(c => c.category === 'Device Tampering')?.count) || 0}
                            </div>
                            <p className="text-[11px] text-amber-300/70 mt-1 font-medium">
                                Keyboards, Mice, USB plugs
                            </p>
                        </div>

                        {/* 6. Ledger Verified */}
                        <div className="bg-purple-950/20 backdrop-blur-md rounded-2xl border border-purple-500/30 p-4 relative overflow-hidden shadow-[0_0_20px_rgba(168,85,247,0.1)]">
                            <div className="flex justify-between items-start mb-2">
                                <span className="text-xs font-bold text-purple-300 uppercase tracking-wider">Offline Ledgers</span>
                                <div className="p-2 rounded-xl bg-purple-500/20 text-purple-400 border border-purple-500/40">
                                    <Lock className="w-4 h-4" />
                                </div>
                            </div>
                            <div className="text-2xl font-black text-purple-400">
                                {analytics?.metrics?.ledger_uploaded_count || 0}
                            </div>
                            <p className="text-[11px] text-purple-300/70 mt-1 font-medium">
                                Cryptographically verified
                            </p>
                        </div>
                    </div>

                    {/* Visual BI Charts Section */}
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                        {/* Chart 1: Risk Distribution Donut */}
                        <div className="bg-[#131B2F]/60 backdrop-blur-md rounded-2xl border border-indigo-500/15 p-5 shadow-lg flex flex-col">
                            <div className="flex justify-between items-center mb-3">
                                <h3 className="text-sm font-bold text-white flex items-center">
                                    <ShieldAlert className="w-4 h-4 mr-2 text-blue-400" />
                                    Student Risk Distribution
                                </h3>
                                <span className="text-xs text-indigo-300/60 font-mono">N = {analytics?.metrics?.total_students || 0}</span>
                            </div>
                            <div className="flex-1 min-h-[240px] flex items-center justify-center">
                                {analytics?.risk_distribution && analytics.risk_distribution.some(d => d.count > 0) ? (
                                    <ResponsiveContainer width="100%" height={240}>
                                        <PieChart>
                                            <Pie
                                                data={analytics.risk_distribution}
                                                cx="50%"
                                                cy="50%"
                                                innerRadius={60}
                                                outerRadius={85}
                                                paddingAngle={4}
                                                dataKey="count"
                                                nameKey="tier"
                                            >
                                                {analytics.risk_distribution.map((entry, index) => (
                                                    <Cell key={`cell-${index}`} fill={entry.color} />
                                                ))}
                                            </Pie>
                                            <Tooltip
                                                contentStyle={{ backgroundColor: '#0A0F1C', borderColor: '#312E81', borderRadius: '12px', fontSize: '12px' }}
                                                itemStyle={{ color: '#fff' }}
                                            />
                                            <Legend
                                                verticalAlign="bottom"
                                                height={36}
                                                iconType="circle"
                                                formatter={(value) => <span className="text-[11px] text-gray-300 font-medium">{value}</span>}
                                            />
                                        </PieChart>
                                    </ResponsiveContainer>
                                ) : (
                                    <div className="text-center text-gray-500 text-xs">No student data to display</div>
                                )}
                            </div>
                        </div>

                        {/* Chart 2: Malpractice Categories Breakdown */}
                        <div className="bg-[#131B2F]/60 backdrop-blur-md rounded-2xl border border-indigo-500/15 p-5 shadow-lg flex flex-col">
                            <div className="flex justify-between items-center mb-3">
                                <h3 className="text-sm font-bold text-white flex items-center">
                                    <AlertTriangle className="w-4 h-4 mr-2 text-amber-400" />
                                    Violations by Category
                                </h3>
                                <span className="text-xs text-amber-400/80 font-mono">
                                    Total: {analytics?.metrics?.total_suspicious || 0} Alerts
                                </span>
                            </div>
                            <div className="flex-1 min-h-[240px]">
                                {analytics?.violation_categories ? (
                                    <ResponsiveContainer width="100%" height={240}>
                                        <BarChart
                                            data={analytics.violation_categories}
                                            layout="vertical"
                                            margin={{ top: 5, right: 20, left: 20, bottom: 5 }}
                                        >
                                            <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" horizontal={false} />
                                            <XAxis type="number" stroke="#64748B" fontSize={11} />
                                            <YAxis
                                                dataKey="category"
                                                type="category"
                                                stroke="#94A3B8"
                                                fontSize={10}
                                                width={100}
                                                tick={{ fill: '#CBD5E1' }}
                                            />
                                            <Tooltip
                                                contentStyle={{ backgroundColor: '#0A0F1C', borderColor: '#312E81', borderRadius: '12px', fontSize: '12px' }}
                                                itemStyle={{ color: '#fff' }}
                                            />
                                            <Bar dataKey="count" radius={[0, 8, 8, 0]}>
                                                {analytics.violation_categories.map((entry, index) => (
                                                    <Cell key={`bar-${index}`} fill={entry.color} />
                                                ))}
                                            </Bar>
                                        </BarChart>
                                    </ResponsiveContainer>
                                ) : (
                                    <div className="text-center text-gray-500 text-xs py-20">No violation data recorded</div>
                                )}
                            </div>
                        </div>

                        {/* Chart 3: Incident Activity Timeline */}
                        <div className="bg-[#131B2F]/60 backdrop-blur-md rounded-2xl border border-indigo-500/15 p-5 shadow-lg flex flex-col">
                            <div className="flex justify-between items-center mb-3">
                                <h3 className="text-sm font-bold text-white flex items-center">
                                    <Clock className="w-4 h-4 mr-2 text-indigo-400" />
                                    Exam Incident Timeline
                                </h3>
                                <span className="text-xs text-indigo-300/60 font-mono">Live Progression</span>
                            </div>
                            <div className="flex-1 min-h-[240px]">
                                {analytics?.timeline && analytics.timeline.length > 0 ? (
                                    <ResponsiveContainer width="100%" height={240}>
                                        <AreaChart data={analytics.timeline} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                                            <defs>
                                                <linearGradient id="suspiciousGrad" x1="0" y1="0" x2="0" y2="1">
                                                    <stop offset="5%" stopColor="#EF4444" stopOpacity={0.8} />
                                                    <stop offset="95%" stopColor="#EF4444" stopOpacity={0} />
                                                </linearGradient>
                                                <linearGradient id="normalGrad" x1="0" y1="0" x2="0" y2="1">
                                                    <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.5} />
                                                    <stop offset="95%" stopColor="#3B82F6" stopOpacity={0} />
                                                </linearGradient>
                                            </defs>
                                            <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" />
                                            <XAxis dataKey="time" stroke="#64748B" fontSize={10} />
                                            <YAxis stroke="#64748B" fontSize={10} />
                                            <Tooltip
                                                contentStyle={{ backgroundColor: '#0A0F1C', borderColor: '#312E81', borderRadius: '12px', fontSize: '12px' }}
                                            />
                                            <Area type="monotone" dataKey="normal" stroke="#3B82F6" fillOpacity={1} fill="url(#normalGrad)" name="Normal Events" />
                                            <Area type="monotone" dataKey="suspicious" stroke="#EF4444" fillOpacity={1} fill="url(#suspiciousGrad)" name="Alerts" />
                                        </AreaChart>
                                    </ResponsiveContainer>
                                ) : (
                                    <div className="text-center text-gray-500 text-xs py-20">Timeline populating as students work...</div>
                                )}
                            </div>
                        </div>
                    </div>

                    {/* Student Scorecard & Triage Section (Designed for 100+ Students) */}
                    <div className="bg-[#131B2F]/60 backdrop-blur-md rounded-2xl border border-indigo-500/15 overflow-hidden shadow-2xl">
                        {/* Table Header Controls */}
                        <div className="p-5 border-b border-indigo-500/15 flex flex-col md:flex-row justify-between items-start md:items-center gap-4 bg-[#0A0F1C]/40">
                            <div>
                                <h3 className="text-lg font-bold text-white flex items-center">
                                    <Users className="w-5 h-5 mr-2.5 text-blue-400" />
                                    Student Exam Integrity Scorecard
                                </h3>
                                <p className="text-xs text-indigo-300/60 mt-0.5">
                                    Instantly triage students by risk tier, device connection events, and audit logs.
                                </p>
                            </div>

                            <div className="flex flex-wrap items-center gap-3 w-full md:w-auto">
                                {/* Search Bar */}
                                <div className="relative flex-1 md:w-64">
                                    <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
                                    <input
                                        type="text"
                                        placeholder="Search by student or email..."
                                        value={searchQuery}
                                        onChange={(e) => setSearchQuery(e.target.value)}
                                        className="w-full bg-[#0A0F1C]/80 border border-indigo-500/20 rounded-xl pl-9 pr-4 py-2 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 transition-colors"
                                    />
                                </div>

                                {/* Filter Pills */}
                                <div className="flex items-center bg-[#0A0F1C]/80 p-1 rounded-xl border border-indigo-500/20 text-xs font-bold">
                                    <button
                                        onClick={() => setStudentFilter('all')}
                                        className={`px-3 py-1.5 rounded-lg transition-all ${studentFilter === 'all' ? 'bg-blue-600 text-white shadow-md' : 'text-gray-400 hover:text-white'}`}
                                    >
                                        All ({analytics?.students?.length || 0})
                                    </button>
                                    <button
                                        onClick={() => setStudentFilter('critical')}
                                        className={`px-3 py-1.5 rounded-lg transition-all flex items-center space-x-1 ${studentFilter === 'critical' ? 'bg-red-600 text-white shadow-md' : 'text-red-400 hover:bg-red-500/10'}`}
                                    >
                                        <AlertTriangle className="w-3 h-3 mr-1" />
                                        <span>Critical ({analytics?.metrics?.critical_students || 0})</span>
                                    </button>
                                    <button
                                        onClick={() => setStudentFilter('warning')}
                                        className={`px-3 py-1.5 rounded-lg transition-all ${studentFilter === 'warning' ? 'bg-amber-600 text-white shadow-md' : 'text-amber-400 hover:bg-amber-500/10'}`}
                                    >
                                        Low Risk ({analytics?.metrics?.warning_students || 0})
                                    </button>
                                    <button
                                        onClick={() => setStudentFilter('clean')}
                                        className={`px-3 py-1.5 rounded-lg transition-all ${studentFilter === 'clean' ? 'bg-emerald-600 text-white shadow-md' : 'text-emerald-400 hover:bg-emerald-500/10'}`}
                                    >
                                        Clean ({analytics?.metrics?.clean_students || 0})
                                    </button>
                                    <button
                                        onClick={() => setStudentFilter('zero')}
                                        className={`px-3 py-1.5 rounded-lg transition-all ${studentFilter === 'zero' ? 'bg-slate-700 text-white shadow-md' : 'text-slate-400 hover:bg-slate-500/10'}`}
                                    >
                                        Zero Logs ({analytics?.metrics?.zero_logs_students || 0})
                                    </button>
                                </div>
                            </div>
                        </div>

                        {/* Table View */}
                        <div className="overflow-x-auto">
                            <table className="w-full text-left border-collapse text-xs">
                                <thead>
                                    <tr className="border-b border-indigo-500/15 bg-black/30 text-indigo-300 uppercase tracking-wider font-mono">
                                        <th className="py-3.5 px-4 font-bold">Student</th>
                                        <th className="py-3.5 px-4 font-bold">Risk Level</th>
                                        <th className="py-3.5 px-4 font-bold">Integrity Score</th>
                                        <th className="py-3.5 px-4 font-bold">Total Events</th>
                                        <th className="py-3.5 px-4 font-bold">Alert Flags</th>
                                        <th className="py-3.5 px-4 font-bold">External Devices</th>
                                        <th className="py-3.5 px-4 font-bold">Offline Ledger</th>
                                        <th className="py-3.5 px-4 font-bold">Top Detected Infraction</th>
                                        <th className="py-3.5 px-4 font-bold text-right">Action</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-indigo-500/10">
                                    {filteredStudents.length === 0 ? (
                                        <tr>
                                            <td colSpan={9} className="py-12 text-center text-gray-500">
                                                No students matched the selected filter criteria.
                                            </td>
                                        </tr>
                                    ) : (
                                        filteredStudents.map((s) => (
                                            <tr
                                                key={s.session_id}
                                                className={`transition-colors hover:bg-indigo-500/5 ${
                                                    s.risk_tier === 'CRITICAL'
                                                        ? 'bg-red-950/10'
                                                        : s.risk_tier === 'ZERO_LOGS'
                                                        ? 'bg-slate-900/20'
                                                        : ''
                                                }`}
                                            >
                                                {/* Student Info */}
                                                <td className="py-3.5 px-4">
                                                    <div className="font-bold text-white text-sm flex items-center">
                                                        <span>{s.username}</span>
                                                        <span className="ml-2 text-[10px] text-gray-500 font-mono">#{s.student_id}</span>
                                                    </div>
                                                    <div className="text-gray-400 text-[11px] truncate max-w-[160px]">{s.email}</div>
                                                </td>

                                                {/* Risk Tier Badge */}
                                                <td className="py-3.5 px-4">
                                                    {s.risk_tier === 'CRITICAL' && (
                                                        <span className="px-2.5 py-1 bg-red-500/20 text-red-400 border border-red-500/30 rounded-full font-bold uppercase tracking-wider text-[10px] flex items-center w-fit shadow-[0_0_10px_rgba(239,68,68,0.2)]">
                                                            <AlertTriangle className="w-3 h-3 mr-1" /> Critical
                                                        </span>
                                                    )}
                                                    {s.risk_tier === 'WARNING' && (
                                                        <span className="px-2.5 py-1 bg-amber-500/20 text-amber-400 border border-amber-500/30 rounded-full font-bold uppercase tracking-wider text-[10px] flex items-center w-fit">
                                                            <AlertCircle className="w-3 h-3 mr-1" /> Low Risk
                                                        </span>
                                                    )}
                                                    {s.risk_tier === 'CLEAN' && (
                                                        <span className="px-2.5 py-1 bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 rounded-full font-bold uppercase tracking-wider text-[10px] flex items-center w-fit">
                                                            <CheckCircle className="w-3 h-3 mr-1" /> Clean
                                                        </span>
                                                    )}
                                                    {s.risk_tier === 'ZERO_LOGS' && (
                                                        <span className="px-2.5 py-1 bg-slate-700/50 text-slate-300 border border-slate-600 rounded-full font-bold uppercase tracking-wider text-[10px] flex items-center w-fit">
                                                            <AlertCircle className="w-3 h-3 mr-1" /> Zero Logs
                                                        </span>
                                                    )}
                                                </td>

                                                {/* Integrity Score Progress Bar */}
                                                <td className="py-3.5 px-4">
                                                    <div className="w-28">
                                                        <div className="flex justify-between text-[11px] font-bold mb-1">
                                                            <span className={
                                                                s.integrity_score >= 80 ? 'text-emerald-400' :
                                                                s.integrity_score >= 50 ? 'text-amber-400' : 'text-red-400'
                                                            }>{s.integrity_score}%</span>
                                                        </div>
                                                        <div className="h-1.5 w-full bg-gray-800 rounded-full overflow-hidden">
                                                            <div
                                                                className={`h-full rounded-full transition-all ${
                                                                    s.integrity_score >= 80 ? 'bg-gradient-to-r from-emerald-500 to-green-400' :
                                                                    s.integrity_score >= 50 ? 'bg-gradient-to-r from-yellow-500 to-amber-500' :
                                                                    'bg-gradient-to-r from-red-600 to-rose-500'
                                                                }`}
                                                                style={{ width: `${s.integrity_score}%` }}
                                                            />
                                                        </div>
                                                    </div>
                                                </td>

                                                {/* Total Logs */}
                                                <td className="py-3.5 px-4 font-mono text-gray-300 font-medium">
                                                    {s.total_logs}
                                                </td>

                                                {/* Suspicious Logs */}
                                                <td className="py-3.5 px-4 font-mono font-bold">
                                                    {s.suspicious_logs > 0 ? (
                                                        <span className="text-red-400 bg-red-500/10 px-2 py-0.5 rounded border border-red-500/20">
                                                            {s.suspicious_logs}
                                                        </span>
                                                    ) : (
                                                        <span className="text-emerald-400">0</span>
                                                    )}
                                                </td>

                                                {/* Device / External Peripherals Count */}
                                                <td className="py-3.5 px-4">
                                                    {s.device_alerts > 0 ? (
                                                        <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 font-bold flex items-center w-fit">
                                                            <Usb className="w-3 h-3 mr-1" />
                                                            {s.device_alerts} Plugged
                                                        </span>
                                                    ) : (
                                                        <span className="text-gray-500">None</span>
                                                    )}
                                                </td>

                                                {/* Offline Ledger */}
                                                <td className="py-3.5 px-4">
                                                    {s.ledger_uploaded ? (
                                                        <span className="px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30 font-bold flex items-center w-fit text-[10px]">
                                                            <Lock className="w-2.5 h-2.5 mr-1" /> Verified
                                                        </span>
                                                    ) : (
                                                        <span className="text-gray-500 text-[11px]">Pending</span>
                                                    )}
                                                </td>

                                                {/* Top Infraction Preview */}
                                                <td className="py-3.5 px-4">
                                                    {s.top_infractions && s.top_infractions.length > 0 ? (
                                                        <div className="text-[11px] text-red-300 truncate max-w-[220px] bg-red-500/10 px-2 py-1 rounded border border-red-500/20 font-mono" title={s.top_infractions[0]}>
                                                            {s.top_infractions[0]}
                                                        </div>
                                                    ) : (
                                                        <span className="text-gray-500 text-[11px]">No infractions</span>
                                                    )}
                                                </td>

                                                {/* Actions */}
                                                <td className="py-3.5 px-4 text-right">
                                                    <button
                                                        onClick={() => inspectStudent(s.session_id)}
                                                        className="px-3 py-1.5 bg-blue-600/20 hover:bg-blue-600 text-blue-400 hover:text-white border border-blue-500/30 rounded-lg text-xs font-bold transition-all"
                                                    >
                                                        Inspect Logs
                                                    </button>
                                                </td>
                                            </tr>
                                        ))
                                    )}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            )}

            {/* TAB 2: LIVE LOGS STREAM (Granular 1-on-1 Inspection View) */}
            {activeTab === 'logs' && (
                <div className="flex flex-1 overflow-hidden">
                    {/* Left Sidebar: Student List */}
                    <div className="w-1/3 min-w-[300px] max-w-[380px] bg-[#131B2F]/40 backdrop-blur-md border-r border-indigo-500/20 flex flex-col z-0">
                        <div className="p-4 border-b border-indigo-500/10 bg-[#0A0F1C]/50 flex justify-between items-center">
                            <h2 className="text-xs font-bold text-indigo-300 uppercase tracking-widest flex items-center">
                                <Users className="h-4 w-4 mr-2" /> Select Student ({sessions.length})
                            </h2>
                            <button
                                onClick={() => setActiveTab('analytics')}
                                className="text-xs text-blue-400 hover:underline flex items-center font-bold"
                            >
                                <BarChart3 className="w-3.5 h-3.5 mr-1" /> Analytics
                            </button>
                        </div>
                        <div className="flex-1 overflow-y-auto custom-scrollbar">
                            {loading && sessions.length === 0 ? (
                                <div className="p-8 text-center">
                                    <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-blue-500 mx-auto"></div>
                                </div>
                            ) : sessions.length === 0 ? (
                                <div className="p-8 text-center text-indigo-300/50 text-sm">
                                    <p>No students have joined yet.</p>
                                </div>
                            ) : (
                                <ul className="divide-y divide-indigo-500/10">
                                    {sessions.map((session) => (
                                        <li key={session.id}>
                                            <button
                                                onClick={() => setSelectedSessionId(session.id)}
                                                className={`w-full text-left p-4 transition-all border-l-4 ${
                                                    selectedSessionId === session.id
                                                        ? 'bg-blue-600/15 border-blue-500 shadow-[inset_0_0_20px_rgba(37,71,244,0.15)]'
                                                        : 'border-transparent hover:bg-white/5'
                                                }`}
                                            >
                                                <div className="flex justify-between items-start">
                                                    <div>
                                                        <p className={`font-bold ${selectedSessionId === session.id ? 'text-blue-300' : 'text-gray-200'}`}>
                                                            {session.student?.username || 'Unknown'}
                                                        </p>
                                                        <p className="text-xs text-indigo-300/60 mt-0.5 truncate">{session.student?.email}</p>
                                                    </div>
                                                    <div className="flex flex-col items-end space-y-1">
                                                        <span className={`text-[10px] px-2 py-0.5 rounded-full font-bold uppercase border ${
                                                            session.end_time
                                                                ? 'bg-[#131B2F]/60 text-gray-400 border-gray-600'
                                                                : 'bg-green-500/10 text-green-400 border-green-500/30'
                                                        }`}>
                                                            {session.end_time ? 'Completed' : 'Active'}
                                                        </span>
                                                        {session.ledger_uploaded && (
                                                            <span className="text-[9px] px-1.5 py-0.2 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30 font-bold uppercase">
                                                                Ledger
                                                            </span>
                                                        )}
                                                    </div>
                                                </div>
                                                <p className="text-[10px] text-indigo-400/40 mt-1 font-mono">
                                                    Session #{session.id}
                                                </p>
                                            </button>
                                        </li>
                                    ))}
                                </ul>
                            )}
                        </div>
                    </div>

                    {/* Right Content: Student Logs Feed */}
                    <div className="flex-1 min-w-0 bg-transparent flex flex-col relative z-0">
                        {!selectedSession ? (
                            <div className="flex-1 flex flex-col items-center justify-center text-gray-500 p-8">
                                <div className="bg-gray-800 p-6 rounded-full mb-4">
                                    <Users className="h-12 w-12 text-gray-600" />
                                </div>
                                <h3 className="text-xl font-medium text-gray-300">Select a Student</h3>
                                <p className="max-w-md text-center mt-2 text-gray-600">
                                    Click on a student from the sidebar or click "Inspect Logs" from the Analytics Scorecard.
                                </p>
                            </div>
                        ) : (
                            <>
                                {/* Selected Student Bar */}
                                <div className="bg-[#131B2F]/60 backdrop-blur-md border-b border-indigo-500/20 px-6 py-4 flex flex-wrap justify-between items-center gap-3 shadow-md">
                                    <div>
                                        <h2 className="text-xl font-bold text-white flex items-center">
                                            {selectedSession.student?.username}
                                            <span className="ml-3 text-xs font-bold text-indigo-300/70 border border-indigo-500/30 px-3 py-1 rounded-full bg-indigo-500/5">
                                                {selectedSession.student?.email}
                                            </span>
                                        </h2>
                                    </div>

                                    <div className="flex items-center space-x-3">
                                        {/* Toggle Live vs Offline Ledger */}
                                        {selectedSession.ledger_uploaded && (
                                            <div className="flex items-center space-x-1 bg-[#0A0F1C]/80 rounded-lg p-1 border border-indigo-500/20">
                                                <button
                                                    onClick={() => setViewLedgerMode(false)}
                                                    className={`text-xs px-3 py-1 rounded-md font-bold transition-all ${!viewLedgerMode ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white'}`}
                                                >
                                                    Live Logs
                                                </button>
                                                <button
                                                    onClick={() => setViewLedgerMode(true)}
                                                    className={`text-xs px-3 py-1 rounded-md font-bold transition-all ${viewLedgerMode ? 'bg-purple-600 text-white' : 'text-gray-400 hover:text-white'}`}
                                                >
                                                    Ledger Logs
                                                </button>
                                            </div>
                                        )}

                                        {/* Critical Only Filter */}
                                        <button
                                            onClick={() => setShowCriticalOnly(!showCriticalOnly)}
                                            className={`text-xs px-3 py-1.5 rounded-lg border font-bold transition-all flex items-center ${
                                                showCriticalOnly
                                                    ? 'bg-red-500/20 text-red-400 border-red-500/50 shadow-[0_0_10px_rgba(239,68,68,0.2)]'
                                                    : 'bg-[#131B2F] border-indigo-500/20 text-gray-400 hover:text-white'
                                            }`}
                                        >
                                            <AlertTriangle className="w-3.5 h-3.5 mr-1" />
                                            <span>Critical Only</span>
                                        </button>

                                        {/* Log Category Filter */}
                                        <select
                                            value={logTypeFilter}
                                            onChange={(e) => setLogTypeFilter(e.target.value)}
                                            className="bg-[#0A0F1C] border border-indigo-500/20 rounded-lg px-2.5 py-1 text-xs text-gray-300 focus:outline-none"
                                        >
                                            <option value="all">All Types</option>
                                            <option value="warning">File Explorer / Warnings</option>
                                            <option value="device">External Devices</option>
                                            <option value="alert">Critical Alerts</option>
                                            <option value="process">Processes</option>
                                            <option value="url">URLs / DNS</option>
                                        </select>

                                        {/* Auto-Refresh Toggle */}
                                        <button
                                            onClick={() => setAutoRefresh(!autoRefresh)}
                                            disabled={viewLedgerMode || Boolean(selectedSession?.end_time)}
                                            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-bold transition-all border ${
                                                autoRefresh && !viewLedgerMode && !selectedSession?.end_time
                                                    ? 'bg-green-500/10 text-green-400 border-green-500/30'
                                                    : 'bg-[#131B2F] text-gray-400 border-indigo-500/20'
                                            }`}
                                        >
                                            <RefreshCw className={`h-3.5 w-3.5 ${autoRefresh && !viewLedgerMode ? 'animate-spin text-green-400' : ''}`} />
                                            <span>{autoRefresh ? 'Live' : 'Paused'}</span>
                                        </button>
                                    </div>
                                </div>

                                {/* Logs Stream Feed */}
                                <div className="flex-1 overflow-y-auto p-6 space-y-3 custom-scrollbar">
                                    {selectedSession.ledger_uploaded && !viewLedgerMode && (
                                        <div className="bg-purple-600/10 border border-purple-500/30 p-4 rounded-xl mb-4 flex items-center justify-between shadow-lg backdrop-blur-sm">
                                            <div className="flex items-center space-x-3">
                                                <div className="bg-purple-500/20 p-2 rounded-full">
                                                    <CheckCircle className="w-5 h-5 text-purple-400" />
                                                </div>
                                                <div>
                                                    <h4 className="font-bold text-sm text-purple-100">Exam Ledger Available</h4>
                                                    <p className="text-xs text-purple-300/80">Student has uploaded their encrypted offline ledger.</p>
                                                </div>
                                            </div>
                                            <button
                                                onClick={() => setViewLedgerMode(true)}
                                                className="bg-purple-600 hover:bg-purple-500 text-white px-3.5 py-1.5 rounded-lg text-xs font-bold transition-all"
                                            >
                                                Switch to Ledger
                                            </button>
                                        </div>
                                    )}

                                    {logs.length === 0 ? (
                                        <div className="text-center py-20 text-indigo-300/50 font-medium">
                                            No activity logs recorded for this student yet.
                                        </div>
                                    ) : (
                                        logs
                                            .slice()
                                            .reverse()
                                            .filter(log => !showCriticalOnly || (log.is_suspicious && !(log.content || '').toLowerCase().includes('file explorer') && !(log.content || '').toLowerCase().includes('internal storage')))
                                            .filter(log => {
                                                if (logTypeFilter === 'all') return true;
                                                const lt = (log.log_type || '').toLowerCase();
                                                if (logTypeFilter === 'warning') {
                                                    return lt === 'warning' || (log.content || '').toLowerCase().includes('file explorer') || (log.content || '').toLowerCase().includes('internal storage');
                                                }
                                                return lt === logTypeFilter.toLowerCase();
                                            })
                                            .map((log, index) => {
                                                const isDeviceLog = (log.log_type || '').toLowerCase() === 'device';
                                                const contentLower = (log.content || '').toLowerCase();
                                                const isKeyboard = contentLower.includes('keyboard');
                                                const isMouse = contentLower.includes('mouse') || contentLower.includes('pointer');
                                                const isFileExplorer = contentLower.includes('file explorer') || contentLower.includes('internal storage');
                                                const isWarningLog = (log.log_type || '').toLowerCase() === 'warning' || isFileExplorer;

                                                return (
                                                    <div
                                                        key={index}
                                                        className={`p-4 rounded-xl border text-xs font-mono transition-all backdrop-blur-sm ${
                                                            isWarningLog
                                                                ? 'bg-amber-500/10 border-amber-500/40 text-amber-200 shadow-[0_0_15px_rgba(245,158,11,0.15)]'
                                                                : log.is_suspicious
                                                                ? 'bg-red-500/10 border-red-500/30 text-red-200 shadow-[0_0_15px_rgba(239,68,68,0.1)]'
                                                                : isDeviceLog
                                                                ? 'bg-amber-500/10 border-amber-500/30 text-amber-200'
                                                                : 'bg-[#131B2F]/50 border-indigo-500/10 text-gray-300 hover:border-blue-500/30'
                                                        }`}
                                                    >
                                                        <div className="flex justify-between items-start mb-2">
                                                            <div className="flex items-center space-x-2">
                                                                {isWarningLog ? (
                                                                    <div className="bg-amber-500/20 p-1 rounded-md text-amber-400">
                                                                        <FolderOpen className="w-3.5 h-3.5" />
                                                                    </div>
                                                                ) : log.is_suspicious ? (
                                                                    <div className="bg-red-500/20 p-1 rounded-md text-red-400">
                                                                        <AlertTriangle className="w-3.5 h-3.5" />
                                                                    </div>
                                                                ) : isDeviceLog ? (
                                                                    <div className="bg-amber-500/20 p-1 rounded-md text-amber-400">
                                                                        {isKeyboard ? <Keyboard className="w-3.5 h-3.5" /> : isMouse ? <Mouse className="w-3.5 h-3.5" /> : <Usb className="w-3.5 h-3.5" />}
                                                                    </div>
                                                                ) : (
                                                                    <div className="bg-green-500/10 p-1 rounded-md text-green-400">
                                                                        <CheckCircle className="w-3.5 h-3.5" />
                                                                    </div>
                                                                )}

                                                                {/* Log Type Pill */}
                                                                <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold tracking-wider border ${
                                                                    isWarningLog ? 'bg-amber-500/20 text-amber-300 border-amber-500/40' :
                                                                    isDeviceLog ? 'bg-amber-500/20 text-amber-300 border-amber-500/40' :
                                                                    log.log_type === 'alert' ? 'bg-red-500/20 text-red-400 border-red-500/30' :
                                                                    log.log_type === 'process' ? 'bg-blue-500/20 text-blue-400 border-blue-500/30' :
                                                                    log.log_type === 'url' ? 'bg-purple-500/20 text-purple-400 border-purple-500/30' :
                                                                    'bg-gray-700/50 text-gray-400 border-gray-600'
                                                                }`}>
                                                                    {isWarningLog ? 'WARNING' : log.log_type}
                                                                </span>

                                                                {log.source === 'ledger' && (
                                                                    <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30">
                                                                        OFFLINE
                                                                    </span>
                                                                )}
                                                            </div>

                                                            <span className="text-gray-500 text-[11px] font-sans">
                                                                {new Date(log.timestamp.endsWith('Z') ? log.timestamp : log.timestamp + 'Z').toLocaleTimeString()}
                                                            </span>
                                                        </div>

                                                        <p className="break-all leading-relaxed text-xs mt-1.5 ml-1 font-mono">
                                                            {log.content}
                                                        </p>
                                                    </div>
                                                );
                                            })
                                    )}
                                </div>
                            </>
                        )}
                    </div>
                </div>
            )}

            {/* Power BI Modal Guide */}
            {showPowerBIModal && (
                <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 backdrop-blur-md p-4">
                    <div className="bg-[#131B2F] border border-amber-500/30 rounded-2xl p-6 w-full max-w-2xl shadow-2xl relative">
                        <button
                            onClick={() => setShowPowerBIModal(false)}
                            className="absolute right-4 top-4 text-gray-400 hover:text-white p-1 rounded-lg hover:bg-white/10"
                        >
                            <X className="w-5 h-5" />
                        </button>

                        <div className="flex items-center space-x-3 mb-4">
                            <div className="bg-amber-500/20 p-2.5 rounded-xl border border-amber-500/40 text-amber-400">
                                <FileSpreadsheet className="w-6 h-6" />
                            </div>
                            <div>
                                <h3 className="text-lg font-bold text-white">How to Load Data into Microsoft Power BI</h3>
                                <p className="text-xs text-amber-300/80">Step-by-step instructions for enterprise proctoring analytics</p>
                            </div>
                        </div>

                        <div className="space-y-4 text-xs text-gray-300">
                            <div className="bg-[#0A0F1C] p-4 rounded-xl border border-indigo-500/20 space-y-2">
                                <h4 className="font-bold text-white text-sm">Step 1: Download the Power BI Dataset</h4>
                                <p>Click the <strong>"Export for Power BI"</strong> button in the top bar. It will generate a pre-formatted CSV file encoded with UTF-8 BOM for seamless column mapping.</p>
                            </div>

                            <div className="bg-[#0A0F1C] p-4 rounded-xl border border-indigo-500/20 space-y-2">
                                <h4 className="font-bold text-white text-sm">Step 2: Open Power BI Desktop</h4>
                                <ol className="list-decimal list-inside space-y-1 text-gray-300">
                                    <li>Open <strong>Microsoft Power BI Desktop</strong>.</li>
                                    <li>Click on <strong>"Get Data" → "Text/CSV"</strong>.</li>
                                    <li>Select the downloaded <code className="text-amber-300 font-mono">PowerBI_Exam_Room_{roomId}_Analytics.csv</code>.</li>
                                    <li>Click <strong>"Load"</strong> (No transformation necessary; all numeric types and boolean flags are normalized).</li>
                                </ol>
                            </div>

                            <div className="bg-[#0A0F1C] p-4 rounded-xl border border-indigo-500/20 space-y-2">
                                <h4 className="font-bold text-white text-sm">Step 3: Recommended Visualizations</h4>
                                <ul className="list-disc list-inside space-y-1 text-gray-300">
                                    <li><strong>Donut Chart:</strong> Legend = <code className="text-blue-300 font-mono">RiskTier</code>, Values = Count of <code className="text-blue-300 font-mono">StudentID</code>.</li>
                                    <li><strong>Clustered Bar Chart:</strong> Axis = <code className="text-blue-300 font-mono">StudentUsername</code>, Values = <code className="text-blue-300 font-mono">DeviceAlerts</code>, <code className="text-blue-300 font-mono">WindowAlerts</code>.</li>
                                    <li><strong>Slicer:</strong> Field = <code className="text-blue-300 font-mono">IsZeroLogs</code> to instantly filter unattended vs active exam tokens.</li>
                                    <li><strong>Gauge Chart:</strong> Value = Average of <code className="text-blue-300 font-mono">IntegrityScore</code> (Target = 100%).</li>
                                </ul>
                            </div>
                        </div>

                        <div className="flex justify-end space-x-3 mt-6">
                            <button
                                onClick={handleExportPowerBI}
                                className="px-4 py-2 bg-gradient-to-r from-amber-600 to-yellow-600 hover:from-amber-500 hover:to-yellow-500 text-white rounded-xl text-xs font-bold transition-all shadow-md"
                            >
                                Download Dataset (.csv)
                            </button>
                            <button
                                onClick={() => setShowPowerBIModal(false)}
                                className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-xl text-xs font-bold transition-all"
                            >
                                Close
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default ExamDetails;
