import { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import api from '../api/axios';
import { ArrowLeft, AlertTriangle, CheckCircle, RefreshCw, Users, Download } from 'lucide-react';
import { saveAs } from 'file-saver';

const ExamDetails = () => {
    const { roomId } = useParams();
    const [sessions, setSessions] = useState([]); // List of { id, student, ... }
    const [selectedSessionId, setSelectedSessionId] = useState(null);
    const [logs, setLogs] = useState([]);
    const [loading, setLoading] = useState(true);
    const [autoRefresh, setAutoRefresh] = useState(true);
    const [viewLedgerMode, setViewLedgerMode] = useState(false);
    const [showCriticalOnly, setShowCriticalOnly] = useState(false);

    const navigate = useNavigate();

    // Derived state
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

    // Initial load and Polling
    // Keep a ref to sessions to use in interval without triggering re-renders/effect resets
    const sessionsRef = useRef(sessions);
    useEffect(() => {
        sessionsRef.current = sessions;
    }, [sessions]);

    // Initial load and Polling
    useEffect(() => {
        fetchSessions();
        const interval = setInterval(() => {
            fetchSessions(); // Always update session list to see new students/status changes

            // Auto-refresh logs only if:
            // 1. Auto-refresh is enabled
            // 2. We are NOT looking at static ledger logs
            // 3. A session is selected
            // 4. The session is NOT completed (check ref for latest data)
            if (autoRefresh && !viewLedgerMode && selectedSessionId) {
                const currentSession = sessionsRef.current.find(s => s.id === selectedSessionId);
                if (currentSession && !currentSession.end_time) {
                    fetchLogs();
                }
            }
        }, 1000);
        return () => clearInterval(interval);
    }, [roomId, selectedSessionId, autoRefresh, viewLedgerMode]); // Removed selectedSession/sessions from deps

    // Fetch logs immediately when selection changes or mode changes
    useEffect(() => {
        if (selectedSessionId) {
            setLogs([]); // Clear previous logs
            setShowCriticalOnly(false); // Reset filter
            fetchLogs();
        }
    }, [selectedSessionId, viewLedgerMode]);

    const handleExport = async () => {
        try {
            const response = await api.get(`/exams/room/${roomId}/export_csv`, {
                responseType: 'blob',
            });
            const blob = new Blob([response.data], { type: 'text/csv' });
            saveAs(blob, `exam_room_${roomId}_logs.csv`);
        } catch (error) {
            console.error("Export failed", error);
        }
    };

    return (
        <div className="min-h-screen bg-gray-900 text-white font-sans flex flex-col h-screen overflow-hidden">
            {/* Header */}
            <div className="bg-gray-800 border-b border-gray-700 p-4 flex justify-between items-center shadow-lg z-10">
                <div className="flex items-center space-x-4">
                    <button
                        onClick={() => navigate('/teacher')}
                        className="p-2 hover:bg-gray-700 rounded-full transition-colors"
                    >
                        <ArrowLeft className="h-6 w-6 text-gray-400" />
                    </button>
                    <div>
                        <h1 className="text-xl font-bold flex items-center">
                            Exam Monitor <span className="ml-2 px-2 py-0.5 bg-blue-500/10 text-blue-400 text-sm rounded-md font-mono">#{roomId}</span>
                        </h1>
                        <p className="text-xs text-gray-400 mt-0.5">
                            {sessions.length} Students Enrolled
                        </p>
                    </div>
                </div>
                <div className="flex items-center space-x-3">
                    <button
                        onClick={() => setAutoRefresh(!autoRefresh)}
                        disabled={viewLedgerMode || (selectedSession && selectedSession.end_time)}
                        className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${viewLedgerMode ? 'bg-gray-700 text-gray-500 opacity-50 cursor-not-allowed' :
                            (selectedSession && selectedSession.end_time) ? 'bg-gray-700 text-gray-400 opacity-75 cursor-not-allowed' :
                                autoRefresh ? 'bg-green-500/10 text-green-400 border border-green-500/20' :
                                    'bg-gray-700 text-gray-400 opacity-50 cursor-not-allowed'
                            }`}
                        title={selectedSession?.end_time ? "Session Completed" : "Toggle Auto-Refresh"}
                    >
                        {selectedSession?.end_time ? (
                            <CheckCircle className="h-4 w-4" />
                        ) : (
                            <RefreshCw className={`h-4 w-4 ${autoRefresh && !viewLedgerMode ? 'animate-spin' : ''}`} />
                        )}
                        <span>
                            {selectedSession?.end_time ? 'Completed' :
                                viewLedgerMode ? 'Offline View' :
                                    autoRefresh ? 'Live' : 'Paused'}
                        </span>
                    </button>
                    <button
                        onClick={handleExport}
                        className="flex items-center space-x-2 px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium transition-colors shadow-lg shadow-blue-600/20"
                    >
                        <Download className="h-4 w-4" />
                        <span>Export CSV</span>
                    </button>
                </div>
            </div>

            {/* Main Layout */}
            <div className="flex flex-1 overflow-hidden">

                {/* Left Sidebar: Student List */}
                <div className="w-1/3 min-w-[300px] max-w-[400px] bg-gray-800/50 border-r border-gray-700 flex flex-col">
                    <div className="p-4 border-b border-gray-700 bg-gray-800">
                        <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider flex items-center">
                            <Users className="h-4 w-4 mr-2" /> Students
                        </h2>
                    </div>
                    <div className="flex-1 overflow-y-auto overflow-x-hidden custom-scrollbar">
                        {loading && sessions.length === 0 ? (
                            <div className="p-8 text-center">
                                <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-blue-500 mx-auto"></div>
                            </div>
                        ) : sessions.length === 0 ? (
                            <div className="p-8 text-center text-gray-500 text-sm">
                                <p>No students have joined yet.</p>
                                <p className="mt-2 text-xs">Share the exam code with your students.</p>
                            </div>
                        ) : (
                            <ul className="divide-y divide-gray-700/50">
                                {sessions.map((session) => (
                                    <li key={session.id}>
                                        <button
                                            onClick={() => setSelectedSessionId(session.id)}
                                            className={`w-full text-left p-4 hover:bg-gray-700/50 transition-all border-l-4 ${selectedSessionId === session.id ? 'bg-blue-900/20 border-blue-500' : 'border-transparent'}`}
                                        >
                                            <div className="flex justify-between items-start">
                                                <div>
                                                    <p className={`font-medium ${selectedSessionId === session.id ? 'text-blue-300' : 'text-gray-200'}`}>
                                                        {session.student?.username || 'Unknown'}
                                                    </p>
                                                    <p className="text-xs text-gray-500 mt-0.5 truncate">{session.student?.email}</p>
                                                </div>
                                                <span className={`text-[10px] px-1.5 py-0.5 rounded border ${session.end_time
                                                    ? 'bg-gray-700 text-gray-400 border-gray-600'
                                                    : 'bg-green-500/10 text-green-400 border-green-500/20'
                                                    }`}>
                                                    {session.end_time ? 'Completed' : 'Active'}
                                                </span>
                                                {session.ledger_uploaded && (
                                                    <span className="ml-2 text-[10px] px-1.5 py-0.5 rounded border bg-purple-500/10 text-purple-400 border-purple-500/20" title="Ledger Uploaded">
                                                        Ledger
                                                    </span>
                                                )}
                                            </div>
                                            <p className="text-[10px] text-gray-600 mt-2 font-mono">
                                                Session ID: {session.id}
                                            </p>
                                        </button>
                                    </li>
                                ))}
                            </ul>
                        )}
                    </div>
                </div>

                {/* Right Content: Student Logs */}
                <div className="flex-1 bg-gray-900 flex flex-col relative">
                    {!selectedSession ? (
                        <div className="flex-1 flex flex-col items-center justify-center text-gray-500 p-8">
                            <div className="bg-gray-800 p-6 rounded-full mb-4">
                                <Users className="h-12 w-12 text-gray-600" />
                            </div>
                            <h3 className="text-xl font-medium text-gray-300">Select a Student</h3>
                            <p className="max-w-md text-center mt-2 text-gray-600">
                                Click on a student from the sidebar to view their real-time activity logs and security alerts.
                            </p>
                        </div>
                    ) : (
                        <>
                            {/* Selected Student Header */}
                            <div className="bg-gray-800/30 border-b border-gray-700 px-6 py-4 flex justify-between items-center">
                                <div>
                                    <h2 className="text-lg font-bold text-white flex items-center">
                                        {selectedSession.student?.username}
                                        <span className="ml-3 text-xs font-normal text-gray-400 border border-gray-600 px-2 py-0.5 rounded-full">
                                            {selectedSession.student?.email}
                                        </span>
                                    </h2>
                                </div>
                                <div className="flex items-center space-x-4">
                                    {selectedSession.ledger_uploaded && (
                                        <div className="flex items-center space-x-2 bg-gray-800 rounded-lg p-1 border border-gray-700">
                                            <button
                                                onClick={() => setViewLedgerMode(false)}
                                                className={`text-xs px-3 py-1.5 rounded-md transition-all ${!viewLedgerMode ? 'bg-gray-700 text-white shadow' : 'text-gray-400 hover:text-gray-200'}`}
                                            >
                                                Live Logs
                                            </button>
                                            <button
                                                onClick={() => setViewLedgerMode(true)}
                                                className={`text-xs px-3 py-1.5 rounded-md transition-all flex items-center ${viewLedgerMode ? 'bg-purple-600 text-white shadow' : 'text-gray-400 hover:text-gray-200'}`}
                                            >
                                                <span>Ledger Logs</span>
                                                {viewLedgerMode && <CheckCircle className="w-3 h-3 ml-1.5" />}
                                            </button>
                                        </div>
                                    )}

                                    {selectedSession.ledger_uploaded && !viewLedgerMode && (
                                        <button
                                            onClick={async () => {
                                                try {
                                                    const response = await api.get(`/exams/${selectedSession.id}/export_logs_txt`, {
                                                        responseType: 'blob',
                                                    });
                                                    const blob = new Blob([response.data], { type: 'text/plain' });
                                                    saveAs(blob, `session_${selectedSession.id}_logs.txt`);
                                                } catch (error) {
                                                    console.error("Download failed", error);
                                                    alert("Failed to download logs.");
                                                }
                                            }}
                                            className="text-gray-400 hover:text-white transition-colors"
                                            title="Download Decrypted Logs (TXT)"
                                        >
                                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="lucide lucide-file-text"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" /><polyline points="14 2 14 8 20 8" /><line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" /><line x1="10" y1="9" x2="8" y2="9" /></svg>
                                        </button>
                                    )}

                                    {viewLedgerMode && (
                                        <button
                                            onClick={() => setShowCriticalOnly(!showCriticalOnly)}
                                            className={`text-xs px-3 py-1.5 rounded-md transition-all flex items-center border ${showCriticalOnly
                                                ? 'bg-red-900/30 text-red-200 border-red-500/50'
                                                : 'border-gray-700 text-gray-400 hover:text-gray-200 hover:border-gray-600'
                                                }`}
                                            title={showCriticalOnly ? "Show All Logs" : "Show Critical Only"}
                                        >
                                            <AlertTriangle className="w-3 h-3 mr-1.5" />
                                            <span>Critical Only</span>
                                        </button>
                                    )}

                                    <div className="text-sm text-gray-400">
                                        <span className={`font-mono ${viewLedgerMode ? 'text-purple-400' : 'text-blue-400'}`}>{logs.length}</span> Events Logged
                                    </div>
                                </div>
                            </div>

                            {/* Logs Stream */}
                            <div className="flex-1 overflow-y-auto p-6 space-y-3 custom-scrollbar">

                                {selectedSession.ledger_uploaded && !viewLedgerMode && (
                                    <div className="bg-purple-600/10 border border-purple-500/30 p-4 rounded-xl mb-6 flex items-center justify-between shadow-lg shadow-purple-900/20 backdrop-blur-sm">
                                        <div className="flex items-center">
                                            <div className="bg-purple-500/20 p-2 rounded-full mr-4">
                                                <CheckCircle className="w-6 h-6 text-purple-400" />
                                            </div>
                                            <div>
                                                <h4 className="font-bold text-lg text-purple-100">Exam Ledger Uploaded</h4>
                                                <p className="text-xs text-purple-300">
                                                    This student has completed the exam and verified their offline logs.
                                                    Switch to Ledger view to see the full, decrypted history including offline activity.
                                                </p>
                                            </div>
                                        </div>
                                        <button
                                            onClick={() => setViewLedgerMode(true)}
                                            className="bg-purple-600 hover:bg-purple-500 text-white px-5 py-2.5 rounded-lg text-sm font-bold shadow-md transition-all hover:scale-105"
                                        >
                                            View Ledger Logs
                                        </button>
                                    </div>
                                )}

                                {viewLedgerMode && (
                                    <div className="mb-4 p-3 bg-purple-500/10 border border-purple-500/20 rounded-lg text-purple-200 text-xs flex items-center">
                                        <AlertTriangle className="w-4 h-4 mr-2" />
                                        You are viewing verified offline logs from the student's encrypted ledger.
                                    </div>
                                )}
                                {logs.length === 0 ? (
                                    <div className="text-center py-20 text-gray-500">
                                        {viewLedgerMode ? "No logs found in the uploaded ledger." : "No activity recorded for this session yet."}
                                    </div>
                                ) : (
                                    logs.slice().reverse().filter(log => !showCriticalOnly || log.is_suspicious).map((log, index) => (
                                        <div
                                            key={index}
                                            className={`p-4 rounded-lg border text-sm font-mono transition-all ${log.is_suspicious
                                                ? 'bg-red-900/10 border-red-500/30 text-red-200'
                                                : 'bg-gray-800 border-gray-700 text-gray-300 hover:border-gray-600'
                                                }`}
                                        >
                                            <div className="flex justify-between items-start mb-2">
                                                <div className="flex items-center space-x-2">
                                                    {log.is_suspicious ? (
                                                        <AlertTriangle className="w-4 h-4 text-red-500" />
                                                    ) : (
                                                        <CheckCircle className="w-4 h-4 text-green-500/50" />
                                                    )}
                                                    <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold tracking-wider ${log.log_type === 'alert' ? 'bg-red-500 text-white' :
                                                        log.log_type === 'process' ? 'bg-blue-500/20 text-blue-400' :
                                                            log.log_type === 'url' ? 'bg-purple-500/20 text-purple-400' :
                                                                'bg-gray-700 text-gray-400'
                                                        }`}>
                                                        {log.log_type}
                                                    </span>
                                                    {log.source === 'ledger' && (
                                                        <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold tracking-wider bg-purple-500/20 text-purple-300 border border-purple-500/30">
                                                            OFFLINE
                                                        </span>
                                                    )}
                                                </div>
                                                <span className="text-gray-500 text-xs">
                                                    {new Date(log.timestamp.endsWith('Z') ? log.timestamp : log.timestamp + 'Z').toLocaleTimeString()}
                                                </span>
                                            </div>
                                            <p className="break-words leading-relaxed pl-6 opacity-90">{log.content}</p>
                                        </div>
                                    ))
                                )}
                            </div>
                        </>
                    )}
                </div>
            </div>
        </div>
    );
};

export default ExamDetails;
