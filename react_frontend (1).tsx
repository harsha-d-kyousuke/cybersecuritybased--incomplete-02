import React, { useState, useEffect } from 'react';
import { Shield, Target, Activity, FileText, Users, Settings, AlertTriangle, CheckCircle, XCircle, Clock, BarChart3, Zap, Globe, Lock, Eye, UserX } from 'lucide-react';

const CyberAttackSimulator = () => {
  const [currentPage, setCurrentPage] = useState('dashboard');
  const [user, setUser] = useState(null);
  const [authMode, setAuthMode] = useState('login');
  const [attacks, setAttacks] = useState([]);
  const [dashboardStats, setDashboardStats] = useState({
    total_attacks: 0,
    total_vulnerabilities: 0,
    average_severity: 0,
    attack_types: []
  });

  // Authentication forms
  const [loginForm, setLoginForm] = useState({ username: '', password: '' });
  const [registerForm, setRegisterForm] = useState({ username: '', email: '', password: '', role: 'user' });

  // Attack form
  const [attackForm, setAttackForm] = useState({
    attack_type: 'sql_injection',
    target_url: 'http://localhost:5000/vulnerable/login',
    parameters: {}
  });

  // API base URL
  const API_BASE = 'http://localhost:8000/api';

  // Authentication functions
  const login = async (credentials) => {
    try {
      const response = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credentials)
      });
      
      if (response.ok) {
        const data = await response.json();
        localStorage.setItem('token', data.access_token);
        localStorage.setItem('user', JSON.stringify({
          id: data.user_id,
          username: data.username,
          role: data.role
        }));
        setUser({ id: data.user_id, username: data.username, role: data.role });
        setCurrentPage('dashboard');
        await loadDashboardData();
      } else {
        alert('Login failed');
      }
    } catch (error) {
      alert('Login error: ' + error.message);
    }
  };

  const register = async (userData) => {
    try {
      const response = await fetch(`${API_BASE}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(userData)
      });
      
      if (response.ok) {
        const data = await response.json();
        localStorage.setItem('token', data.access_token);
        localStorage.setItem('user', JSON.stringify({
          id: data.user_id,
          username: data.username,
          role: 'user'
        }));
        setUser({ id: data.user_id, username: data.username, role: 'user' });
        setCurrentPage('dashboard');
        await loadDashboardData();
      } else {
        alert('Registration failed');
      }
    } catch (error) {
      alert('Registration error: ' + error.message);
    }
  };

  const logout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setUser(null);
    setCurrentPage('dashboard');
  };

  // Load dashboard data
  const loadDashboardData = async () => {
    const token = localStorage.getItem('token');
    if (!token) return;

    try {
      const [statsResponse, historyResponse] = await Promise.all([
        fetch(`${API_BASE}/dashboard/stats`, {
          headers: { 'Authorization': `Bearer ${token}` }
        }),
        fetch(`${API_BASE}/attacks/history`, {
          headers: { 'Authorization': `Bearer ${token}` }
        })
      ]);

      if (statsResponse.ok) {
        const stats = await statsResponse.json();
        setDashboardStats(stats);
      }

      if (historyResponse.ok) {
        const history = await historyResponse.json();
        setAttacks(history);
      }
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
    }
  };

  // Execute attack
  const executeAttack = async () => {
    const token = localStorage.getItem('token');
    if (!token) return;

    try {
      const response = await fetch(`${API_BASE}/attacks/execute`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(attackForm)
      });

      if (response.ok) {
        const result = await response.json();
        setAttacks(prev => [result, ...prev]);
        await loadDashboardData();
        alert(`Attack completed! Found ${result.vulnerabilities_found.length} vulnerabilities.`);
      } else {
        alert('Attack execution failed');
      }
    } catch (error) {
      alert('Attack error: ' + error.message);
    }
  };

  // Load user from localStorage on component mount
  useEffect(() => {
    const storedUser = localStorage.getItem('user');
    if (storedUser) {
      setUser(JSON.parse(storedUser));
      loadDashboardData();
    }
  }, []);

  // Authentication component
  const AuthComponent = () => (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-purple-900 to-violet-900 flex items-center justify-center p-4">
      <div className="bg-white/10 backdrop-blur-lg rounded-2xl p-8 w-full max-w-md border border-white/20">
        <div className="text-center mb-8">
          <Shield className="w-16 h-16 text-cyan-400 mx-auto mb-4" />
          <h1 className="text-3xl font-bold text-white mb-2">CyberAttack Simulator</h1>
          <p className="text-gray-300">Professional Security Testing Platform</p>
        </div>

        <div className="flex mb-6">
          <button
            onClick={() => setAuthMode('login')}
            className={`flex-1 py-2 px-4 rounded-l-lg font-medium transition-colors ${
              authMode === 'login' 
                ? 'bg-cyan-600 text-white' 
                : 'bg-white/10 text-gray-300 hover:bg-white/20'
            }`}
          >
            Login
          </button>
          <button
            onClick={() => setAuthMode('register')}
            className={`flex-1 py-2 px-4 rounded-r-lg font-medium transition-colors ${
              authMode === 'register' 
                ? 'bg-cyan-600 text-white' 
                : 'bg-white/10 text-gray-300 hover:bg-white/20'
            }`}
          >
            Register
          </button>
        </div>

 text-white py-3 rounded-lg font-semibold hover:from-cyan-600 hover:to-purple-700 transition-all transform hover:scale-105"
              >
                Login
              </button>
            </div>
          </form>
        ) : (
          <form onSubmit={(e) => { e.preventDefault(); register(registerForm); }}>
            <div className="space-y-4">
              <input
                type="text"
                placeholder="Username"
                value={registerForm.username}
                onChange={(e) => setRegisterForm({...registerForm, username: e.target.value})}
                className="w-full p-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:border-cyan-400 focus:outline-none"
                required
              />
              <input
                type="email"
                placeholder="Email"
                value={registerForm.email}
                onChange={(e) => setRegisterForm({...registerForm, email: e.target.value})}
                className="w-full p-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:border-cyan-400 focus:outline-none"
                required
              />
              <input
                type="password"
                placeholder="Password"
                value={registerForm.password}
                onChange={(e) => setRegisterForm({...registerForm, password: e.target.value})}
                className="w-full p-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:border-cyan-400 focus:outline-none"
                required
              />
              <button
                type="submit"
                className="w-full bg-gradient-to-r from-purple-500 to-pink-600 text-white py-3 rounded-lg font-semibold hover:from-purple-600 hover:to-pink-700 transition-all transform hover:scale-105"
              >
                Register
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );

  // Navigation component
  const Navigation = () => (
    <div className="bg-gray-900 border-b border-gray-700">
      <div className="max-w-7xl mx-auto px-4">
        <div className="flex justify-between items-center py-4">
          <div className="flex items-center space-x-8">
            <div className="flex items-center space-x-2">
              <Shield className="w-8 h-8 text-cyan-400" />
              <span className="text-xl font-bold text-white">CyberSim</span>
            </div>
            <nav className="flex space-x-6">
              {[
                { id: 'dashboard', label: 'Dashboard', icon: Activity },
                { id: 'attacks', label: 'Attacks', icon: Target },
                { id: 'reports', label: 'Reports', icon: FileText },
                { id: 'settings', label: 'Settings', icon: Settings }
              ].map(item => (
                <button
                  key={item.id}
                  onClick={() => setCurrentPage(item.id)}
                  className={`flex items-center space-x-2 px-3 py-2 rounded-md transition-colors ${
                    currentPage === item.id 
                      ? 'bg-cyan-600 text-white' 
                      : 'text-gray-300 hover:text-white hover:bg-gray-700'
                  }`}
                >
                  <item.icon className="w-4 h-4" />
                  <span>{item.label}</span>
                </button>
              ))}
            </nav>
          </div>
          <div className="flex items-center space-x-4">
            <span className="text-gray-300">Welcome, {user?.username}</span>
            <button
              onClick={logout}
              className="bg-red-600 text-white px-4 py-2 rounded-md hover:bg-red-700 transition-colors"
            >
              Logout
            </button>
          </div>
        </div>
      </div>
    </div>
  );

  // Dashboard component
  const Dashboard = () => (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-gradient-to-r from-blue-600 to-blue-700 rounded-lg p-6 text-white">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-blue-100 text-sm">Total Attacks</p>
              <p className="text-3xl font-bold">{dashboardStats.total_attacks}</p>
            </div>
            <Target className="w-12 h-12 text-blue-200" />
          </div>
        </div>
        <div className="bg-gradient-to-r from-red-600 to-red-700 rounded-lg p-6 text-white">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-red-100 text-sm">Vulnerabilities</p>
              <p className="text-3xl font-bold">{dashboardStats.total_vulnerabilities}</p>
            </div>
            <AlertTriangle className="w-12 h-12 text-red-200" />
          </div>
        </div>
        <div className="bg-gradient-to-r from-yellow-600 to-yellow-700 rounded-lg p-6 text-white">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-yellow-100 text-sm">Avg Severity</p>
              <p className="text-3xl font-bold">{dashboardStats.average_severity}</p>
            </div>
            <BarChart3 className="w-12 h-12 text-yellow-200" />
          </div>
        </div>
        <div className="bg-gradient-to-r from-green-600 to-green-700 rounded-lg p-6 text-white">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-green-100 text-sm">Success Rate</p>
              <p className="text-3xl font-bold">85%</p>
            </div>
            <CheckCircle className="w-12 h-12 text-green-200" />
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white rounded-lg shadow-lg p-6">
          <h3 className="text-lg font-semibold text-gray-800 mb-4">Recent Attacks</h3>
          <div className="space-y-3">
            {attacks.slice(0, 5).map((attack, index) => (
              <div key={index} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                <div className="flex items-center space-x-3">
                  <div className={`w-3 h-3 rounded-full ${
                    attack.vulnerabilities_found?.length > 0 ? 'bg-red-500' : 'bg-green-500'
                  }`} />
                  <div>
                    <p className="font-medium text-gray-800">{attack.attack_type?.replace('_', ' ').toUpperCase()}</p>
                    <p className="text-sm text-gray-600">{new Date(attack.timestamp).toLocaleString()}</p>
                  </div>
                </div>
                <div className="text-right">
                  <p className="text-sm font-medium">{attack.vulnerabilities_found?.length || 0} vulns</p>
                  <p className="text-xs text-gray-500">Score: {attack.severity_score}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-white rounded-lg shadow-lg p-6">
          <h3 className="text-lg font-semibold text-gray-800 mb-4">Attack Types Distribution</h3>
          <div className="space-y-3">
            {dashboardStats.attack_types.map((type, index) => (
              <div key={index} className="flex items-center justify-between">
                <span className="text-gray-700 capitalize">{type.attack_type?.replace('_', ' ')}</span>
                <div className="flex items-center space-x-2">
                  <div className="w-32 bg-gray-200 rounded-full h-2">
                    <div 
                      className="bg-gradient-to-r from-cyan-500 to-purple-600 h-2 rounded-full"
                      style={{ width: `${Math.min((type.count / Math.max(...dashboardStats.attack_types.map(t => t.count))) * 100, 100)}%` }}
                    />
                  </div>
                  <span className="text-sm font-medium text-gray-600">{type.count}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );

  // Attacks component
  const AttacksPage = () => (
    <div className="space-y-6">
      <div className="bg-white rounded-lg shadow-lg p-6">
        <h3 className="text-lg font-semibold text-gray-800 mb-4">Execute New Attack</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <select
            value={attackForm.attack_type}
            onChange={(e) => setAttackForm({...attackForm, attack_type: e.target.value})}
            className="p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
          >
            <option value="sql_injection">SQL Injection</option>
            <option value="xss">Cross-Site Scripting (XSS)</option>
            <option value="csrf">Cross-Site Request Forgery (CSRF)</option>
            <option value="brute_force">Brute Force</option>
            <option value="directory_traversal">Directory Traversal</option>
          </select>
          <input
            type="url"
            placeholder="Target URL"
            value={attackForm.target_url}
            onChange={(e) => setAttackForm({...attackForm, target_url: e.target.value})}
            className="p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
          />
          <button
            onClick={executeAttack}
            className="bg-gradient-to-r from-red-500 to-red-600 text-white px-6 py-3 rounded-lg font-semibold hover:from-red-600 hover:to-red-700 transition-all flex items-center justify-center space-x-2"
          >
            <Zap className="w-5 h-5" />
            <span>Execute Attack</span>
          </button>
        </div>
      </div>

      <div className="bg-white rounded-lg shadow-lg p-6">
        <h3 className="text-lg font-semibold text-gray-800 mb-4">Attack History</h3>
        <div className="overflow-x-auto">
          <table className="w-full table-auto">
            <thead>
              <tr className="border-b">
                <th className="text-left py-3 px-4">Type</th>
                <th className="text-left py-3 px-4">Target</th>
                <th className="text-left py-3 px-4">Vulnerabilities</th>
                <th className="text-left py-3 px-4">Severity</th>
                <th className="text-left py-3 px-4">Date</th>
                <th className="text-left py-3 px-4">Actions</th>
              </tr>
            </thead>
            <tbody>
              {attacks.map((attack, index) => (
                <tr key={index} className="border-b hover:bg-gray-50">
                  <td className="py-3 px-4">
                    <div className="flex items-center space-x-2">
                      {attack.attack_type === 'sql_injection' && <Lock className="w-4 h-4 text-red-500" />}
                      {attack.attack_type === 'xss' && <Eye className="w-4 h-4 text-orange-500" />}
                      {attack.attack_type === 'csrf' && <UserX className="w-4 h-4 text-yellow-500" />}
                      {attack.attack_type === 'brute_force' && <Target className="w-4 h-4 text-purple-500" />}
                      {attack.attack_type === 'directory_traversal' && <Globe className="w-4 h-4 text-blue-500" />}
                      <span className="capitalize">{attack.attack_type?.replace('_', ' ')}</span>
                    </div>
                  </td>
                  <td className="py-3 px-4 text-sm text-gray-600">{attack.target_url}</td>
                  <td className="py-3 px-4">
                    <span className={`px-2 py-1 rounded-full text-xs ${
                      (attack.vulnerabilities_found?.length || 0) > 0 
                        ? 'bg-red-100 text-red-800' 
                        : 'bg-green-100 text-green-800'
                    }`}>
                      {attack.vulnerabilities_found?.length || 0} found
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <span className={`px-2 py-1 rounded-full text-xs ${
                      attack.severity_score >= 7 ? 'bg-red-100 text-red-800' :
                      attack.severity_score >= 4 ? 'bg-yellow-100 text-yellow-800' :
                      'bg-green-100 text-green-800'
                    }`}>
                      {attack.severity_score}/10
                    </span>
                  </td>
                  <td className="py-3 px-4 text-sm text-gray-600">
                    {new Date(attack.timestamp).toLocaleDateString()}
                  </td>
                  <td className="py-3 px-4">
                    <button className="text-cyan-600 hover:text-cyan-700 text-sm font-medium">
                      View Report
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );

  // Main render
  if (!user) {
    return <AuthComponent />;
  }

  return (
    <div className="min-h-screen bg-gray-100">
      <Navigation />
      <main className="max-w-7xl mx-auto px-4 py-8">
        {currentPage === 'dashboard' && <Dashboard />}
        {currentPage === 'attacks' && <AttacksPage />}
        {currentPage === 'reports' && (
          <div className="text-center py-12">
            <FileText className="w-16 h-16 text-gray-400 mx-auto mb-4" />
            <h3 className="text-xl font-semibold text-gray-700">Reports Coming Soon</h3>
            <p className="text-gray-500">Advanced reporting features are in development.</p>
          </div>
        )}
        {currentPage === 'settings' && (
          <div className="text-center py-12">
            <Settings className="w-16 h-16 text-gray-400 mx-auto mb-4" />
            <h3 className="text-xl font-semibold text-gray-700">Settings Coming Soon</h3>
            <p className="text-gray-500">User settings and configuration options are in development.</p>
          </div>
        )}
      </main>
    </div>
  );
};

export default CyberAttackSimulator;