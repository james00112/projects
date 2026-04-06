import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { LineChart, Line, BarChart, Bar, XAxis, YAxis, Tooltip, Legend, PieChart, Pie, Cell } from 'recharts';

const MongoSecurityDashboard = () => {
  const [auditData, setAuditData] = useState(null);
  const [users, setUsers] = useState([]);
  const [encryptionStats, setEncryptionStats] = useState(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    fetchSecurityAudit();
    fetchUsersStatus();
    fetchEncryptionStats();
  }, []);

  const fetchSecurityAudit = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('adminToken');
      const response = await axios.get('/api/admin/audit/mongodb', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setAuditData(response.data);
    } catch (err) {
      console.error('Audit fetch failed', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchUsersStatus = async () => {
    try {
      const token = localStorage.getItem('adminToken');
      const response = await axios.get('/api/admin/users/security-status', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setUsers(response.data);
    } catch (err) {
      console.error('Users fetch failed', err);
    }
  };

  const fetchEncryptionStats = async () => {
    try {
      const token = localStorage.getItem('adminToken');
      const response = await axios.get('/api/admin/stats/encryption', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setEncryptionStats(response.data);
    } catch (err) {
      console.error('Stats fetch failed', err);
    }
  };

  const forcePasswordReset = async (userId) => {
    if (!window.confirm('Force password reset for this user?')) return;
    try {
      const token = localStorage.getItem('adminToken');
      await axios.post(`/api/admin/users/force-reset/${userId}`, {}, {
        headers: { Authorization: `Bearer ${token}` }
      });
      alert('Password reset forced successfully');
      fetchUsersStatus();
    } catch (err) {
      alert('Failed to force reset');
    }
  };

  const getRiskColor = (risk) => {
    switch(risk) {
      case 'CRITICAL': return 'bg-red-700';
      case 'HIGH': return 'bg-red-500';
      case 'MEDIUM': return 'bg-yellow-500';
      case 'LOW': return 'bg-blue-500';
      default: return 'bg-green-500';
    }
  };

  const vulnerabilityData = auditData ? [
    { name: 'Critical', value: auditData.scans.noSqlInjection.filter(v => v.vulnerable).length },
    { name: 'High', value: auditData.scans.weakPasswords.length },
    { name: 'Medium', value: auditData.scans.unencryptedData.length },
    { name: 'Low', value: auditData.scans.exposedFields.length }
  ] : [];

  const COLORS = ['#DC2626', '#F59E0B', '#FBBF24', '#3B82F6'];

  return (
    <div className="min-h-screen bg-gray-100">
      {/* Header */}
      <div className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 py-6">
          <h1 className="text-3xl font-bold text-gray-900">
            🛡️ MongoDB Security Vulnerability Dashboard
          </h1>
          <p className="text-gray-600 mt-2">
            Real-time security scanning & vulnerability management for encrypted messenger
          </p>
        </div>
      </div>

      {/* Tabs */}
      <div className="max-w-7xl mx-auto px-4 py-6">
        <div className="border-b border-gray-200">
          <nav className="-mb-px flex space-x-8">
            {['overview', 'vulnerabilities', 'users', 'encryption', 'audit-logs'].map(tab => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`py-2 px-1 border-b-2 font-medium text-sm ${
                  activeTab === tab
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                {tab.charAt(0).toUpperCase() + tab.slice(1)}
              </button>
            ))}
          </nav>
        </div>

        {loading && (
          <div className="flex justify-center items-center h-64">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
          </div>
        )}

        {!loading && auditData && activeTab === 'overview' && (
          <div className="mt-6 space-y-6">
            {/* Risk Level Banner */}
            <div className={`${getRiskColor(auditData.riskLevel)} text-white p-6 rounded-lg shadow`}>
              <h2 className="text-2xl font-bold">Overall Risk Level: {auditData.riskLevel}</h2>
              <p className="mt-2">Last scan: {new Date(auditData.timestamp).toLocaleString()}</p>
              <p className="mt-2">Database: {auditData.databaseName}</p>
            </div>

            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
              <div className="bg-white p-6 rounded-lg shadow">
                <div className="text-3xl font-bold text-red-600">
                  {auditData.scans.noSqlInjection.filter(v => v.vulnerable).length}
                </div>
                <div className="text-gray-600">NoSQL Vulnerabilities</div>
              </div>
              <div className="bg-white p-6 rounded-lg shadow">
                <div className="text-3xl font-bold text-yellow-600">
                  {auditData.scans.weakPasswords.length}
                </div>
                <div className="text-gray-600">Weak Password Hashes</div>
              </div>
              <div className="bg-white p-6 rounded-lg shadow">
                <div className="text-3xl font-bold text-blue-600">
                  {encryptionStats?.totalMessages || 0}
                </div>
                <div className="text-gray-600">Total Encrypted Messages</div>
              </div>
              <div className="bg-white p-6 rounded-lg shadow">
                <div className="text-3xl font-bold text-green-600">
                  {users.filter(u => u.mfaEnabled).length}
                </div>
                <div className="text-gray-600">MFA Enabled Users</div>
              </div>
            </div>

            {/* Charts */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="bg-white p-6 rounded-lg shadow">
                <h3 className="text-lg font-bold mb-4">Vulnerability Distribution</h3>
                <PieChart width={400} height={300}>
                  <Pie
                    data={vulnerabilityData}
                    cx={200}
                    cy={150}
                    labelLine={false}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {vulnerabilityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip />
                  <Legend />
                </PieChart>
              </div>
              
              <div className="bg-white p-6 rounded-lg shadow">
                <h3 className="text-lg font-bold mb-4">Security Recommendations</h3>
                <ul className="space-y-2">
                  {auditData.recommendations.map((rec, idx) => (
                    <li key={idx} className="flex items-start">
                      <span className="text-red-500 mr-2">⚠️</span>
                      <span className="text-sm">{rec}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            {/* Remediation Plan */}
            <div className="bg-white p-6 rounded-lg shadow">
              <h3 className="text-lg font-bold mb-4">Remediation Plan</h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <h4 className="font-bold text-red-600">Immediate Actions</h4>
                  <ul className="list-disc list-inside mt-2 space-y-1">
                    {auditData.remediationSteps.immediate.map((step, i) => (
                      <li key={i} className="text-sm">{step}</li>
                    ))}
                  </ul>
                </div>
                <div>
                  <h4 className="font-bold text-yellow-600">Short-term (1-2 weeks)</h4>
                  <ul className="list-disc list-inside mt-2 space-y-1">
                    {auditData.remediationSteps.shortTerm.map((step, i) => (
                      <li key={i} className="text-sm">{step}</li>
                    ))}
                  </ul>
                </div>
                <div>
                  <h4 className="font-bold text-blue-600">Long-term (1-3 months)</h4>
                  <ul className="list-disc list-inside mt-2 space-y-1">
                    {auditData.remediationSteps.longTerm.map((step, i) => (
                      <li key={i} className="text-sm">{step}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'vulnerabilities' && auditData && (
          <div className="mt-6 space-y-6">
            {/* NoSQL Injection */}
            <div className="bg-white p-6 rounded-lg shadow">
              <h3 className="text-xl font-bold mb-4">🔍 NoSQL Injection Vulnerabilities</h3>
              <div className="overflow-x-auto">
                <table className="min-w-full">
                  <thead>
                    <tr className="border-b">
                      <th className="text-left py-2">Payload</th>
                      <th className="text-left py-2">Status</th>
                      <th className="text-left py-2">Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditData.scans.noSqlInjection.map((test, idx) => (
                      <tr key={idx} className="border-b">
                        <td className="py-2 font-mono text-sm">{test.payload}</td>
                        <td className="py-2">
                          {test.vulnerable ? (
                            <span className="text-red-600 font-bold">⚠️ VULNERABLE</span>
                          ) : (
                            <span className="text-green-600">✅ Safe</span>
                          )}
                        </td>
                        <td className="py-2 text-sm">
                          {test.foundDocument ? `Found document: ${test.foundDocument}` : test.error || '-'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Unencrypted Data */}
            <div className="bg-white p-6 rounded-lg shadow">
              <h3 className="text-xl font-bold mb-4">🔓 Unencrypted Sensitive Data</h3>
              {auditData.scans.unencryptedData.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="min-w-full">
                    <thead>
                      <tr className="border-b">
                        <th className="text-left py-2">Collection</th>
                        <th className="text-left py-2">Field</th>
                        <th className="text-left py-2">Sample</th>
                      </tr>
                    </thead>
                    <tbody>
                      {auditData.scans.unencryptedData.map((item, idx) => (
                        <tr key={idx} className="border-b">
                          <td className="py-2">{item.collection}</td>
                          <td className="py-2 font-mono text-sm">{item.field}</td>
                          <td className="py-2 text-sm">{item.sample}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-green-600">No unencrypted sensitive data detected</p>
              )}
            </div>

            {/* Weak Passwords */}
            <div className="bg-white p-6 rounded-lg shadow">
              <h3 className="text-xl font-bold mb-4">🔑 Weak Password Hashes</h3>
              {auditData.scans.weakPasswords.length > 0 ? (
                <div className="space-y-2">
                  {auditData.scans.weakPasswords.map((wp, idx) => (
                    <div key={idx} className="border-l-4 border-red-500 bg-red-50 p-4">
                      <p><strong>User:</strong> {wp.username}</p>
                      <p><strong>Hash Type:</strong> {wp.hashType}</p>
                      <p><strong>Risk Level:</strong> {wp.risk}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-green-600">All users have strong password hashing (bcrypt)</p>
              )}
            </div>
          </div>
        )}

        {activeTab === 'users' && (
          <div className="mt-6">
            <div className="bg-white rounded-lg shadow overflow-hidden">
              <table className="min-w-full">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Username</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Email</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Role</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">MFA</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Security Score</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200">
                  {users.map(user => (
                    <tr key={user._id}>
                      <td className="px-6 py-4">{user.username}</td>
                      <td className="px-6 py-4">{user.email}</td>
                      <td className="px-6 py-4">
                        <span className={`px-2 py-1 rounded text-xs ${
                          user.role === 'admin' ? 'bg-red-100 text-red-800' : 'bg-gray-100'
                        }`}>
                          {user.role}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        {user.mfaEnabled ? '✅ Yes' : '❌ No'}
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center">
                          <div className="w-16 bg-gray-200 rounded-full h-2 mr-2">
                            <div 
                              className={`h-2 rounded-full ${
                                user.securityScore > 70 ? 'bg-green-500' : 
                                user.securityScore > 40 ? 'bg-yellow-500' : 'bg-red-500'
                              }`}
                              style={{ width: `${user.securityScore}%` }}
                            />
                          </div>
                          <span className="text-sm">{user.securityScore}</span>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <button
                          onClick={() => forcePasswordReset(user._id)}
                          className="text-red-600 hover:text-red-800 text-sm"
                        >
                          Force Reset
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeTab === 'encryption' && encryptionStats && (
          <div className="mt-6 space-y-6">
            <div className="bg-white p-6 rounded-lg shadow">
              <h3 className="text-xl font-bold mb-4">🔐 Encryption Statistics</h3>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p><strong>Total Messages:</strong> {encryptionStats.totalMessages.toLocaleString()}</p>
                  <p><strong>Encryption Rate:</strong> {encryptionStats.encryptionRate}</p>
                  <p><strong>Algorithm:</strong> {encryptionStats.encryptionAlgorithm}</p>
                  <p><strong>Key Exchange:</strong> {encryptionStats.keyExchange}</p>
                </div>
                <div>
                  <h4 className="font-bold mb-2">Messages by Type</h4>
                  {encryptionStats.messagesByType.map(type => (
                    <p key={type._id}>{type._id}: {type.count.toLocaleString()}</p>
                  ))}
                </div>
              </div>
            </div>

            <div className="bg-white p-6 rounded-lg shadow">
              <h3 className="text-xl font-bold mb-4">⏱️ Ephemeral Messages (Self-Destruct)</h3>
              {encryptionStats.ephemeralMessages.length > 0 ? (
                <div className="space-y-2">
                  {encryptionStats.ephemeralMessages.map(em => (
                    <p key={em._id}>{em.count} messages with {em._id}s timer</p>
                  ))}
                </div>
              ) : (
                <p>No ephemeral messages configured</p>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default MongoSecurityDashboard;