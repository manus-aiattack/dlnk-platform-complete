import React, { useState, useEffect } from 'react';
import { useTheme } from '../theme/ThemeProvider';
import { useNavigate } from 'react-router-dom';
import io from 'socket.io-client';

interface Target {
  target_id: string;
  name: string;
  url: string;
  description?: string;
  created_at: string;
}

interface Campaign {
  campaign_id: string;
  name: string;
  status: string;
  current_phase: string;
  progress: number;
  started_at?: string;
  completed_at?: string;
  results?: any;
}

export const NewDashboard: React.FC = () => {
  const { theme } = useTheme();
  const navigate = useNavigate();
  const [apiKey, setApiKey] = useState('');
  const [targets, setTargets] = useState<Target[]>([]);
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [socket, setSocket] = useState<any>(null);
  
  // New target form
  const [newTarget, setNewTarget] = useState({
    name: '',
    url: '',
    description: ''
  });

  useEffect(() => {
    const key = localStorage.getItem('api_key');
    if (!key) {
      navigate('/login');
      return;
    }
    setApiKey(key);

    // Connect to WebSocket
    const ws = io('http://localhost:8000', {
      transports: ['websocket'],
      auth: {
        token: key
      }
    });

    ws.on('connect', () => {
      console.log('WebSocket connected');
    });

    ws.on('campaign_progress', (data: any) => {
      console.log('Campaign progress:', data);
      // Update campaign in state
      setCampaigns(prev => prev.map(c => 
        c.campaign_id === data.campaign_id 
          ? { ...c, current_phase: data.phase, progress: data.progress }
          : c
      ));
    });

    ws.on('campaign_completed', (data: any) => {
      console.log('Campaign completed:', data);
      loadCampaigns(key);
    });

    setSocket(ws);

    // Load initial data
    loadTargets(key);
    loadCampaigns(key);

    return () => {
      ws.disconnect();
    };
  }, [navigate]);

  const loadTargets = async (key: string) => {
    try {
      const response = await fetch('http://localhost:8000/api/targets', {
        headers: { 'X-API-Key': key }
      });
      if (response.ok) {
        const data = await response.json();
        setTargets(data.targets || []);
      }
    } catch (error) {
      console.error('Failed to load targets:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const loadCampaigns = async (key: string) => {
    try {
      const response = await fetch('http://localhost:8000/api/campaigns', {
        headers: { 'X-API-Key': key }
      });
      if (response.ok) {
        const data = await response.json();
        setCampaigns(data.campaigns || []);
      }
    } catch (error) {
      console.error('Failed to load campaigns:', error);
    }
  };

  const handleCreateTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const response = await fetch(`http://localhost:8000/api/targets?name=${encodeURIComponent(newTarget.name)}&url=${encodeURIComponent(newTarget.url)}&description=${encodeURIComponent(newTarget.description)}`, {
        method: 'POST',
        headers: { 'X-API-Key': apiKey }
      });
      if (response.ok) {
        setNewTarget({ name: '', url: '', description: '' });
        loadTargets(apiKey);
      }
    } catch (error) {
      console.error('Failed to create target:', error);
    }
  };

  const handleStartCampaign = async (targetId: string) => {
    try {
      const response = await fetch(`http://localhost:8000/api/campaigns/start?target_id=${targetId}&campaign_name=Auto Campaign`, {
        method: 'POST',
        headers: { 'X-API-Key': apiKey }
      });
      if (response.ok) {
        loadCampaigns(apiKey);
      }
    } catch (error) {
      console.error('Failed to start campaign:', error);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('api_key');
    navigate('/login');
  };

  const getPhaseIcon = (phase: string) => {
    const icons: any = {
      reconnaissance: '🔍',
      vulnerability_discovery: '🔎',
      exploitation: '⚡',
      post_exploitation: '🎯'
    };
    return icons[phase] || '📊';
  };

  const getStatusColor = (status: string) => {
    const colors: any = {
      pending: theme.colors.warning,
      running: theme.colors.info,
      completed: theme.colors.success,
      failed: theme.colors.danger,
      cancelled: theme.colors.textSecondary
    };
    return colors[status] || theme.colors.textSecondary;
  };

  if (isLoading) {
    return (
      <div style={{
        minHeight: '100vh',
        background: theme.colors.background,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center'
      }}>
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontSize: '48px', marginBottom: theme.spacing.md }}>⚡</div>
          <p style={{ color: theme.colors.text }}>Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <div style={{
      minHeight: '100vh',
      background: `linear-gradient(135deg, ${theme.colors.backgroundDark} 0%, #0a0e27 100%)`,
      padding: theme.spacing.lg
    }}>
      {/* Header */}
      <header style={{
        background: theme.colors.background,
        border: `1px solid ${theme.colors.border}`,
        borderRadius: theme.borderRadius.lg,
        padding: theme.spacing.lg,
        marginBottom: theme.spacing.lg,
        boxShadow: theme.shadows.md
      }}>
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <div>
            <h1 style={{
              fontSize: '28px',
              fontWeight: 'bold',
              color: theme.colors.primary,
              margin: 0,
              marginBottom: theme.spacing.xs
            }}>
              🎯 dLNk Attack Platform
            </h1>
            <p style={{
              color: theme.colors.textSecondary,
              margin: 0,
              fontSize: '14px'
            }}>
              AI-Powered Cyber Security Testing Dashboard
            </p>
          </div>
          <button
            onClick={handleLogout}
            style={{
              padding: `${theme.spacing.sm} ${theme.spacing.lg}`,
              background: theme.colors.danger,
              color: '#ffffff',
              border: 'none',
              borderRadius: theme.borderRadius.md,
              fontSize: '14px',
              fontWeight: 'bold',
              cursor: 'pointer',
              transition: 'all 0.2s'
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.transform = 'translateY(-2px)';
              e.currentTarget.style.boxShadow = theme.shadows.md;
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.transform = 'translateY(0)';
              e.currentTarget.style.boxShadow = 'none';
            }}
          >
            🚪 Logout
          </button>
        </div>
      </header>

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(500px, 1fr))',
        gap: theme.spacing.lg
      }}>
        {/* Create Target Section */}
        <div style={{
          background: theme.colors.background,
          border: `1px solid ${theme.colors.border}`,
          borderRadius: theme.borderRadius.lg,
          padding: theme.spacing.lg,
          boxShadow: theme.shadows.md
        }}>
          <h2 style={{
            fontSize: '20px',
            fontWeight: 'bold',
            color: theme.colors.text,
            marginBottom: theme.spacing.md
          }}>
            ➕ สร้าง Target ใหม่
          </h2>
          <form onSubmit={handleCreateTarget}>
            <div style={{ marginBottom: theme.spacing.md }}>
              <label style={{
                display: 'block',
                marginBottom: theme.spacing.xs,
                color: theme.colors.text,
                fontSize: '14px'
              }}>
                ชื่อ Target
              </label>
              <input
                type="text"
                value={newTarget.name}
                onChange={(e) => setNewTarget({ ...newTarget, name: e.target.value })}
                required
                placeholder="เช่น Production Server"
                style={{
                  width: '100%',
                  padding: theme.spacing.sm,
                  background: theme.colors.backgroundDark,
                  border: `1px solid ${theme.colors.border}`,
                  borderRadius: theme.borderRadius.md,
                  color: theme.colors.text,
                  fontSize: '14px'
                }}
              />
            </div>
            <div style={{ marginBottom: theme.spacing.md }}>
              <label style={{
                display: 'block',
                marginBottom: theme.spacing.xs,
                color: theme.colors.text,
                fontSize: '14px'
              }}>
                URL
              </label>
              <input
                type="url"
                value={newTarget.url}
                onChange={(e) => setNewTarget({ ...newTarget, url: e.target.value })}
                required
                placeholder="https://example.com"
                style={{
                  width: '100%',
                  padding: theme.spacing.sm,
                  background: theme.colors.backgroundDark,
                  border: `1px solid ${theme.colors.border}`,
                  borderRadius: theme.borderRadius.md,
                  color: theme.colors.text,
                  fontSize: '14px'
                }}
              />
            </div>
            <div style={{ marginBottom: theme.spacing.md }}>
              <label style={{
                display: 'block',
                marginBottom: theme.spacing.xs,
                color: theme.colors.text,
                fontSize: '14px'
              }}>
                คำอธิบาย (ไม่บังคับ)
              </label>
              <textarea
                value={newTarget.description}
                onChange={(e) => setNewTarget({ ...newTarget, description: e.target.value })}
                placeholder="รายละเอียดเพิ่มเติม..."
                rows={3}
                style={{
                  width: '100%',
                  padding: theme.spacing.sm,
                  background: theme.colors.backgroundDark,
                  border: `1px solid ${theme.colors.border}`,
                  borderRadius: theme.borderRadius.md,
                  color: theme.colors.text,
                  fontSize: '14px',
                  resize: 'vertical'
                }}
              />
            </div>
            <button
              type="submit"
              style={{
                width: '100%',
                padding: theme.spacing.md,
                background: theme.colors.primary,
                color: '#ffffff',
                border: 'none',
                borderRadius: theme.borderRadius.md,
                fontSize: '16px',
                fontWeight: 'bold',
                cursor: 'pointer',
                transition: 'all 0.2s'
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.transform = 'translateY(-2px)';
                e.currentTarget.style.boxShadow = theme.shadows.lg;
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.transform = 'translateY(0)';
                e.currentTarget.style.boxShadow = 'none';
              }}
            >
              ✨ สร้าง Target
            </button>
          </form>
        </div>

        {/* Targets List */}
        <div style={{
          background: theme.colors.background,
          border: `1px solid ${theme.colors.border}`,
          borderRadius: theme.borderRadius.lg,
          padding: theme.spacing.lg,
          boxShadow: theme.shadows.md
        }}>
          <h2 style={{
            fontSize: '20px',
            fontWeight: 'bold',
            color: theme.colors.text,
            marginBottom: theme.spacing.md
          }}>
            🎯 Targets ({targets.length})
          </h2>
          <div style={{
            maxHeight: '400px',
            overflowY: 'auto'
          }}>
            {targets.length === 0 ? (
              <p style={{ color: theme.colors.textSecondary, textAlign: 'center', padding: theme.spacing.lg }}>
                ยังไม่มี Target<br/>สร้าง Target แรกของคุณเลย!
              </p>
            ) : (
              targets.map(target => (
                <div
                  key={target.target_id}
                  style={{
                    background: theme.colors.backgroundDark,
                    border: `1px solid ${theme.colors.border}`,
                    borderRadius: theme.borderRadius.md,
                    padding: theme.spacing.md,
                    marginBottom: theme.spacing.sm
                  }}
                >
                  <div style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'start',
                    marginBottom: theme.spacing.xs
                  }}>
                    <div style={{ flex: 1 }}>
                      <h3 style={{
                        fontSize: '16px',
                        fontWeight: 'bold',
                        color: theme.colors.text,
                        margin: 0,
                        marginBottom: theme.spacing.xs
                      }}>
                        {target.name}
                      </h3>
                      <p style={{
                        fontSize: '13px',
                        color: theme.colors.info,
                        margin: 0,
                        marginBottom: theme.spacing.xs
                      }}>
                        🔗 {target.url}
                      </p>
                      {target.description && (
                        <p style={{
                          fontSize: '12px',
                          color: theme.colors.textSecondary,
                          margin: 0
                        }}>
                          {target.description}
                        </p>
                      )}
                    </div>
                    <button
                      onClick={() => handleStartCampaign(target.target_id)}
                      style={{
                        padding: `${theme.spacing.xs} ${theme.spacing.sm}`,
                        background: theme.colors.success,
                        color: '#ffffff',
                        border: 'none',
                        borderRadius: theme.borderRadius.sm,
                        fontSize: '12px',
                        fontWeight: 'bold',
                        cursor: 'pointer',
                        whiteSpace: 'nowrap'
                      }}
                    >
                      ⚡ Start
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Campaigns Section */}
      <div style={{
        background: theme.colors.background,
        border: `1px solid ${theme.colors.border}`,
        borderRadius: theme.borderRadius.lg,
        padding: theme.spacing.lg,
        marginTop: theme.spacing.lg,
        boxShadow: theme.shadows.md
      }}>
        <h2 style={{
          fontSize: '20px',
          fontWeight: 'bold',
          color: theme.colors.text,
          marginBottom: theme.spacing.md
        }}>
          ⚔️ Attack Campaigns ({campaigns.length})
        </h2>
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))',
          gap: theme.spacing.md
        }}>
          {campaigns.length === 0 ? (
            <p style={{ color: theme.colors.textSecondary, textAlign: 'center', padding: theme.spacing.lg, gridColumn: '1 / -1' }}>
              ยังไม่มี Campaign<br/>เริ่มต้น Campaign แรกโดยกดปุ่ม "Start" ที่ Target
            </p>
          ) : (
            campaigns.map(campaign => (
              <div
                key={campaign.campaign_id}
                style={{
                  background: theme.colors.backgroundDark,
                  border: `1px solid ${theme.colors.border}`,
                  borderRadius: theme.borderRadius.md,
                  padding: theme.spacing.md
                }}
              >
                <div style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  marginBottom: theme.spacing.sm
                }}>
                  <h3 style={{
                    fontSize: '16px',
                    fontWeight: 'bold',
                    color: theme.colors.text,
                    margin: 0
                  }}>
                    {campaign.name}
                  </h3>
                  <span style={{
                    padding: `${theme.spacing.xs} ${theme.spacing.sm}`,
                    background: getStatusColor(campaign.status),
                    color: '#ffffff',
                    borderRadius: theme.borderRadius.sm,
                    fontSize: '11px',
                    fontWeight: 'bold'
                  }}>
                    {campaign.status.toUpperCase()}
                  </span>
                </div>
                <div style={{
                  marginBottom: theme.spacing.sm
                }}>
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: theme.spacing.xs,
                    marginBottom: theme.spacing.xs
                  }}>
                    <span style={{ fontSize: '16px' }}>{getPhaseIcon(campaign.current_phase)}</span>
                    <span style={{
                      fontSize: '13px',
                      color: theme.colors.textSecondary
                    }}>
                      {campaign.current_phase.replace(/_/g, ' ')}
                    </span>
                  </div>
                  <div style={{
                    width: '100%',
                    height: '8px',
                    background: theme.colors.border,
                    borderRadius: theme.borderRadius.sm,
                    overflow: 'hidden'
                  }}>
                    <div style={{
                      width: `${campaign.progress}%`,
                      height: '100%',
                      background: theme.colors.success,
                      transition: 'width 0.3s ease'
                    }} />
                  </div>
                  <p style={{
                    fontSize: '12px',
                    color: theme.colors.textSecondary,
                    margin: `${theme.spacing.xs} 0 0 0`,
                    textAlign: 'right'
                  }}>
                    {campaign.progress.toFixed(1)}%
                  </p>
                </div>
                {campaign.results && (
                  <div style={{
                    padding: theme.spacing.sm,
                    background: 'rgba(34, 197, 94, 0.1)',
                    border: '1px solid rgba(34, 197, 94, 0.3)',
                    borderRadius: theme.borderRadius.sm,
                    fontSize: '12px',
                    color: theme.colors.success
                  }}>
                    ✅ {campaign.results.summary}
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};

export default NewDashboard;

