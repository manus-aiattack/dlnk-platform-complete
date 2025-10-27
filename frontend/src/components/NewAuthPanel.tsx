import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTheme } from '../theme/ThemeProvider';

export const NewAuthPanel: React.FC = () => {
  const [apiKey, setApiKey] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const { theme } = useTheme();
  const navigate = useNavigate();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    try {
      // Validate API key with backend
      const response = await fetch('http://localhost:8000/health', {
        headers: {
          'X-API-Key': apiKey
        }
      });

      if (response.ok) {
        // Save API key to localStorage
        localStorage.setItem('api_key', apiKey);
        navigate('/');
      } else {
        setError('Invalid API Key. Please check and try again.');
      }
    } catch (err) {
      setError('Connection error. Please make sure the backend server is running.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleLineContact = () => {
    // Open LINE chat or redirect to LINE contact
    window.open('https://line.me/ti/p/YOUR_LINE_ID', '_blank');
  };

  return (
    <div style={{
      minHeight: '100vh',
      background: `linear-gradient(135deg, ${theme.colors.backgroundDark} 0%, #0a0e27 100%)`,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: theme.spacing.lg
    }}>
      <div style={{
        width: '100%',
        maxWidth: '480px'
      }}>
        {/* Logo and Title */}
        <div style={{
          textAlign: 'center',
          marginBottom: theme.spacing.xl
        }}>
          <div style={{
            fontSize: '64px',
            marginBottom: theme.spacing.md
          }}>
            🎯
          </div>
          <h1 style={{
            fontSize: '32px',
            fontWeight: 'bold',
            color: theme.colors.primary,
            marginBottom: theme.spacing.sm
          }}>
            dLNk Attack Platform
          </h1>
          <p style={{
            color: theme.colors.textSecondary,
            fontSize: '16px'
          }}>
            AI-Powered Cyber Security Testing
          </p>
        </div>

        {/* Login Card */}
        <div style={{
          background: theme.colors.background,
          border: `1px solid ${theme.colors.border}`,
          borderRadius: theme.borderRadius.lg,
          padding: theme.spacing.xl,
          boxShadow: theme.shadows.lg
        }}>
          <h2 style={{
            fontSize: '24px',
            fontWeight: 'bold',
            color: theme.colors.text,
            marginBottom: theme.spacing.sm
          }}>
            เข้าสู่ระบบ
          </h2>
          <p style={{
            color: theme.colors.textSecondary,
            marginBottom: theme.spacing.lg,
            fontSize: '14px'
          }}>
            กรุณากรอก API Key เพื่อเข้าใช้งานระบบ
          </p>

          <form onSubmit={handleLogin}>
            <div style={{ marginBottom: theme.spacing.lg }}>
              <label style={{
                display: 'block',
                marginBottom: theme.spacing.sm,
                color: theme.colors.text,
                fontSize: '14px',
                fontWeight: '500'
              }}>
                API Key
              </label>
              <input
                type="text"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder="กรอก API Key ของคุณ"
                required
                style={{
                  width: '100%',
                  padding: theme.spacing.md,
                  background: theme.colors.backgroundDark,
                  border: `1px solid ${theme.colors.border}`,
                  borderRadius: theme.borderRadius.md,
                  color: theme.colors.text,
                  fontSize: '14px',
                  outline: 'none',
                  transition: 'border-color 0.2s'
                }}
                onFocus={(e) => e.target.style.borderColor = theme.colors.primary}
                onBlur={(e) => e.target.style.borderColor = theme.colors.border}
              />
            </div>

            {error && (
              <div style={{
                background: 'rgba(239, 68, 68, 0.1)',
                border: '1px solid rgba(239, 68, 68, 0.3)',
                borderRadius: theme.borderRadius.md,
                padding: theme.spacing.md,
                marginBottom: theme.spacing.lg,
                color: '#ef4444',
                fontSize: '14px'
              }}>
                ⚠️ {error}
              </div>
            )}

            <button
              type="submit"
              disabled={isLoading || !apiKey}
              style={{
                width: '100%',
                padding: theme.spacing.md,
                background: theme.colors.primary,
                color: '#ffffff',
                border: 'none',
                borderRadius: theme.borderRadius.md,
                fontSize: '16px',
                fontWeight: 'bold',
                cursor: isLoading || !apiKey ? 'not-allowed' : 'pointer',
                opacity: isLoading || !apiKey ? 0.6 : 1,
                transition: 'all 0.2s'
              }}
              onMouseEnter={(e) => {
                if (!isLoading && apiKey) {
                  e.currentTarget.style.transform = 'translateY(-2px)';
                  e.currentTarget.style.boxShadow = theme.shadows.lg;
                }
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.transform = 'translateY(0)';
                e.currentTarget.style.boxShadow = 'none';
              }}
            >
              {isLoading ? '🔄 กำลังตรวจสอบ...' : '🚀 เข้าสู่ระบบ'}
            </button>
          </form>

          {/* Divider */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            margin: `${theme.spacing.lg} 0`,
            gap: theme.spacing.md
          }}>
            <div style={{
              flex: 1,
              height: '1px',
              background: theme.colors.border
            }} />
            <span style={{
              color: theme.colors.textSecondary,
              fontSize: '14px'
            }}>
              หรือ
            </span>
            <div style={{
              flex: 1,
              height: '1px',
              background: theme.colors.border
            }} />
          </div>

          {/* LINE Contact Button */}
          <button
            type="button"
            onClick={handleLineContact}
            style={{
              width: '100%',
              padding: theme.spacing.md,
              background: '#06C755',
              color: '#ffffff',
              border: 'none',
              borderRadius: theme.borderRadius.md,
              fontSize: '16px',
              fontWeight: 'bold',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: theme.spacing.sm,
              transition: 'all 0.2s'
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.transform = 'translateY(-2px)';
              e.currentTarget.style.boxShadow = '0 10px 30px rgba(6, 199, 85, 0.4)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.transform = 'translateY(0)';
              e.currentTarget.style.boxShadow = 'none';
            }}
          >
            <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
              <path d="M19.365 9.863c.349 0 .63.285.63.631 0 .345-.281.63-.63.63H17.61v1.125h1.755c.349 0 .63.283.63.63 0 .344-.281.629-.63.629h-2.386c-.345 0-.627-.285-.627-.629V8.108c0-.345.282-.63.63-.63h2.386c.346 0 .627.285.627.63 0 .349-.281.63-.63.63H17.61v1.125h1.755zm-3.855 3.016c0 .27-.174.51-.432.596-.064.021-.133.031-.199.031-.211 0-.391-.09-.51-.25l-2.443-3.317v2.94c0 .344-.279.629-.631.629-.346 0-.626-.285-.626-.629V8.108c0-.27.173-.51.43-.595.06-.023.136-.033.194-.033.195 0 .375.104.495.254l2.462 3.33V8.108c0-.345.282-.63.63-.63.345 0 .63.285.63.63v4.771zm-5.741 0c0 .344-.282.629-.631.629-.345 0-.627-.285-.627-.629V8.108c0-.345.282-.63.63-.63.346 0 .628.285.628.63v4.771zm-2.466.629H4.917c-.345 0-.63-.285-.63-.629V8.108c0-.345.285-.63.63-.63.348 0 .63.285.63.63v4.141h1.756c.348 0 .629.283.629.63 0 .344-.282.629-.629.629M24 10.314C24 4.943 18.615.572 12 .572S0 4.943 0 10.314c0 4.811 4.27 8.842 10.035 9.608.391.082.923.258 1.058.59.12.301.079.766.038 1.08l-.164 1.02c-.045.301-.24 1.186 1.049.645 1.291-.539 6.916-4.078 9.436-6.975C23.176 14.393 24 12.458 24 10.314"/>
            </svg>
            💬 ติดต่อซื้อ API Key ผ่าน LINE
          </button>

          {/* Info Box */}
          <div style={{
            marginTop: theme.spacing.lg,
            padding: theme.spacing.md,
            background: 'rgba(59, 130, 246, 0.1)',
            border: '1px solid rgba(59, 130, 246, 0.3)',
            borderRadius: theme.borderRadius.md
          }}>
            <p style={{
              color: theme.colors.info,
              fontSize: '13px',
              margin: 0,
              lineHeight: '1.6'
            }}>
              💡 <strong>ยังไม่มี API Key?</strong><br/>
              กดปุ่มด้านบนเพื่อติดต่อทีมงานผ่าน LINE และขอรับ API Key สำหรับการใช้งาน
            </p>
          </div>
        </div>

        {/* Footer */}
        <div style={{
          textAlign: 'center',
          marginTop: theme.spacing.lg,
          color: theme.colors.textSecondary,
          fontSize: '14px'
        }}>
          <p style={{ margin: 0 }}>
            🔒 Secured by dLNk Security Platform
          </p>
          <p style={{ margin: `${theme.spacing.sm} 0 0 0`, fontSize: '12px' }}>
            © 2025 dLNk. All rights reserved.
          </p>
        </div>
      </div>
    </div>
  );
};

export default NewAuthPanel;

