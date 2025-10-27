import React, { useState, useEffect } from 'react';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Label } from './ui/label';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Switch } from './ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select';
import { useAuth } from '../hooks/useAuth';

export const SettingsPanel: React.FC = () => {
  const [settings, setSettings] = useState({
    notifications: {
      email: true,
      desktop: false,
      slack: false
    },
    api: {
      timeout: 30,
      retries: 3,
      rateLimit: 100
    },
    ui: {
      theme: 'dark',
      autoRefresh: true,
      compactMode: false
    },
    security: {
      twoFactorAuth: false,
      sessionTimeout: 60,
      passwordExpiry: 90
    }
  });

  const { user } = useAuth();

  useEffect(() => {
    // Load settings from localStorage or API
    const savedSettings = localStorage.getItem('platform-settings');
    if (savedSettings) {
      setSettings(JSON.parse(savedSettings));
    }
  }, []);

  const handleSettingChange = (section: string, key: string, value: any) => {
    const newSettings = {
      ...settings,
      [section]: {
        ...settings[section],
        [key]: value
      }
    };
    setSettings(newSettings);
    localStorage.setItem('platform-settings', JSON.stringify(newSettings));
  };

  const handleSave = async () => {
    try {
      // Save to backend API
      const response = await fetch('/api/v2/settings', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify(settings)
      });

      if (response.ok) {
        alert('Settings saved successfully!');
      } else {
        alert('Failed to save settings');
      }
    } catch (error) {
      console.error('Save settings error:', error);
      alert('Error saving settings');
    }
  };

  const handleReset = () => {
    const defaultSettings = {
      notifications: {
        email: true,
        desktop: false,
        slack: false
      },
      api: {
        timeout: 30,
        retries: 3,
        rateLimit: 100
      },
      ui: {
        theme: 'dark',
        autoRefresh: true,
        compactMode: false
      },
      security: {
        twoFactorAuth: false,
        sessionTimeout: 60,
        passwordExpiry: 90
      }
    };
    setSettings(defaultSettings);
    localStorage.setItem('platform-settings', JSON.stringify(defaultSettings));
  };

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle>Platform Settings</CardTitle>
      </CardHeader>
      <CardContent className="space-y-8">
        {/* Notification Settings */}
        <section>
          <h3 className="text-lg font-medium mb-4">Notifications</h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <Label htmlFor="email-notifications">Email Notifications</Label>
                <p className="text-sm text-gray-600">Receive email updates for attack completions</p>
              </div>
              <Switch
                id="email-notifications"
                checked={settings.notifications.email}
                onCheckedChange={(checked) => handleSettingChange('notifications', 'email', checked)}
              />
            </div>
            <div className="flex items-center justify-between">
              <div>
                <Label htmlFor="desktop-notifications">Desktop Notifications</Label>
                <p className="text-sm text-gray-600">Show desktop notifications for real-time updates</p>
              </div>
              <Switch
                id="desktop-notifications"
                checked={settings.notifications.desktop}
                onCheckedChange={(checked) => handleSettingChange('notifications', 'desktop', checked)}
              />
            </div>
            <div className="flex items-center justify-between">
              <div>
                <Label htmlFor="slack-notifications">Slack Integration</Label>
                <p className="text-sm text-gray-600">Send notifications to Slack workspace</p>
              </div>
              <Switch
                id="slack-notifications"
                checked={settings.notifications.slack}
                onCheckedChange={(checked) => handleSettingChange('notifications', 'slack', checked)}
              />
            </div>
          </div>
        </section>

        {/* API Settings */}
        <section>
          <h3 className="text-lg font-medium mb-4">API Settings</h3>
          <div className="space-y-4">
            <div>
              <Label>Request Timeout (seconds)</Label>
              <Input
                type="number"
                value={settings.api.timeout}
                onChange={(e) => handleSettingChange('api', 'timeout', parseInt(e.target.value))}
                min="10"
                max="120"
              />
            </div>
            <div>
              <Label>Retry Attempts</Label>
              <Input
                type="number"
                value={settings.api.retries}
                onChange={(e) => handleSettingChange('api', 'retries', parseInt(e.target.value))}
                min="1"
                max="10"
              />
            </div>
            <div>
              <Label>Rate Limit (requests/minute)</Label>
              <Input
                type="number"
                value={settings.api.rateLimit}
                onChange={(e) => handleSettingChange('api', 'rateLimit', parseInt(e.target.value))}
                min="10"
                max="1000"
              />
            </div>
          </div>
        </section>

        {/* UI Settings */}
        <section>
          <h3 className="text-lg font-medium mb-4">UI Settings</h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <Label>Theme</Label>
                <p className="text-sm text-gray-600">Choose your preferred interface theme</p>
              </div>
              <Select
                value={settings.ui.theme}
                onValueChange={(value) => handleSettingChange('ui', 'theme', value)}
              >
                <SelectTrigger className="w-32">
                  <SelectValue>{settings.ui.theme}</SelectValue>
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="light">Light</SelectItem>
                  <SelectItem value="dark">Dark</SelectItem>
                  <SelectItem value="auto">Auto</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-center justify-between">
              <div>
                <Label htmlFor="auto-refresh">Auto Refresh</Label>
                <p className="text-sm text-gray-600">Automatically refresh data every 30 seconds</p>
              </div>
              <Switch
                id="auto-refresh"
                checked={settings.ui.autoRefresh}
                onCheckedChange={(checked) => handleSettingChange('ui', 'autoRefresh', checked)}
              />
            </div>
            <div className="flex items-center justify-between">
              <div>
                <Label htmlFor="compact-mode">Compact Mode</Label>
                <p className="text-sm text-gray-600">Use compact layout for better screen utilization</p>
              </div>
              <Switch
                id="compact-mode"
                checked={settings.ui.compactMode}
                onCheckedChange={(checked) => handleSettingChange('ui', 'compactMode', checked)}
              />
            </div>
          </div>
        </section>

        {/* Security Settings */}
        <section>
          <h3 className="text-lg font-medium mb-4">Security</h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <Label htmlFor="2fa">Two-Factor Authentication</Label>
                <p className="text-sm text-gray-600">Add extra security to your account</p>
              </div>
              <Switch
                id="2fa"
                checked={settings.security.twoFactorAuth}
                onCheckedChange={(checked) => handleSettingChange('security', 'twoFactorAuth', checked)}
              />
            </div>
            <div>
              <Label>Session Timeout (minutes)</Label>
              <Input
                type="number"
                value={settings.security.sessionTimeout}
                onChange={(e) => handleSettingChange('security', 'sessionTimeout', parseInt(e.target.value))}
                min="15"
                max="240"
              />
            </div>
            <div>
              <Label>Password Expiry (days)</Label>
              <Input
                type="number"
                value={settings.security.passwordExpiry}
                onChange={(e) => handleSettingChange('security', 'passwordExpiry', parseInt(e.target.value))}
                min="30"
                max="365"
              />
            </div>
          </div>
        </section>

        {/* Action Buttons */}
        <div className="flex space-x-4 pt-4">
          <Button onClick={handleSave} className="flex-1">
            Save Settings
          </Button>
          <Button variant="outline" onClick={handleReset} className="flex-1">
            Reset to Defaults
          </Button>
        </div>
      </CardContent>
    </Card>
  );
};

export default SettingsPanel;