import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import Login from '../Login';
import api from '../../services/api';

vi.mock('../../services/api');

describe('Login Component', () => {
  const mockOnLogin = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders login form', () => {
    render(<Login onLogin={mockOnLogin} />);
    
    expect(screen.getByText('dLNk Attack Platform')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Enter username')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Enter password')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /login/i })).toBeInTheDocument();
  });

  it('handles successful login', async () => {
    const mockResponse = { data: { token: 'test-token' } };
    vi.mocked(api.post).mockResolvedValueOnce(mockResponse);

    render(<Login onLogin={mockOnLogin} />);

    fireEvent.change(screen.getByPlaceholderText('Enter username'), {
      target: { value: 'testuser' },
    });
    fireEvent.change(screen.getByPlaceholderText('Enter password'), {
      target: { value: 'testpass' },
    });

    fireEvent.click(screen.getByRole('button', { name: /login/i }));

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith('/auth/login', {
        username: 'testuser',
        password: 'testpass',
      });
      expect(mockOnLogin).toHaveBeenCalled();
    });
  });

  it('displays error on failed login', async () => {
    vi.mocked(api.post).mockRejectedValueOnce({
      response: { data: { message: 'Invalid credentials' } },
    });

    render(<Login onLogin={mockOnLogin} />);

    fireEvent.change(screen.getByPlaceholderText('Enter username'), {
      target: { value: 'wronguser' },
    });
    fireEvent.change(screen.getByPlaceholderText('Enter password'), {
      target: { value: 'wrongpass' },
    });

    fireEvent.click(screen.getByRole('button', { name: /login/i }));

    await waitFor(() => {
      expect(screen.getByText('Invalid credentials')).toBeInTheDocument();
      expect(mockOnLogin).not.toHaveBeenCalled();
    });
  });

  it('shows loading state during login', async () => {
    vi.mocked(api.post).mockImplementation(
      () => new Promise(resolve => setTimeout(resolve, 100))
    );

    render(<Login onLogin={mockOnLogin} />);

    fireEvent.change(screen.getByPlaceholderText('Enter username'), {
      target: { value: 'testuser' },
    });
    fireEvent.change(screen.getByPlaceholderText('Enter password'), {
      target: { value: 'testpass' },
    });

    fireEvent.click(screen.getByRole('button', { name: /login/i }));

    expect(screen.getByText('Logging in...')).toBeInTheDocument();
  });
});

