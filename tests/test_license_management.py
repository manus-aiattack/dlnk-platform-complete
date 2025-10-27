import asyncio
import asynctest
from asynctest.mock import patch, MagicMock, call
import unittest
import uuid
from datetime import datetime, timedelta, timezone

# Make sure the paths are correct for your project structure
from api.license import license_manager

class TestLicenseManager(asynctest.TestCase):
    """Tests for the license management functionality."""

    def setUp(self):
        """Set up for each test case."""
        self.test_user_id = 1
        self.api_key = "test_api_key_123"
        self.key_hash = license_manager.hashlib.sha256(self.api_key.encode()).hexdigest()

    @asynctest.patch('api.license.license_manager.get_db_connection')
    async def test_generate_api_key(self, mock_get_conn):
        """Test API key generation."""
        # Mock the database connection and execute method
        mock_conn = MagicMock()
        mock_get_conn.return_value = asyncio.Future()
        mock_get_conn.return_value.set_result(mock_conn)
        mock_conn.execute.return_value = asyncio.Future()
        mock_conn.execute.return_value.set_result(None)

        # Call the function
        generated_key = await license_manager.generate_api_key(self.test_user_id, expires_in_days=90)

        # Assertions
        self.assertIsInstance(generated_key, str)
        self.assertTrue(len(generated_key) > 30)
        mock_conn.execute.assert_called_once()
        args, _ = mock_conn.execute.call_args
        self.assertIn("INSERT INTO api_keys", args[0])
        self.assertEqual(args[1], self.test_user_id)
        # Check that expires_at is roughly correct
        self.assertAlmostEqual(args[3], datetime.now(timezone.utc) + timedelta(days=90), delta=timedelta(seconds=5))

    @asynctest.patch('api.license.license_manager.get_db_connection')
    async def test_validate_api_key_valid(self, mock_get_conn):
        """Test a valid API key."""
        mock_conn = MagicMock()
        mock_get_conn.return_value = asyncio.Future()
        mock_get_conn.return_value.set_result(mock_conn)
        
        # Mock the fetchrow to return a valid, active key
        mock_conn.fetchrow.return_value = asyncio.Future()
        mock_conn.fetchrow.return_value.set_result({
            'is_active': True,
            'expires_at': datetime.now(timezone.utc) + timedelta(days=1)
        })
        mock_conn.execute.return_value = asyncio.Future()
        mock_conn.execute.return_value.set_result(None)

        is_valid = await license_manager.validate_api_key(self.api_key)

        self.assertTrue(is_valid)
        mock_conn.fetchrow.assert_called_once_with("SELECT is_active, expires_at FROM api_keys WHERE key_hash = $1", self.key_hash)
        # Check that last_used_at was updated
        mock_conn.execute.assert_called_once()
        self.assertIn("UPDATE api_keys SET last_used_at", mock_conn.execute.call_args[0][0])

    @asynctest.patch('api.license.license_manager.get_db_connection')
    async def test_validate_api_key_invalid(self, mock_get_conn):
        """Test an invalid or expired API key."""
        mock_conn = MagicMock()
        mock_get_conn.return_value = asyncio.Future()
        mock_get_conn.return_value.set_result(mock_conn)
        
        # Mock fetchrow to return nothing (key not found)
        mock_conn.fetchrow.return_value = asyncio.Future()
        mock_conn.fetchrow.return_value.set_result(None)

        is_valid = await license_manager.validate_api_key("non_existent_key")
        self.assertFalse(is_valid)

    @asynctest.patch('api.license.license_manager.get_db_connection')
    async def test_revoke_api_key(self, mock_get_conn):
        """Test revoking an API key."""
        mock_conn = MagicMock()
        mock_get_conn.return_value = asyncio.Future()
        mock_get_conn.return_value.set_result(mock_conn)
        mock_conn.execute.return_value = asyncio.Future()
        mock_conn.execute.return_value.set_result(None)

        await license_manager.revoke_api_key(self.api_key)

        mock_conn.execute.assert_called_once_with("UPDATE api_keys SET is_active = FALSE WHERE key_hash = $1", self.key_hash)

if __name__ == '__main__':
    unittest.main()
