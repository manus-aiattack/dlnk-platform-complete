import asyncio
import asynctest
from asynctest.mock import patch, MagicMock
import unittest
import uuid
import json

# Adjust the import path based on your project structure
from core import attack_logger

class TestAttackLogger(asynctest.TestCase):
    """Tests for the attack logging functionality."""

    def setUp(self):
        self.attack_id = uuid.uuid4()
        self.target_id = "test-target.com"
        self.phase = "reconnaissance"
        self.details = {"ports": [80, 443]}

    @asynctest.patch('core.attack_logger.get_db_connection')
    @asynctest.patch('core.attack_logger.cache_attack_status')
    async def test_log_attack_phase(self, mock_cache_status, mock_get_conn):
        """Test logging a generic attack phase."""
        mock_conn = MagicMock()
        mock_get_conn.return_value = asyncio.Future()
        mock_get_conn.return_value.set_result(mock_conn)
        mock_conn.execute.return_value = asyncio.Future()
        mock_conn.execute.return_value.set_result(None)
        mock_cache_status.return_value = asyncio.Future()
        mock_cache_status.return_value.set_result(None)

        await attack_logger.log_attack_phase(self.attack_id, self.target_id, self.phase, "COMPLETED", self.details, user_id=1)

        # Check if DB execute was called correctly
        mock_conn.execute.assert_called_once()
        args, _ = mock_conn.execute.call_args
        self.assertIn("INSERT INTO attack_logs", args[0])
        self.assertEqual(args[1], self.attack_id)
        self.assertEqual(args[2], 1) # user_id
        self.assertEqual(args[3], self.target_id)
        self.assertEqual(args[4], self.phase)
        self.assertEqual(args[5], "COMPLETED")
        self.assertEqual(args[6], json.dumps(self.details))

        # Check if caching was called correctly
        mock_cache_status.assert_called_once()
        cached_args, _ = mock_cache_status.call_args
        self.assertEqual(cached_args[0], self.attack_id)
        self.assertEqual(cached_args[1]['phase'], self.phase)
        self.assertEqual(cached_args[1]['status'], "COMPLETED")

    @asynctest.patch('core.attack_logger.get_db_connection')
    async def test_get_attack_history(self, mock_get_conn):
        """Test retrieving attack history."""
        mock_conn = MagicMock()
        mock_get_conn.return_value = asyncio.Future()
        mock_get_conn.return_value.set_result(mock_conn)
        
        # Mock the fetch to return some log records
        mock_records = [
            {'timestamp': '2023-10-27T10:00:00Z', 'phase': 'start', 'status': 'STARTED', 'details': '{}'},
            {'timestamp': '2023-10-27T10:05:00Z', 'phase': 'recon', 'status': 'COMPLETED', 'details': '{"ports": [80]}'}
        ]
        mock_conn.fetch.return_value = asyncio.Future()
        mock_conn.fetch.return_value.set_result(mock_records)

        history = await attack_logger.get_attack_history(self.attack_id)

        self.assertEqual(len(history), 2)
        self.assertEqual(history[0]['phase'], 'start')
        mock_conn.fetch.assert_called_once_with(
            "SELECT timestamp, phase, status, details FROM attack_logs WHERE attack_id = $1 ORDER BY timestamp ASC",
            self.attack_id
        )

    @asynctest.patch('core.attack_logger.get_db_connection')
    async def test_save_workflow_state_insert(self, mock_get_conn):
        """Test saving a new workflow state."""
        mock_conn = MagicMock()
        mock_get_conn.return_value = asyncio.Future()
        mock_get_conn.return_value.set_result(mock_conn)
        mock_conn.execute.return_value = asyncio.Future()
        mock_conn.execute.return_value.set_result(None)

        state_data = {"current_step": "scanning"}
        await attack_logger.save_workflow_state(self.attack_id, state_data)

        mock_conn.execute.assert_called_once()
        args, _ = mock_conn.execute.call_args
        self.assertIn("INSERT INTO workflow_states", args[0])
        self.assertIn("ON CONFLICT (attack_id) DO UPDATE", args[0])
        self.assertEqual(args[1], self.attack_id)
        self.assertEqual(args[2], json.dumps(state_data))

if __name__ == '__main__':
    unittest.main()
