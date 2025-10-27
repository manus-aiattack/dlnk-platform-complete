import asyncio
import asynctest
from asynctest.mock import patch, MagicMock
import unittest
import uuid

# Adjust imports based on your project structure
from core import attack_logger
from api.license import license_manager
from core import session_manager

class TestSystemIntegration(asynctest.TestCase):
    """Integration tests for different components of the system."""

    def setUp(self):
        self.user_id = 1
        self.attack_id = uuid.uuid4()
        self.target_id = "integration-test.com"

    @patch('asyncpg.connect')
    @patch('redis.asyncio.Redis.from_url')
    async def test_full_workflow(self, mock_redis_from_url, mock_pg_connect):
        """
        Test a simplified end-to-end workflow:
        1. Create a user session.
        2. Start an attack log.
        3. Save workflow state.
        4. Validate the session.
        5. Terminate the session.
        """
        # --- Mocking Setup ---
        # Mock PostgreSQL connection
        mock_pg_conn = MagicMock()
        mock_pg_connect.return_value = asyncio.Future()
        mock_pg_connect.return_value.set_result(mock_pg_conn)
        mock_pg_conn.execute.return_value = asyncio.Future()
        mock_pg_conn.execute.return_value.set_result(None)
        mock_pg_conn.fetchrow.return_value = asyncio.Future()
        mock_pg_conn.fetchrow.return_value.set_result(None)

        # Mock Redis connection
        mock_redis_conn = MagicMock()
        mock_redis_conn.set.return_value = asyncio.Future()
        mock_redis_conn.set.return_value.set_result("OK")
        mock_redis_conn.get.return_value = asyncio.Future()
        mock_redis_conn.get.return_value.set_result(self.user_id.encode('utf-8')) # Simulate valid session
        mock_redis_conn.delete.return_value = asyncio.Future()
        mock_redis_conn.delete.return_value.set_result(1)
        mock_redis_conn.expire.return_value = asyncio.Future()
        mock_redis_conn.expire.return_value.set_result(1)
        
        # Since RedisManager is a class with classmethods, we need to patch get_connection
        with patch('database.redis_config.RedisManager.get_connection') as mock_get_redis_conn:
            mock_get_redis_conn.return_value = asyncio.Future()
            mock_get_redis_conn.return_value.set_result(mock_redis_conn)

            # --- 1. Create Session ---
            session_id = await session_manager.SessionManager.create_session(self.user_id)
            self.assertIsInstance(session_id, str)
            mock_redis_conn.set.assert_called_once()

            # --- 2. Start Attack Log ---
            # We need to patch the cache_attack_status inside attack_logger
            with patch('core.attack_logger.cache_attack_status') as mock_cache_status:
                mock_cache_status.return_value = asyncio.Future()
                mock_cache_status.return_value.set_result(None)
                await attack_logger.log_attack_start(self.attack_id, self.target_id, self.user_id)
                mock_pg_conn.execute.assert_any_call(
                    "INSERT INTO attack_logs (attack_id, user_id, target_id, phase, status, details) VALUES ($1, $2, $3, $4, $5, $6)",
                    self.attack_id, self.user_id, self.target_id, "start", "STARTED", '{"message": "Attack initiated"}'
                )

            # --- 3. Save Workflow State ---
            state = {"status": "running"}
            await attack_logger.save_workflow_state(self.attack_id, state)
            self.assertIn("INSERT INTO workflow_states", mock_pg_conn.execute.call_args[0][0])

            # --- 4. Validate Session ---
            validated_user = await session_manager.SessionManager.validate_session(session_id)
            self.assertEqual(validated_user, self.user_id)
            mock_redis_conn.get.assert_called_with(f"session:{session_id}")

            # --- 5. Terminate Session ---
            await session_manager.SessionManager.terminate_session(session_id)
            mock_redis_conn.delete.assert_called_with(f"session:{session_id}")

if __name__ == '__main__':
    unittest.main()
