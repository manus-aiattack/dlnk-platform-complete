import os
from datetime import datetime, timezone

# In a real application, you would use a proper logging library
# and a notification service (e.g., email, Slack, webhook).

# Get notification settings from environment variables
NOTIFICATION_WEBHOOK = os.getenv("NOTIFICATION_WEBHOOK", "")
NOTIFICATION_EMAIL = os.getenv("NOTIFICATION_EMAIL", "")
NOTIFICATION_ENABLED = os.getenv("NOTIFICATION_ENABLED", "False").lower() in ('true', '1', 't')

def _send_notification(title: str, message: str):
    """Generic function to send notifications. For now, it just prints."""
    if not NOTIFICATION_ENABLED:
        return

    timestamp = datetime.now(timezone.utc).isoformat()
    full_message = f"[{timestamp}] - {title}\n{message}"
    print("--- ADMIN NOTIFICATION ---")
    print(full_message)
    print("--------------------------")

    # In a real implementation, you would add logic here:
    # if NOTIFICATION_WEBHOOK:
    #     # Send to webhook
    #     pass
    # if NOTIFICATION_EMAIL:
    #     # Send email
    #     pass

async def notify_key_expired(user_id: str, key_hash: str):
    """Notifies that an API key has expired."""
    title = "API Key Expired"
    message = f"The API key with hash {key_hash} belonging to user {user_id} has expired."
    _send_notification(title, message)

async def notify_key_revoked(user_id: str, key_hash: str, admin_user: str):
    """Notifies that an API key has been manually revoked."""
    title = "API Key Revoked"
    message = f"The API key with hash {key_hash} for user {user_id} was revoked by {admin_user}."
    _send_notification(title, message)

async def notify_suspicious_activity(user_id: str, key_hash: str, activity_details: str):
    """Notifies about suspicious activity related to an API key."""
    title = "Suspicious Activity Detected"
    message = f"Suspicious activity detected with API key hash {key_hash} (User: {user_id}).\nDetails: {activity_details}"
    _send_notification(title, message)

# Example Usage
async def main():
    print("Testing admin notifications...")
    # Enable notifications for the test
    global NOTIFICATION_ENABLED
    NOTIFICATION_ENABLED = True
    
    await notify_key_expired("user-123", "hash-abc")
    await notify_key_revoked("user-123", "hash-abc", "admin-001")
    await notify_suspicious_activity("user-456", "hash-def", "Multiple failed validation attempts.")

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
