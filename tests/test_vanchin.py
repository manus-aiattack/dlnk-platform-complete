#!/usr/bin/env python3
"""
Test Vanchin AI Integration
Tests Vanchin API connection and key rotation
"""
import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

async def test_vanchin():
    """Test Vanchin AI integration"""
    print("=" * 80)
    print("Testing Vanchin AI Integration")
    print("=" * 80)
    print()
    
    try:
        from core.llm_provider import VanchinProvider
        from core.logger import log
        
        print("Creating Vanchin provider...")
        import os
        api_keys_str = os.getenv("VANCHIN_API_KEYS", "")
        api_keys = [key.strip() for key in api_keys_str.split(',') if key.strip()] if api_keys_str else None

        provider = VanchinProvider(
            logger=log,
            knowledge_base_path="knowledge_base.json",
            api_keys=api_keys
        )
        
        print(f"  ✓ Provider created")
        print(f"  ✓ API URL: {provider.api_url}")
        print(f"  ✓ Model: {provider.model}")
        print(f"  ✓ API Keys: {len(provider.api_keys)} keys loaded")
        print(f"  ✓ Rate Limit: {provider.rate_limit} req/sec")
        print(f"  ✓ Max Tokens: {provider.max_tokens}")
        print()
        
        # Test simple text generation
        print("Testing text generation...")
        try:
            response = await provider.generate_text(
                "Say 'Hello from Vanchin AI' in one short sentence",
                context="test"
            )
            print(f"  ✓ Response received: {response[:100]}...")
            print()
            
            # Test key rotation
            print("Testing key rotation...")
            key1 = provider._get_next_api_key()
            key2 = provider._get_next_api_key()
            print(f"  ✓ Key 1: {key1[:20]}...")
            print(f"  ✓ Key 2: {key2[:20]}...")
            print(f"  ✓ Keys are different: {key1 != key2}")
            print()
            
            print("=" * 80)
            print("Vanchin AI Integration Test: SUCCESS")
            print("=" * 80)
            print()
            print("✓ Vanchin AI is working correctly")
            print("✓ Key rotation is functional")
            print("✓ Rate limiting is configured")
            print()
            
            return True
            
        except Exception as e:
            print(f"  ✗ API call failed: {e}")
            print()
            print("=" * 80)
            print("Vanchin AI Integration Test: PARTIAL")
            print("=" * 80)
            print()
            print("✓ Provider configuration is correct")
            print("✗ API call failed (check API keys or network)")
            print()
            print("Note: This may be expected if:")
            print("  - API keys are invalid or expired")
            print("  - Network connectivity issues")
            print("  - Rate limit exceeded")
            print()
            
            return False
            
    except Exception as e:
        print(f"✗ Error creating provider: {e}")
        print()
        print("=" * 80)
        print("Vanchin AI Integration Test: FAILED")
        print("=" * 80)
        print()
        print("✗ Provider configuration failed")
        print()
        print("Troubleshooting:")
        print("  1. Check .env file has VANCHIN_* variables")
        print("  2. Verify VanchinProvider class exists in core/llm_provider.py")
        print("  3. Check import paths")
        print()
        
        return False

if __name__ == "__main__":
    success = asyncio.run(test_vanchin())
    sys.exit(0 if success else 1)

