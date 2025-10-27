import ollama

def test_ollama_connection():
    """Test Ollama connection and model availability"""
    try:
        # List available models
        models = ollama.list()
        print("Available models:")
        for model in models['models']:
            print(f"  - {model['name']} ({model['size']} bytes)")

        # Test model generation
        response = ollama.generate(
            model='llama3:8b-instruct-fp16',
            prompt='Hello, this is a test. Respond with "Test successful".',
            stream=False
        )

        print(f"Test response: {response['response']}")
        return True
    except Exception as e:
        print(f"Ollama connection failed: {e}")
        return False

if __name__ == "__main__":
    test_ollama_connection()