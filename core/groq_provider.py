import os
import requests
import json
from core.logger import log
from config import settings
import time


class GroqProvider:
    def __init__(self, model=None, timeout=600):
        self.api_keys = settings.GROQ_API_KEY
        if isinstance(self.api_keys, str):
            self.api_keys = [key.strip() for key in self.api_keys.split(',')]

        if not self.api_keys:
            raise ValueError(
                "GROQ_API_KEYS not found in config.py or environment variables.")

        self.model = model or "llama-3.3-70b-versatile"
        self.timeout = timeout
        self.api_url = "https://api.groq.com/openai/v1/chat/completions"

        self.current_key_index = 0
        self.key_status = {}
        self.min_delay_between_requests = 30  # seconds, based on 2 req/min rate limit

        log.info(
            f"Groq LLM Provider initialized with model: {self.model} and {len(self.api_keys)} API keys. Validating keys...")
        self._validate_all_api_keys()

        if not any(info["status"] == "active" for info in self.key_status.values()):
            raise ValueError("No active Groq API keys found after validation.")

    def _validate_all_api_keys(self):
        if settings.GROQ_SKIP_KEY_VALIDATION:
            log.warning(
                "GROQ_SKIP_KEY_VALIDATION is enabled. Marking all keys as active without validation.")
            for key in self.api_keys:
                self.key_status[key] = {"status": "active", "last_used": 0}
            return

        for key in self.api_keys:
            self.key_status[key] = {"status": "inactive", "last_used": 0}
            try:
                headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
                # Use a simpler, smaller model for validation to save tokens and speed
                validation_payload = {
                    "model": "llama-3.1-8b-instant",
                    "messages": [{"role": "user", "content": "Hello"}]
                }
                log.debug(f"[GroqProvider] Validation Payload: {json.dumps(validation_payload, indent=2)}")
                response = requests.post(self.api_url, headers=headers, json=validation_payload, timeout=5)
                response.raise_for_status()
                self.key_status[key]["status"] = "active"
                log.success(f"[GroqProvider] API Key {key[:5]}... validated successfully.")
            except requests.exceptions.HTTPError as e:
                log.warning(f"[GroqProvider] API Key {key[:5]}... failed validation (HTTP {e.response.status_code}. Error: {e}. Response: {e.response.text}")
            except requests.exceptions.RequestException as e:
                log.warning(f"[GroqProvider] API Key {key[:5]}... failed validation (Network Error). Error: {e}")

    def generate_text(self, prompt: str, context: str = "", options: dict = None) -> dict:
        all_keys_exhausted = False
        attempts = 0
        max_attempts = len(self.api_keys) * 2 # Try each key at least twice

        while attempts < max_attempts and not all_keys_exhausted:
            attempts += 1
            current_key = self.api_keys[self.current_key_index]
            key_info = self.key_status[current_key]

            # Check key status and rate limit
            if key_info["status"] == "inactive":
                self._advance_key_index()
                continue
            elif key_info["status"] == "rate_limited" and (time.time() - key_info["last_used"]) < self.min_delay_between_requests:
                log.warning(f"[GroqProvider] Key {current_key[:5]}... is rate-limited. Trying next key.")
                self._advance_key_index()
                continue
            
            headers = {
                "Authorization": f"Bearer {current_key}",
                "Content-Type": "application/json"
            }

            payload = {
                "model": self.model,
                "messages": [{
                        "role": "user",
                        "content": prompt
                }]
            }
            try:
                log.info(f"[GroqProvider] Using API Key {current_key[:5]}... for context: {context}")
                log.debug(f"[GroqProvider] Request Payload: {json.dumps(payload, indent=2)}")
                response = requests.post(self.api_url, headers=headers, json=payload, timeout=self.timeout)
                self.key_status[current_key]["last_used"] = time.time()
                response.raise_for_status()
                
                response_json = response.json()
                content_str = response_json['choices'][0]['message']['content']
                
                # Reset status if successful
                self.key_status[current_key]["status"] = "active"
                self._advance_key_index() # Advance for next request
                try:
                    return json.loads(content_str)
                except json.JSONDecodeError:
                    log.warning(f"[GroqProvider] Response content is not a valid JSON. Returning as plain text.")
                    return {"response": content_str}


            except requests.exceptions.HTTPError as e:
                self.key_status[current_key]["last_used"] = time.time()
                if e.response.status_code == 429:
                    log.warning(f"[GroqProvider] Key {current_key[:5]}... hit rate limit (429). Marking as rate_limited.")
                    self.key_status[current_key]["status"] = "rate_limited"
                else:
                    log.error(f"[GroqProvider] Key {current_key[:5]}... encountered HTTP error {e.response.status_code}. Marking as inactive. Error: {e}")
                    self.key_status[current_key]["status"] = "inactive"
                self._advance_key_index()
            except requests.exceptions.RequestException as e:
                self.key_status[current_key]["last_used"] = time.time()
                log.error(f"[GroqProvider] Key {current_key[:5]}... encountered network error. Marking as inactive. Error: {e}")
                self.key_status[current_key]["status"] = "inactive"
                self._advance_key_index()
            except (json.JSONDecodeError, KeyError) as e:
                log.error(f"[GroqProvider] Key {current_key[:5]}... failed to parse JSON response. Error: {e}")
                log.error(f"[GroqProvider] Raw response content: {response.text if 'response' in locals() else 'N/A'}")
                self._advance_key_index()
            
            # Check if all keys are now exhausted or rate-limited
            all_keys_exhausted = all(k["status"] == "inactive" or (k["status"] == "rate_limited" and (time.time() - k["last_used"]) < self.min_delay_between_requests) for k in self.key_status.values())
        
        if all_keys_exhausted:
            log.error("[GroqProvider] All Groq API keys are exhausted. Attempting to use fallback provider.")
            # Placeholder for fallback to another LLM provider like OpenAI
            # try:
            #     fallback_provider = OpenAIProvider()
            #     return fallback_provider.generate_text(prompt, context, options)
            # except Exception as fallback_e:
            #     log.critical(f"Fallback provider also failed: {fallback_e}")
            return {"error": "all_llm_providers_failed", "message": "All Groq API keys are exhausted and fallback provider failed."}

        log.error("[GroqProvider] Exceeded max attempts to find an active key. Cannot fulfill request.")
        return {"error": "all_groq_keys_exhausted", "message": "All Groq API keys are exhausted or rate-limited."}

    def _advance_key_index(self):
        self.current_key_index = (self.current_key_index + 1) % len(self.api_keys)
