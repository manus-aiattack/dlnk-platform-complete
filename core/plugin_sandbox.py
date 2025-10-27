from core.logger import log


class PluginSandbox:
    def __init__(self):
        # In a real implementation, this would set up a secure environment,
        # possibly using containers (Docker), separate processes, or libraries
        # like 'RestrictedPython' or 'PyPy's sandboxing features.
        log.info(
            "PluginSandbox initialized. (Note: True sandboxing is not yet implemented)")

    def run_in_sandbox(self, plugin_code: str, function_name: str, *args, **kwargs):
        """
        Executes a function from a string of plugin code within a simulated sandbox.

        WARNING: This is a basic simulation. It does NOT provide true security.
        It uses `exec` which is inherently insecure if the code is not trusted.
        """
        try:
            log.info(f"Executing '{function_name}' in simulated sandbox...")

            # Create a restricted global scope for the execution
            restricted_globals = {
                "__builtins__": {
                    'print': print,  # Allow printing for debugging
                    'len': len,
                    'range': range,
                    # Add other safe built-ins here
                },
                "log": log  # Allow logging
            }

            local_scope = {}
            exec(plugin_code, restricted_globals, local_scope)

            # Get the function from the executed code's local scope
            target_function = local_scope.get(function_name)

            if callable(target_function):
                result = target_function(*args, **kwargs)
                log.success(
                    f"'{function_name}' executed successfully in sandbox.")
                return result
            else:
                raise ValueError(
                    f"Function '{function_name}' not found or not callable in plugin code.")

        except Exception as e:
            log.error(
                f"Error executing plugin code in sandbox: {e}", exc_info=True)
            return None
