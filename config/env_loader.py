"""
Environment Variable Loader with Validation
Centralized configuration management for dLNk Attack Platform
"""
import os
from typing import Optional
from pathlib import Path

# Load .env file if exists
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent.parent / '.env'
    load_dotenv(dotenv_path=env_path)
except ImportError:
    # dotenv not installed, will use system environment variables
    pass


class ConfigError(Exception):
    """Configuration Error Exception"""
    pass


def get_env(key: str, default: Optional[str] = None, required: bool = False) -> str:
    """
    Get environment variable with validation
    
    Args:
        key: Environment variable name
        default: Default value if not set
        required: If True, raises ConfigError when not set
        
    Returns:
        Environment variable value
        
    Raises:
        ConfigError: If required variable is not set
    """
    value = os.getenv(key, default)
    
    if required and not value:
        raise ConfigError(f"Required environment variable '{key}' is not set")
    
    return value


def get_env_int(key: str, default: int, min_value: Optional[int] = None, max_value: Optional[int] = None) -> int:
    """
    Get integer environment variable with validation
    
    Args:
        key: Environment variable name
        default: Default value if not set
        min_value: Minimum allowed value
        max_value: Maximum allowed value
        
    Returns:
        Integer value
        
    Raises:
        ConfigError: If value is not a valid integer or out of range
    """
    value = os.getenv(key)
    if value is None:
        return default
    
    try:
        int_value = int(value)
    except ValueError:
        raise ConfigError(f"Environment variable '{key}' must be an integer, got: {value}")
    
    if min_value is not None and int_value < min_value:
        raise ConfigError(f"Environment variable '{key}' must be >= {min_value}, got: {int_value}")
    
    if max_value is not None and int_value > max_value:
        raise ConfigError(f"Environment variable '{key}' must be <= {max_value}, got: {int_value}")
    
    return int_value


def get_env_float(key: str, default: float, min_value: Optional[float] = None, max_value: Optional[float] = None) -> float:
    """
    Get float environment variable with validation
    
    Args:
        key: Environment variable name
        default: Default value if not set
        min_value: Minimum allowed value
        max_value: Maximum allowed value
        
    Returns:
        Float value
        
    Raises:
        ConfigError: If value is not a valid float or out of range
    """
    value = os.getenv(key)
    if value is None:
        return default
    
    try:
        float_value = float(value)
    except ValueError:
        raise ConfigError(f"Environment variable '{key}' must be a float, got: {value}")
    
    if min_value is not None and float_value < min_value:
        raise ConfigError(f"Environment variable '{key}' must be >= {min_value}, got: {float_value}")
    
    if max_value is not None and float_value > max_value:
        raise ConfigError(f"Environment variable '{key}' must be <= {max_value}, got: {float_value}")
    
    return float_value


def get_env_bool(key: str, default: bool = False) -> bool:
    """
    Get boolean environment variable
    
    Args:
        key: Environment variable name
        default: Default value if not set
        
    Returns:
        Boolean value
    """
    value = os.getenv(key)
    if value is None:
        return default
    return value.lower() in ('true', '1', 'yes', 'on', 'enabled')


def validate_config():
    """
    Validate critical configuration
    
    Raises:
        ConfigError: If configuration validation fails
    """
    errors = []
    
    # Check database configuration
    database_url = get_env('DATABASE_URL')
    if not database_url:
        # Check if individual DB components are set
        db_host = get_env('DB_HOST')
        db_user = get_env('DB_USER')
        db_name = get_env('DB_NAME')
        if not all([db_host, db_user, db_name]):
            errors.append("DATABASE_URL or DB_HOST/DB_USER/DB_NAME must be set")
    
    # Check LLM configuration
    llm_provider = get_env('LLM_PROVIDER', 'ollama')
    if llm_provider == 'openai':
        openai_key = get_env('OPENAI_API_KEY')
        if not openai_key:
            errors.append("OPENAI_API_KEY is required when using OpenAI provider")
    
    # Check secret key
    secret_key = get_env('SECRET_KEY')
    if not secret_key:
        errors.append("SECRET_KEY must be set")
    elif secret_key == 'dlnk-dlnk-secret-key-change-in-production':
        errors.append("SECRET_KEY must be changed from default value for security")
    elif len(secret_key) < 32:
        errors.append("SECRET_KEY must be at least 32 characters long")
    
    # Check webshell password
    webshell_password = get_env('WEBSHELL_PASSWORD', 'changeme')
    if webshell_password == 'changeme':
        errors.append("WEBSHELL_PASSWORD should be changed from default value")
    
    if errors:
        error_msg = "Configuration validation failed:\n" + "\n".join(f"  - {e}" for e in errors)
        raise ConfigError(error_msg)


def get_database_url() -> str:
    """
    Build and return DATABASE_URL from components or return existing one
    
    Returns:
        Complete database URL
    """
    database_url = get_env('DATABASE_URL')
    if database_url:
        return database_url
    
    # Build from components
    db_host = get_env('DB_HOST', 'localhost')
    db_port = get_env_int('DB_PORT', 5432)
    db_user = get_env('DB_USER', 'dlnk')
    db_password = get_env('DB_PASSWORD', '')
    db_name = get_env('DB_NAME', 'dlnk_db')
    
    if db_password:
        return f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"
    else:
        return f"postgresql://{db_user}@{db_host}:{db_port}/{db_name}"


def get_redis_url() -> str:
    """
    Build and return REDIS_URL from components or return existing one
    
    Returns:
        Complete Redis URL
    """
    redis_url = get_env('REDIS_URL')
    if redis_url:
        return redis_url
    
    # Build from components
    redis_host = get_env('REDIS_HOST', 'localhost')
    redis_port = get_env_int('REDIS_PORT', 6379)
    redis_db = get_env_int('REDIS_DB', 0)
    redis_password = get_env('REDIS_PASSWORD', '')
    
    if redis_password:
        return f"redis://:{redis_password}@{redis_host}:{redis_port}/{redis_db}"
    else:
        return f"redis://{redis_host}:{redis_port}/{redis_db}"


def get_c2_domain() -> str:
    """
    Build and return C2_DOMAIN from components or return existing one
    
    Returns:
        Complete C2 domain with port
    """
    c2_domain = get_env('C2_DOMAIN')
    if c2_domain:
        return c2_domain
    
    # Build from components
    c2_host = get_env('C2_HOST', 'localhost')
    c2_port = get_env_int('C2_PORT', 8000)
    
    return f"{c2_host}:{c2_port}"


if __name__ == "__main__":
    # Test configuration loading
    print("Testing configuration loading...")
    try:
        validate_config()
        print("✅ Configuration is valid")
    except ConfigError as e:
        print(f"❌ Configuration Error:\n{e}")

