# Python Version Compatibility Notice

## Recommended Python Version

**Python 3.11 or 3.12** is recommended for best compatibility.

## Python 3.13 Compatibility

If you're using **Python 3.13** (like Kali Linux 2025), some packages may have build issues. The requirements have been updated to use flexible versions (>=) to allow pip to install compatible versions.

### Known Issues with Python 3.13

1. **asyncpg** - May have C extension build issues
2. **psycopg2-binary** - May have build issues
3. **aiohttp** - May need newer version
4. **pymongo** - May need newer version

### Solutions

#### Option 1: Use Python 3.11 or 3.12 (Recommended)

```bash
# Install Python 3.11
sudo apt install python3.11 python3.11-venv python3.11-dev

# Create venv with Python 3.11
python3.11 -m venv venv
source venv/bin/activate

# Install requirements
pip install -r requirements-full.txt
```

#### Option 2: Use Python 3.13 with updated packages

The requirements.txt has been updated to allow newer versions:

```bash
# Use your existing Python 3.13
python3 -m venv venv
source venv/bin/activate

# Upgrade pip first
pip install --upgrade pip

# Install with latest compatible versions
pip install -r requirements-full.txt
```

If you still encounter build errors, try installing pre-built wheels:

```bash
# Install problematic packages separately with --only-binary
pip install --only-binary :all: asyncpg psycopg2-binary aiohttp pymongo
```

#### Option 3: Skip problematic packages (if not needed)

If you don't need PostgreSQL or MongoDB:

```bash
# Install without database packages
pip install fastapi uvicorn[standard] python-multipart websockets \
    requests httpx ollama openai pydantic python-dotenv pyyaml \
    aiofiles loguru rich click colorama tqdm beautifulsoup4
```

### PostgreSQL Service Issue

If you see "PostgreSQL failed to start":

```bash
# Start PostgreSQL manually
sudo service postgresql start

# Check status
sudo service postgresql status

# If it fails, check logs
sudo tail -f /var/log/postgresql/postgresql-*.log
```

On Kali Linux, PostgreSQL might need initialization:

```bash
# Initialize PostgreSQL cluster
sudo pg_createcluster 17 main --start

# Or restart existing cluster
sudo pg_ctlcluster 17 main start
```

### Verify Installation

After installation, verify everything works:

```bash
# Test Python imports
python3 -c "import fastapi, uvicorn, ollama; print('✅ Core packages OK')"

# Test database (if installed)
python3 -c "import asyncpg, psycopg2; print('✅ Database packages OK')"

# Test Ollama connection
curl http://localhost:11434/api/tags
```

### System Information

Check your Python version:

```bash
python3 --version
```

Check installed packages:

```bash
pip list | grep -E "asyncpg|psycopg2|aiohttp|pymongo"
```

---

## Summary

- **Best compatibility:** Python 3.11 or 3.12
- **Python 3.13:** Use updated requirements with flexible versions
- **Build errors:** Try `--only-binary` flag or skip problematic packages
- **PostgreSQL:** May need manual initialization on Kali Linux

For more help, see:
- [WSL_INSTALLATION_GUIDE.md](WSL_INSTALLATION_GUIDE.md)
- [README.md](README.md)

