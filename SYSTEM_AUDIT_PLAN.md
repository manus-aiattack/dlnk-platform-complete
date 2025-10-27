# 🔍 แผนการตรวจสอบระบบทั้งโปรเจค Manus AI Attack Platform

**โปรเจค:** Manus AI Attack Platform  
**วันที่สร้าง:** 26 ตุลาคม 2568  
**เวอร์ชัน:** 1.0.0  
**ผู้จัดทำ:** Manus AI  
**Repository:** https://github.com/manus-aiattack/aiprojectattack

---

## 📊 ภาพรวมโปรเจค

### สถิติโค้ดปัจจุบัน

| ประเภท | จำนวน | สถานะ |
|--------|--------|-------|
| **Python Files** | 472 ไฟล์ | ✅ |
| **Config Files** | 35 ไฟล์ | ✅ |
| **Test Files** | 16 ไฟล์ | ⚠️ ต้องเพิ่ม |
| **Documentation** | 36 ไฟล์ | ✅ |

### ปัญหาที่พบเบื้องต้น

| ปัญหา | จำนวน | ระดับความสำคัญ |
|-------|--------|----------------|
| **TODO/FIXME Comments** | 19 | 🟡 Medium |
| **Debug print() Statements** | 1,389 | 🔴 High |
| **Empty pass Placeholders** | 80 | 🟡 Medium |
| **Missing Tests** | ~456 | 🔴 High |

---

## 🎯 วัตถุประสงค์การตรวจสอบ

### เป้าหมายหลัก
1. ✅ **ความถูกต้อง (Correctness)** - ตรวจสอบว่าโค้ดทำงานถูกต้องตามที่ออกแบบ
2. ✅ **ความสมบูรณ์ (Completeness)** - ตรวจสอบว่าครบทุกส่วนที่จำเป็น
3. ✅ **คุณภาพโค้ด (Code Quality)** - ตรวจสอบมาตรฐานการเขียนโค้ด
4. ✅ **ประสิทธิภาพ (Performance)** - ตรวจสอบความเร็วและการใช้ทรัพยากร
5. ✅ **ความปลอดภัย (Security)** - ตรวจสอบช่องโหว่ด้านความปลอดภัย
6. ✅ **การทดสอบ (Testing)** - ตรวจสอบ test coverage
7. ✅ **เอกสาร (Documentation)** - ตรวจสอบความครบถ้วนของเอกสาร

---

## 📋 Phase 1: Code Quality Audit (สัปดาห์ 1)

### 1.1 Static Code Analysis

#### เป้าหมาย
ตรวจสอบคุณภาพโค้ดด้วย static analysis tools

#### เครื่องมือที่ใช้
- **pylint** - Python code quality checker
- **flake8** - Style guide enforcement
- **mypy** - Static type checker
- **bandit** - Security issue scanner
- **black** - Code formatter
- **isort** - Import sorter

#### ขั้นตอนการดำเนินการ

##### 1.1.1 ติดตั้ง Tools
```bash
pip install pylint flake8 mypy bandit black isort
```

##### 1.1.2 รัน Pylint
```bash
# Run pylint on all Python files
pylint --rcfile=.pylintrc \
       --output-format=json \
       --reports=y \
       $(find . -name "*.py" -not -path "./venv/*") \
       > reports/pylint_report.json

# Generate summary
pylint --rcfile=.pylintrc \
       --reports=y \
       $(find . -name "*.py" -not -path "./venv/*") \
       > reports/pylint_summary.txt
```

**เป้าหมาย:**
- Score: > 8.0/10
- Critical issues: 0
- Errors: < 10
- Warnings: < 50

##### 1.1.3 รัน Flake8
```bash
# Run flake8 with configuration
flake8 --config=.flake8 \
       --output-file=reports/flake8_report.txt \
       --statistics \
       .

# Generate detailed report
flake8 --config=.flake8 \
       --format=html \
       --htmldir=reports/flake8_html \
       .
```

**เป้าหมาย:**
- Total violations: < 100
- E501 (line too long): < 20
- F401 (unused imports): 0
- F841 (unused variables): 0

##### 1.1.4 รัน MyPy
```bash
# Run mypy for type checking
mypy --config-file=mypy.ini \
     --html-report=reports/mypy_html \
     --txt-report=reports/mypy_txt \
     .
```

**เป้าหมาย:**
- Type coverage: > 80%
- Type errors: 0
- Missing type hints: < 50

##### 1.1.5 รัน Bandit
```bash
# Run bandit for security issues
bandit -r . \
       -f json \
       -o reports/bandit_report.json \
       -ll

# Generate HTML report
bandit -r . \
       -f html \
       -o reports/bandit_report.html \
       -ll
```

**เป้าหมาย:**
- High severity issues: 0
- Medium severity issues: < 5
- Low severity issues: < 20

##### 1.1.6 Format Code
```bash
# Format all Python files with black
black --config=pyproject.toml .

# Sort imports with isort
isort --settings-path=pyproject.toml .
```

#### การแก้ไข

**สร้างไฟล์ Configuration:**

**.pylintrc**
```ini
[MASTER]
ignore=venv,node_modules,.git
jobs=4

[MESSAGES CONTROL]
disable=
    C0111,  # missing-docstring
    C0103,  # invalid-name
    R0903,  # too-few-public-methods
    R0913,  # too-many-arguments
    W0212,  # protected-access

[FORMAT]
max-line-length=120
indent-string='    '

[DESIGN]
max-args=10
max-locals=20
max-returns=6
max-branches=15
```

**.flake8**
```ini
[flake8]
max-line-length = 120
exclude = 
    .git,
    __pycache__,
    venv,
    node_modules,
    .pytest_cache
ignore = 
    E203,  # whitespace before ':'
    E501,  # line too long (handled by black)
    W503,  # line break before binary operator
per-file-ignores =
    __init__.py:F401
```

**mypy.ini**
```ini
[mypy]
python_version = 3.11
warn_return_any = True
warn_unused_configs = True
disallow_untyped_defs = False
ignore_missing_imports = True

[mypy-tests.*]
ignore_errors = True
```

**pyproject.toml**
```toml
[tool.black]
line-length = 120
target-version = ['py311']
include = '\.pyi?$'
exclude = '''
/(
    \.git
  | \.venv
  | node_modules
  | __pycache__
)/
'''

[tool.isort]
profile = "black"
line_length = 120
multi_line_output = 3
include_trailing_comma = true
force_grid_wrap = 0
use_parentheses = true
ensure_newline_before_comments = true
```

#### ผลลัพธ์ที่คาดหวัง
- ✅ โค้ดผ่าน pylint score > 8.0
- ✅ โค้ดผ่าน flake8 < 100 violations
- ✅ โค้ดมี type hints > 80%
- ✅ ไม่มี security issues ระดับ high
- ✅ โค้ดถูก format ด้วย black
- ✅ Imports ถูกเรียงด้วย isort

---

### 1.2 Remove Debug Code

#### เป้าหมาย
ลบ debug code และ print statements ออกจากโค้ด

#### ปัญหาที่พบ
- **1,389 print() statements** - ต้องแทนที่ด้วย logging

#### ขั้นตอนการแก้ไข

##### 1.2.1 สร้าง Logging Configuration
```python
# core/logging_config.py
import logging
import sys
from pathlib import Path

def setup_logging(
    level: str = "INFO",
    log_file: str = None,
    format_string: str = None
):
    """Setup logging configuration"""
    
    if format_string is None:
        format_string = (
            "[%(asctime)s] %(levelname)-8s "
            "[%(name)s:%(funcName)s:%(lineno)d] "
            "%(message)s"
        )
    
    # Create formatter
    formatter = logging.Formatter(format_string)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    
    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))
    root_logger.addHandler(console_handler)
    
    # File handler (optional)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    
    return root_logger

# Create default logger
log = logging.getLogger(__name__)
```

##### 1.2.2 แทนที่ print() ด้วย logging
```bash
# สร้าง script สำหรับแทนที่ print() อัตโนมัติ
cat > scripts/replace_print_with_logging.py << 'EOF'
#!/usr/bin/env python3
"""Replace print() statements with logging"""

import re
import sys
from pathlib import Path

def replace_print_in_file(file_path: Path):
    """Replace print() with logging in a file"""
    
    content = file_path.read_text()
    original_content = content
    
    # Add logging import if not exists
    if "import logging" not in content and "from logging import" not in content:
        # Find first import
        import_match = re.search(r'^import |^from ', content, re.MULTILINE)
        if import_match:
            insert_pos = import_match.start()
            content = (
                content[:insert_pos] + 
                "import logging\n\n" + 
                content[insert_pos:]
            )
        else:
            # Add at top
            content = "import logging\n\n" + content
    
    # Add logger if not exists
    if "log = logging.getLogger" not in content:
        # Find first class or function definition
        def_match = re.search(r'^(class |def |async def )', content, re.MULTILINE)
        if def_match:
            insert_pos = def_match.start()
            content = (
                content[:insert_pos] + 
                "log = logging.getLogger(__name__)\n\n" + 
                content[insert_pos:]
            )
    
    # Replace print() statements
    patterns = [
        # print("message")
        (r'print\("([^"]+)"\)', r'log.info("\1")'),
        # print('message')
        (r"print\('([^']+)'\)", r"log.info('\1')"),
        # print(f"message {var}")
        (r'print\(f"([^"]+)"\)', r'log.info(f"\1")'),
        # print(variable)
        (r'print\(([a-zA-Z_][a-zA-Z0-9_]*)\)', r'log.info(f"{{\1}}")'),
        # print("Error:", error)
        (r'print\("Error:', r'log.error("'),
        (r'print\("Warning:', r'log.warning("'),
        (r'print\("DEBUG:', r'log.debug("'),
    ]
    
    for pattern, replacement in patterns:
        content = re.sub(pattern, replacement, content)
    
    # Write back if changed
    if content != original_content:
        file_path.write_text(content)
        return True
    
    return False

def main():
    """Main function"""
    project_root = Path(".")
    
    changed_files = []
    
    for py_file in project_root.rglob("*.py"):
        if "venv" in str(py_file) or "node_modules" in str(py_file):
            continue
        
        if replace_print_in_file(py_file):
            changed_files.append(py_file)
            print(f"Updated: {py_file}")
    
    print(f"\nTotal files updated: {len(changed_files)}")

if __name__ == "__main__":
    main()
EOF

chmod +x scripts/replace_print_with_logging.py
python scripts/replace_print_with_logging.py
```

##### 1.2.3 ตรวจสอบและแก้ไขด้วยมือ
```bash
# หา print() ที่เหลือ
grep -rn "print(" --include="*.py" . | grep -v "# print(" | grep -v "\"print(" > reports/remaining_prints.txt

# Review และแก้ไขด้วยมือ
```

#### ผลลัพธ์ที่คาดหวัง
- ✅ print() statements: 0
- ✅ ใช้ logging แทน print() ทั้งหมด
- ✅ มี log levels ที่เหมาะสม (DEBUG, INFO, WARNING, ERROR)

---

### 1.3 Complete TODO/FIXME Items

#### เป้าหมาย
แก้ไขหรือลบ TODO/FIXME comments ทั้งหมด

#### ปัญหาที่พบ
- **19 TODO/FIXME comments**

#### ขั้นตอนการดำเนินการ

##### 1.3.1 สร้างรายการ TODO/FIXME
```bash
# สร้างรายการทั้งหมด
grep -rn "TODO\|FIXME" --include="*.py" . > reports/todo_fixme_list.txt

# แยกตาม priority
grep -rn "TODO.*CRITICAL\|FIXME.*CRITICAL" --include="*.py" . > reports/critical_todos.txt
grep -rn "TODO.*HIGH\|FIXME.*HIGH" --include="*.py" . > reports/high_todos.txt
grep -rn "TODO.*MEDIUM\|FIXME.*MEDIUM" --include="*.py" . > reports/medium_todos.txt
```

##### 1.3.2 จัดลำดับความสำคัญ
```python
# scripts/analyze_todos.py
#!/usr/bin/env python3
"""Analyze and prioritize TODOs"""

import re
from pathlib import Path
from collections import defaultdict

def analyze_todos():
    """Analyze TODO/FIXME comments"""
    
    todos = defaultdict(list)
    
    for py_file in Path(".").rglob("*.py"):
        if "venv" in str(py_file):
            continue
        
        content = py_file.read_text()
        
        for line_num, line in enumerate(content.split("\n"), 1):
            if "TODO" in line or "FIXME" in line:
                # Extract priority
                priority = "MEDIUM"
                if "CRITICAL" in line:
                    priority = "CRITICAL"
                elif "HIGH" in line:
                    priority = "HIGH"
                elif "LOW" in line:
                    priority = "LOW"
                
                todos[priority].append({
                    "file": str(py_file),
                    "line": line_num,
                    "content": line.strip()
                })
    
    # Print summary
    print("TODO/FIXME Summary:")
    print("=" * 80)
    
    for priority in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        items = todos[priority]
        if items:
            print(f"\n{priority}: {len(items)} items")
            for item in items:
                print(f"  {item['file']}:{item['line']}")
                print(f"    {item['content']}")

if __name__ == "__main__":
    analyze_todos()
```

##### 1.3.3 แก้ไข TODO/FIXME
```markdown
**แนวทางการแก้ไข:**

1. **CRITICAL TODOs** - แก้ไขทันที (สัปดาห์ที่ 1)
2. **HIGH TODOs** - แก้ไขภายใน 2 สัปดาห์
3. **MEDIUM TODOs** - แก้ไขภายใน 1 เดือน
4. **LOW TODOs** - เพิ่มใน backlog

**ตัวอย่างการแก้ไข:**

```python
# Before
def process_data(data):
    # TODO: Add validation
    return data

# After
def process_data(data):
    """Process data with validation"""
    if not data:
        raise ValueError("Data cannot be empty")
    
    if not isinstance(data, dict):
        raise TypeError("Data must be a dictionary")
    
    # Validate required fields
    required_fields = ["id", "name", "type"]
    for field in required_fields:
        if field not in data:
            raise ValueError(f"Missing required field: {field}")
    
    return data
```

#### ผลลัพธ์ที่คาดหวัง
- ✅ CRITICAL TODOs: 0
- ✅ HIGH TODOs: 0
- ✅ MEDIUM TODOs: < 5
- ✅ ทุก TODO มี issue tracking

---

### 1.4 Remove Empty Placeholders

#### เป้าหมาย
ลบหรือ implement empty pass statements

#### ปัญหาที่พบ
- **80 empty pass placeholders**

#### ขั้นตอนการดำเนินการ

##### 1.4.1 หา Empty Pass Statements
```bash
# หา pass statements ทั้งหมด
grep -rn "^\s*pass\s*$" --include="*.py" . > reports/pass_statements.txt

# แยกตามประเภท
# 1. Abstract methods (ควรมี pass)
# 2. Empty implementations (ต้อง implement)
# 3. Placeholder methods (ต้อง implement หรือลบ)
```

##### 1.4.2 วิเคราะห์และจัดประเภท
```python
# scripts/analyze_pass_statements.py
#!/usr/bin/env python3
"""Analyze pass statements"""

import re
from pathlib import Path

def analyze_pass_statements():
    """Analyze pass statements in code"""
    
    results = {
        "abstract_methods": [],
        "empty_implementations": [],
        "placeholders": []
    }
    
    for py_file in Path(".").rglob("*.py"):
        if "venv" in str(py_file):
            continue
        
        content = py_file.read_text()
        lines = content.split("\n")
        
        for i, line in enumerate(lines):
            if re.match(r"^\s*pass\s*$", line):
                # Check context
                context_start = max(0, i - 5)
                context = "\n".join(lines[context_start:i+1])
                
                # Classify
                if "@abstractmethod" in context or "ABC" in context:
                    results["abstract_methods"].append({
                        "file": str(py_file),
                        "line": i + 1,
                        "context": context
                    })
                elif "def __init__" in context:
                    results["empty_implementations"].append({
                        "file": str(py_file),
                        "line": i + 1,
                        "context": context
                    })
                else:
                    results["placeholders"].append({
                        "file": str(py_file),
                        "line": i + 1,
                        "context": context
                    })
    
    # Print summary
    print("Pass Statement Analysis:")
    print("=" * 80)
    print(f"Abstract methods: {len(results['abstract_methods'])} (OK)")
    print(f"Empty implementations: {len(results['empty_implementations'])} (NEED FIX)")
    print(f"Placeholders: {len(results['placeholders'])} (NEED FIX)")
    
    return results

if __name__ == "__main__":
    analyze_pass_statements()
```

##### 1.4.3 แก้ไข Empty Implementations
```python
# ตัวอย่างการแก้ไข

# Before - Empty __init__
class MyAgent:
    def __init__(self):
        pass

# After - Proper initialization
class MyAgent:
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize agent with configuration"""
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.results = []

# Before - Empty method
def process_results(self, results):
    pass

# After - Proper implementation
def process_results(self, results: List[Dict]) -> Dict[str, Any]:
    """Process and aggregate results"""
    if not results:
        return {"success": False, "error": "No results to process"}
    
    aggregated = {
        "total": len(results),
        "successful": sum(1 for r in results if r.get("success")),
        "failed": sum(1 for r in results if not r.get("success")),
        "data": results
    }
    
    return aggregated
```

#### ผลลัพธ์ที่คาดหวัง
- ✅ Empty implementations: 0
- ✅ Placeholders: 0
- ✅ Abstract methods: มี pass (ถูกต้อง)

---

## 📋 Phase 2: Architecture & Design Audit (สัปดาห์ 2)

### 2.1 Code Structure Review

#### เป้าหมาย
ตรวจสอบโครงสร้างโค้ดและ architecture

#### ขั้นตอนการดำเนินการ

##### 2.1.1 ตรวจสอบ Module Organization
```bash
# สร้าง dependency graph
pydeps --max-bacon=2 \
       --cluster \
       -o reports/dependency_graph.svg \
       .

# ตรวจสอบ circular dependencies
pydeps --show-cycles \
       -o reports/circular_deps.txt \
       .
```

##### 2.1.2 ตรวจสอบ Import Structure
```python
# scripts/analyze_imports.py
#!/usr/bin/env python3
"""Analyze import structure"""

import ast
from pathlib import Path
from collections import defaultdict

def analyze_imports():
    """Analyze import patterns"""
    
    imports = defaultdict(list)
    
    for py_file in Path(".").rglob("*.py"):
        if "venv" in str(py_file):
            continue
        
        try:
            tree = ast.parse(py_file.read_text())
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports[str(py_file)].append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    for alias in node.names:
                        imports[str(py_file)].append(f"{module}.{alias.name}")
        except:
            pass
    
    # Analyze patterns
    print("Import Analysis:")
    print("=" * 80)
    
    # Find most imported modules
    all_imports = []
    for file_imports in imports.values():
        all_imports.extend(file_imports)
    
    from collections import Counter
    common_imports = Counter(all_imports).most_common(20)
    
    print("\nMost Common Imports:")
    for module, count in common_imports:
        print(f"  {module}: {count}")

if __name__ == "__main__":
    analyze_imports()
```

##### 2.1.3 ตรวจสอบ Design Patterns
```markdown
**Design Patterns ที่ควรใช้:**

1. **Factory Pattern** - สำหรับสร้าง agents
2. **Strategy Pattern** - สำหรับ attack strategies
3. **Observer Pattern** - สำหรับ event notifications
4. **Singleton Pattern** - สำหรับ orchestrator
5. **Command Pattern** - สำหรับ CLI commands
```

#### การแก้ไข

**ตัวอย่าง: Factory Pattern สำหรับ Agent Creation**
```python
# core/agent_factory.py
from typing import Type, Dict, Any
from core.base_agent import BaseAgent

class AgentFactory:
    """Factory for creating agents"""
    
    _registry: Dict[str, Type[BaseAgent]] = {}
    
    @classmethod
    def register(cls, name: str, agent_class: Type[BaseAgent]):
        """Register an agent class"""
        cls._registry[name] = agent_class
    
    @classmethod
    def create(cls, name: str, **kwargs) -> BaseAgent:
        """Create an agent instance"""
        if name not in cls._registry:
            raise ValueError(f"Unknown agent: {name}")
        
        agent_class = cls._registry[name]
        return agent_class(**kwargs)
    
    @classmethod
    def list_agents(cls) -> List[str]:
        """List all registered agents"""
        return list(cls._registry.keys())

# Auto-register decorator
def register_agent(name: str):
    """Decorator to auto-register agents"""
    def decorator(cls):
        AgentFactory.register(name, cls)
        return cls
    return decorator

# Usage
@register_agent("nmap")
class NmapAgent(BaseAgent):
    pass

# Create agent
agent = AgentFactory.create("nmap", config={})
```

#### ผลลัพธ์ที่คาดหวัง
- ✅ ไม่มี circular dependencies
- ✅ Module organization ชัดเจน
- ✅ ใช้ design patterns ที่เหมาะสม
- ✅ Dependency graph สะอาด

---

### 2.2 API Design Review

#### เป้าหมาย
ตรวจสอบ API design และ consistency

#### ขั้นตอนการดำเนินการ

##### 2.2.1 ตรวจสอบ API Endpoints
```bash
# Extract all API endpoints
grep -rn "@app\.\(get\|post\|put\|delete\|patch\)" --include="*.py" api/ > reports/api_endpoints.txt

# Check for consistency
python scripts/analyze_api_endpoints.py
```

##### 2.2.2 ตรวจสอบ Request/Response Models
```python
# scripts/analyze_api_models.py
#!/usr/bin/env python3
"""Analyze API request/response models"""

import ast
from pathlib import Path

def analyze_api_models():
    """Analyze Pydantic models used in API"""
    
    models = []
    
    for py_file in Path("api").rglob("*.py"):
        tree = ast.parse(py_file.read_text())
        
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                # Check if inherits from BaseModel
                for base in node.bases:
                    if isinstance(base, ast.Name) and base.id == "BaseModel":
                        models.append({
                            "file": str(py_file),
                            "name": node.name,
                            "fields": [f.target.id for f in node.body 
                                     if isinstance(f, ast.AnnAssign)]
                        })
    
    print("API Models Analysis:")
    print("=" * 80)
    print(f"Total models: {len(models)}")
    
    for model in models:
        print(f"\n{model['name']} ({model['file']})")
        print(f"  Fields: {', '.join(model['fields'])}")

if __name__ == "__main__":
    analyze_api_models()
```

##### 2.2.3 ตรวจสอบ API Documentation
```bash
# Generate OpenAPI schema
python -c "
from api.main import app
import json

schema = app.openapi()
print(json.dumps(schema, indent=2))
" > reports/openapi_schema.json

# Validate schema
npx @apidevtools/swagger-cli validate reports/openapi_schema.json
```

#### การแก้ไข

**API Design Best Practices:**

```python
# api/models/request.py
from pydantic import BaseModel, Field, validator
from typing import Optional, List
from enum import Enum

class AttackType(str, Enum):
    """Attack type enumeration"""
    WEB = "web"
    NETWORK = "network"
    MOBILE = "mobile"
    CLOUD = "cloud"

class AttackRequest(BaseModel):
    """Request model for starting an attack"""
    
    target: str = Field(..., description="Target URL or IP address")
    attack_type: AttackType = Field(..., description="Type of attack")
    agents: Optional[List[str]] = Field(None, description="Specific agents to use")
    timeout: int = Field(3600, ge=60, le=86400, description="Timeout in seconds")
    
    @validator("target")
    def validate_target(cls, v):
        """Validate target format"""
        if not v:
            raise ValueError("Target cannot be empty")
        # Add more validation
        return v
    
    class Config:
        schema_extra = {
            "example": {
                "target": "https://example.com",
                "attack_type": "web",
                "agents": ["nmap", "nuclei"],
                "timeout": 3600
            }
        }

# api/models/response.py
class AttackResponse(BaseModel):
    """Response model for attack results"""
    
    attack_id: int = Field(..., description="Unique attack ID")
    status: str = Field(..., description="Attack status")
    progress: float = Field(..., ge=0, le=100, description="Progress percentage")
    results: Optional[Dict[str, Any]] = Field(None, description="Attack results")
    
    class Config:
        schema_extra = {
            "example": {
                "attack_id": 123,
                "status": "running",
                "progress": 45.5,
                "results": None
            }
        }
```

#### ผลลัพธ์ที่คาดหวัง
- ✅ API endpoints consistent
- ✅ Request/Response models ครบถ้วน
- ✅ OpenAPI schema valid
- ✅ API documentation complete

---

### 2.3 Database Schema Review

#### เป้าหมาย
ตรวจสอบ database schema และ migrations

#### ขั้นตอนการดำเนินการ

##### 2.3.1 ตรวจสอบ Schema
```bash
# Export current schema
pg_dump -h localhost -U manus -d manus_ai_attack --schema-only > reports/current_schema.sql

# Analyze schema
python scripts/analyze_db_schema.py
```

##### 2.3.2 ตรวจสอบ Indexes
```sql
-- Check missing indexes
SELECT 
    schemaname,
    tablename,
    attname,
    n_distinct,
    correlation
FROM pg_stats
WHERE schemaname = 'public'
  AND n_distinct > 100
  AND correlation < 0.1
ORDER BY n_distinct DESC;

-- Check unused indexes
SELECT 
    schemaname,
    tablename,
    indexname,
    idx_scan,
    idx_tup_read,
    idx_tup_fetch
FROM pg_stat_user_indexes
WHERE idx_scan = 0
ORDER BY pg_relation_size(indexrelid) DESC;
```

##### 2.3.3 ตรวจสอบ Migrations
```bash
# List all migrations
alembic history

# Check current version
alembic current

# Validate migrations
alembic check
```

#### การแก้ไข

**สร้าง Missing Indexes:**
```sql
-- Add indexes for frequently queried columns
CREATE INDEX idx_attacks_status ON attacks(status);
CREATE INDEX idx_attacks_created_at ON attacks(created_at);
CREATE INDEX idx_agents_name ON agents(name);
CREATE INDEX idx_results_attack_id ON results(attack_id);

-- Add composite indexes
CREATE INDEX idx_attacks_status_created ON attacks(status, created_at);
CREATE INDEX idx_results_attack_agent ON results(attack_id, agent_id);
```

**ปรับปรุง Schema:**
```sql
-- Add constraints
ALTER TABLE attacks 
ADD CONSTRAINT chk_attacks_status 
CHECK (status IN ('pending', 'running', 'completed', 'failed'));

-- Add foreign keys
ALTER TABLE results
ADD CONSTRAINT fk_results_attack
FOREIGN KEY (attack_id) REFERENCES attacks(id) ON DELETE CASCADE;

-- Add timestamps
ALTER TABLE agents
ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
```

#### ผลลัพธ์ที่คาดหวัง
- ✅ Schema normalized
- ✅ Indexes optimized
- ✅ Constraints complete
- ✅ Migrations valid

---

## 📋 Phase 3: Testing Audit (สัปดาห์ 3)

### 3.1 Test Coverage Analysis

#### เป้าหมาย
วัดและปรับปรุง test coverage

#### ปัญหาที่พบ
- **16 test files** สำหรับ **472 Python files**
- Test coverage: ~3.4% (ต่ำมาก)

#### ขั้นตอนการดำเนินการ

##### 3.1.1 วัด Current Coverage
```bash
# Install coverage tools
pip install pytest pytest-cov pytest-asyncio

# Run tests with coverage
pytest --cov=. \
       --cov-report=html:reports/coverage_html \
       --cov-report=term \
       --cov-report=json:reports/coverage.json \
       tests/

# Generate coverage badge
coverage-badge -o reports/coverage.svg
```

##### 3.1.2 วิเคราะห์ Coverage Gaps
```python
# scripts/analyze_coverage.py
#!/usr/bin/env python3
"""Analyze test coverage gaps"""

import json
from pathlib import Path

def analyze_coverage():
    """Analyze coverage report"""
    
    with open("reports/coverage.json") as f:
        coverage_data = json.load(f)
    
    files = coverage_data["files"]
    
    # Find files with low coverage
    low_coverage = []
    for file_path, data in files.items():
        coverage_pct = data["summary"]["percent_covered"]
        if coverage_pct < 80:
            low_coverage.append({
                "file": file_path,
                "coverage": coverage_pct,
                "missing_lines": data["summary"]["missing_lines"]
            })
    
    # Sort by coverage
    low_coverage.sort(key=lambda x: x["coverage"])
    
    print("Files with Low Coverage (<80%):")
    print("=" * 80)
    
    for item in low_coverage[:20]:  # Top 20
        print(f"{item['file']}: {item['coverage']:.1f}% "
              f"({item['missing_lines']} lines missing)")

if __name__ == "__main__":
    analyze_coverage()
```

##### 3.1.3 สร้าง Test Plan
```markdown
**Test Coverage Goals:**

| Component | Current | Target | Priority |
|-----------|---------|--------|----------|
| Core Systems | 10% | 90% | 🔴 Critical |
| Agents | 5% | 80% | 🔴 Critical |
| API | 20% | 95% | 🔴 Critical |
| CLI | 0% | 70% | 🟡 High |
| Frontend | 0% | 60% | 🟡 High |
| Utils | 30% | 85% | 🟢 Medium |
```

#### การแก้ไข

##### 3.1.4 สร้าง Test Templates
```python
# tests/conftest.py
"""Pytest configuration and fixtures"""

import pytest
import asyncio
from typing import Generator

@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create event loop for async tests"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
def mock_orchestrator():
    """Mock orchestrator for testing"""
    from unittest.mock import MagicMock
    from core.orchestrator import Orchestrator
    
    orchestrator = MagicMock(spec=Orchestrator)
    return orchestrator

@pytest.fixture
def mock_context_manager():
    """Mock context manager for testing"""
    from unittest.mock import MagicMock
    from core.context_manager import ContextManager
    
    context_manager = MagicMock(spec=ContextManager)
    return context_manager

@pytest.fixture
def sample_target():
    """Sample target for testing"""
    return {
        "url": "https://example.com",
        "ip": "192.0.2.1",
        "ports": [80, 443]
    }
```

**Test Template สำหรับ Agents:**
```python
# tests/agents/test_agent_template.py
"""Template for agent tests"""

import pytest
from agents.your_agent import YourAgent
from core.data_models import AgentData, AttackPhase

class TestYourAgent:
    """Test suite for YourAgent"""
    
    @pytest.fixture
    def agent(self, mock_orchestrator, mock_context_manager):
        """Create agent instance"""
        return YourAgent(
            orchestrator=mock_orchestrator,
            context_manager=mock_context_manager
        )
    
    @pytest.mark.asyncio
    async def test_initialization(self, agent):
        """Test agent initialization"""
        assert agent is not None
        assert hasattr(agent, 'supported_phases')
        assert hasattr(agent, 'required_tools')
    
    @pytest.mark.asyncio
    async def test_run_success(self, agent, sample_target):
        """Test successful agent execution"""
        context = {"target": sample_target}
        result = await agent.run("scan", context)
        
        assert isinstance(result, AgentData)
        assert result.agent_name == "YourAgent"
        assert result.success is True
        assert "data" in result.__dict__
    
    @pytest.mark.asyncio
    async def test_run_missing_params(self, agent):
        """Test agent with missing parameters"""
        context = {}
        result = await agent.run("scan", context)
        
        assert isinstance(result, AgentData)
        assert result.success is False
        assert "error" in result.data
    
    @pytest.mark.asyncio
    async def test_run_invalid_directive(self, agent, sample_target):
        """Test agent with invalid directive"""
        context = {"target": sample_target}
        result = await agent.run("invalid_directive", context)
        
        assert isinstance(result, AgentData)
        assert result.success is False
    
    @pytest.mark.asyncio
    async def test_supported_phases(self, agent):
        """Test agent supported phases"""
        assert len(agent.supported_phases) > 0
        assert all(isinstance(p, AttackPhase) for p in agent.supported_phases)
```

##### 3.1.5 สร้าง Tests สำหรับ Core Components
```python
# tests/core/test_orchestrator.py
"""Tests for Orchestrator"""

import pytest
from core.orchestrator import Orchestrator
from core.data_models import AttackPhase

class TestOrchestrator:
    """Test suite for Orchestrator"""
    
    @pytest.fixture
    def orchestrator(self):
        """Create orchestrator instance"""
        return Orchestrator()
    
    @pytest.mark.asyncio
    async def test_initialization(self, orchestrator):
        """Test orchestrator initialization"""
        assert orchestrator is not None
        assert hasattr(orchestrator, 'agents')
        assert hasattr(orchestrator, 'context_manager')
    
    @pytest.mark.asyncio
    async def test_execute_phase(self, orchestrator, sample_target):
        """Test phase execution"""
        results = await orchestrator.execute_phase(
            phase=AttackPhase.RECONNAISSANCE,
            target=sample_target
        )
        
        assert isinstance(results, list)
        assert len(results) > 0
    
    @pytest.mark.asyncio
    async def test_select_agents(self, orchestrator):
        """Test agent selection"""
        agents = orchestrator.select_agents_for_phase(
            AttackPhase.RECONNAISSANCE
        )
        
        assert isinstance(agents, list)
        assert len(agents) > 0
```

#### ผลลัพธ์ที่คาดหวัง
- ✅ Test coverage > 85%
- ✅ ทุก critical components มี tests
- ✅ ทุก agents มี tests
- ✅ API endpoints มี tests

---

### 3.2 Integration Testing

#### เป้าหมาย
สร้าง integration tests สำหรับ workflows

#### ขั้นตอนการดำเนินการ

##### 3.2.1 สร้าง Integration Test Suite
```python
# tests/integration/test_attack_workflow.py
"""Integration tests for attack workflows"""

import pytest
from core.orchestrator import Orchestrator
from core.data_models import AttackPhase

@pytest.mark.integration
class TestAttackWorkflow:
    """Test complete attack workflows"""
    
    @pytest.fixture
    async def orchestrator(self):
        """Create and setup orchestrator"""
        orch = Orchestrator()
        await orch.initialize()
        yield orch
        await orch.cleanup()
    
    @pytest.mark.asyncio
    async def test_full_web_attack(self, orchestrator, sample_target):
        """Test complete web application attack"""
        
        # Phase 1: Reconnaissance
        recon_results = await orchestrator.execute_phase(
            phase=AttackPhase.RECONNAISSANCE,
            target=sample_target
        )
        assert len(recon_results) > 0
        assert any(r.success for r in recon_results)
        
        # Phase 2: Vulnerability Discovery
        vuln_results = await orchestrator.execute_phase(
            phase=AttackPhase.VULNERABILITY_DISCOVERY,
            target=sample_target,
            previous_results=recon_results
        )
        assert len(vuln_results) > 0
        
        # Phase 3: Exploitation (if vulnerabilities found)
        if any(r.success for r in vuln_results):
            exploit_results = await orchestrator.execute_phase(
                phase=AttackPhase.EXPLOITATION,
                target=sample_target,
                previous_results=vuln_results
            )
            assert len(exploit_results) > 0
    
    @pytest.mark.asyncio
    async def test_agent_coordination(self, orchestrator, sample_target):
        """Test agent coordination and data sharing"""
        
        # Execute multiple agents
        results = await orchestrator.execute_agents(
            agents=["NmapAgent", "NucleiAgent"],
            target=sample_target
        )
        
        # Verify results shared via context
        context = orchestrator.context_manager.get_context(
            sample_target["url"]
        )
        
        assert "nmap_results" in context
        assert "nuclei_results" in context
```

##### 3.2.2 สร้าง End-to-End Tests
```python
# tests/e2e/test_api_workflow.py
"""End-to-end API

 tests"""

import pytest
from httpx import AsyncClient

@pytest.mark.e2e
class TestAPIWorkflow:
    """End-to-end API workflow tests"""
    
    @pytest.fixture
    async def client(self):
        """Create API client"""
        async with AsyncClient(base_url="http://localhost:8000") as client:
            yield client
    
    @pytest.mark.asyncio
    async def test_complete_attack_via_api(self, client):
        """Test complete attack workflow via API"""
        
        # 1. Create attack
        response = await client.post(
            "/api/v1/attacks",
            json={
                "target": "https://example.com",
                "attack_type": "web"
            },
            headers={"Authorization": "Bearer test_token"}
        )
        assert response.status_code == 201
        attack_id = response.json()["attack_id"]
        
        # 2. Check status
        response = await client.get(
            f"/api/v1/attacks/{attack_id}",
            headers={"Authorization": "Bearer test_token"}
        )
        assert response.status_code == 200
        assert response.json()["status"] in ["pending", "running"]
        
        # 3. Wait for completion
        import asyncio
        for _ in range(60):  # Wait up to 60 seconds
            await asyncio.sleep(1)
            response = await client.get(
                f"/api/v1/attacks/{attack_id}",
                headers={"Authorization": "Bearer test_token"}
            )
            if response.json()["status"] in ["completed", "failed"]:
                break
        
        # 4. Get results
        response = await client.get(
            f"/api/v1/attacks/{attack_id}/results",
            headers={"Authorization": "Bearer test_token"}
        )
        assert response.status_code == 200
        assert "results" in response.json()
```

#### ผลลัพธ์ที่คาดหวัง
- ✅ Integration tests ครอบคลุม workflows
- ✅ E2E tests ผ่านทั้งหมด
- ✅ Agent coordination ทำงานถูกต้อง

---

## 📋 Phase 4: Performance Audit (สัปดาห์ 4)

### 4.1 Performance Profiling

#### เป้าหมาย
วัดและปรับปรุง performance

#### ขั้นตอนการดำเนินการ

##### 4.1.1 CPU Profiling
```python
# scripts/profile_cpu.py
"""CPU profiling script"""

import cProfile
import pstats
from pstats import SortKey

def profile_function():
    """Profile a function"""
    
    profiler = cProfile.Profile()
    profiler.enable()
    
    # Run code to profile
    from core.orchestrator import Orchestrator
    import asyncio
    
    async def run_attack():
        orch = Orchestrator()
        await orch.execute_attack({
            "target": "https://example.com",
            "type": "web"
        })
    
    asyncio.run(run_attack())
    
    profiler.disable()
    
    # Print stats
    stats = pstats.Stats(profiler)
    stats.sort_stats(SortKey.TIME)
    stats.print_stats(20)  # Top 20
    
    # Save to file
    stats.dump_stats("reports/cpu_profile.prof")

if __name__ == "__main__":
    profile_function()
```

##### 4.1.2 Memory Profiling
```python
# scripts/profile_memory.py
"""Memory profiling script"""

from memory_profiler import profile
import asyncio

@profile
async def run_attack():
    """Profile memory usage"""
    from core.orchestrator import Orchestrator
    
    orch = Orchestrator()
    await orch.execute_attack({
        "target": "https://example.com",
        "type": "web"
    })

if __name__ == "__main__":
    asyncio.run(run_attack())
```

##### 4.1.3 Database Query Profiling
```sql
-- Enable query logging
ALTER SYSTEM SET log_statement = 'all';
ALTER SYSTEM SET log_duration = on;
ALTER SYSTEM SET log_min_duration_statement = 100;  -- Log queries > 100ms

-- Reload configuration
SELECT pg_reload_conf();

-- Analyze slow queries
SELECT 
    query,
    calls,
    total_time,
    mean_time,
    max_time
FROM pg_stat_statements
ORDER BY mean_time DESC
LIMIT 20;
```

#### การแก้ไข

##### 4.1.4 Optimize Slow Functions
```python
# Before - Slow implementation
def process_results(results):
    processed = []
    for result in results:
        # Slow processing
        data = json.loads(result)
        validated = validate_data(data)
        processed.append(validated)
    return processed

# After - Optimized implementation
def process_results(results):
    # Use list comprehension
    return [
        validate_data(json.loads(result))
        for result in results
    ]

# Or use parallel processing
from concurrent.futures import ThreadPoolExecutor

def process_results(results):
    with ThreadPoolExecutor(max_workers=4) as executor:
        processed = list(executor.map(
            lambda r: validate_data(json.loads(r)),
            results
        ))
    return processed
```

##### 4.1.5 Add Caching
```python
# Add caching for expensive operations
from functools import lru_cache
import asyncio

class AgentManager:
    """Agent manager with caching"""
    
    @lru_cache(maxsize=128)
    def get_agent_class(self, agent_name: str):
        """Get agent class (cached)"""
        return self._load_agent_class(agent_name)
    
    async def get_agent_results(self, agent_name: str, target: str):
        """Get agent results with Redis caching"""
        cache_key = f"agent:{agent_name}:{target}"
        
        # Try cache first
        cached = await self.redis.get(cache_key)
        if cached:
            return json.loads(cached)
        
        # Execute agent
        result = await self.execute_agent(agent_name, target)
        
        # Cache result (5 minutes)
        await self.redis.setex(
            cache_key,
            300,
            json.dumps(result)
        )
        
        return result
```

##### 4.1.6 Optimize Database Queries
```python
# Before - N+1 query problem
def get_attacks_with_results():
    attacks = db.query(Attack).all()
    for attack in attacks:
        attack.results = db.query(Result).filter(
            Result.attack_id == attack.id
        ).all()
    return attacks

# After - Use eager loading
def get_attacks_with_results():
    return db.query(Attack).options(
        joinedload(Attack.results)
    ).all()

# Or use select_in loading for large datasets
def get_attacks_with_results():
    return db.query(Attack).options(
        selectinload(Attack.results)
    ).all()
```

#### ผลลัพธ์ที่คาดหวัง
- ✅ API response time < 100ms (p95)
- ✅ Memory usage < 2GB per instance
- ✅ CPU usage < 70% under load
- ✅ Database queries optimized

---

### 4.2 Load Testing

#### เป้าหมาย
ทดสอบระบบภายใต้ load สูง

#### ขั้นตอนการดำเนินการ

##### 4.2.1 Setup Locust
```python
# tests/load/locustfile.py
"""Locust load testing configuration"""

from locust import HttpUser, task, between
import random

class APIUser(HttpUser):
    """Simulate API user"""
    
    wait_time = between(1, 3)
    
    def on_start(self):
        """Login and get token"""
        response = self.client.post("/api/v1/auth/login", json={
            "username": "test",
            "password": "test"
        })
        self.token = response.json()["token"]
    
    @task(3)
    def list_agents(self):
        """List all agents"""
        self.client.get(
            "/api/v1/agents",
            headers={"Authorization": f"Bearer {self.token}"}
        )
    
    @task(2)
    def get_attack_status(self):
        """Get attack status"""
        attack_id = random.randint(1, 100)
        self.client.get(
            f"/api/v1/attacks/{attack_id}",
            headers={"Authorization": f"Bearer {self.token}"}
        )
    
    @task(1)
    def start_attack(self):
        """Start new attack"""
        self.client.post(
            "/api/v1/attacks",
            json={
                "target": f"https://example{random.randint(1, 100)}.com",
                "attack_type": "web"
            },
            headers={"Authorization": f"Bearer {self.token}"}
        )
```

##### 4.2.2 Run Load Tests
```bash
# Start with 10 users, spawn 1 user/second
locust -f tests/load/locustfile.py \
       --host=http://localhost:8000 \
       --users=10 \
       --spawn-rate=1 \
       --run-time=5m \
       --html=reports/load_test_10users.html

# Increase to 100 users
locust -f tests/load/locustfile.py \
       --host=http://localhost:8000 \
       --users=100 \
       --spawn-rate=10 \
       --run-time=10m \
       --html=reports/load_test_100users.html

# Stress test with 1000 users
locust -f tests/load/locustfile.py \
       --host=http://localhost:8000 \
       --users=1000 \
       --spawn-rate=50 \
       --run-time=15m \
       --html=reports/load_test_1000users.html
```

##### 4.2.3 Analyze Results
```python
# scripts/analyze_load_test.py
"""Analyze load test results"""

import json
from pathlib import Path

def analyze_load_test(report_file):
    """Analyze Locust HTML report"""
    
    # Parse HTML report
    # Extract metrics
    metrics = {
        "total_requests": 0,
        "failed_requests": 0,
        "avg_response_time": 0,
        "p95_response_time": 0,
        "p99_response_time": 0,
        "requests_per_second": 0
    }
    
    print("Load Test Results:")
    print("=" * 80)
    print(f"Total Requests: {metrics['total_requests']}")
    print(f"Failed Requests: {metrics['failed_requests']} "
          f"({metrics['failed_requests']/metrics['total_requests']*100:.2f}%)")
    print(f"Avg Response Time: {metrics['avg_response_time']:.2f}ms")
    print(f"P95 Response Time: {metrics['p95_response_time']:.2f}ms")
    print(f"P99 Response Time: {metrics['p99_response_time']:.2f}ms")
    print(f"Requests/sec: {metrics['requests_per_second']:.2f}")

if __name__ == "__main__":
    analyze_load_test("reports/load_test_100users.html")
```

#### ผลลัพธ์ที่คาดหวัง
- ✅ Support 100 concurrent users
- ✅ Throughput > 1000 req/s
- ✅ Error rate < 1%
- ✅ P95 response time < 100ms

---

## 📋 Phase 5: Security Audit (สัปดาห์ 5)

### 5.1 Security Vulnerability Scan

#### เป้าหมาย
ตรวจหาและแก้ไขช่องโหว่ด้านความปลอดภัย

#### ขั้นตอนการดำเนินการ

##### 5.1.1 Dependency Vulnerability Scan
```bash
# Install safety
pip install safety

# Scan dependencies
safety check --json > reports/safety_report.json

# Scan with detailed output
safety check --full-report > reports/safety_full_report.txt
```

##### 5.1.2 SAST (Static Application Security Testing)
```bash
# Run bandit (already covered in Phase 1)
bandit -r . -f json -o reports/bandit_security.json

# Run semgrep
semgrep --config=auto \
        --json \
        --output=reports/semgrep_report.json \
        .

# Run CodeQL
codeql database create codeql-db --language=python
codeql database analyze codeql-db \
       --format=sarif-latest \
       --output=reports/codeql_results.sarif
```

##### 5.1.3 Secret Scanning
```bash
# Install trufflehog
pip install trufflehog

# Scan for secrets
trufflehog filesystem . \
           --json \
           --output=reports/secrets_scan.json

# Scan git history
trufflehog git file://. \
           --json \
           --output=reports/git_secrets_scan.json
```

##### 5.1.4 Container Security Scan
```bash
# Scan Docker images
trivy image ghcr.io/manus-aiattack/api:latest \
      --format json \
      --output reports/trivy_api.json

# Scan for misconfigurations
trivy config . \
      --format json \
      --output reports/trivy_config.json
```

#### การแก้ไข

##### 5.1.5 Fix Vulnerable Dependencies
```bash
# Update vulnerable packages
pip install --upgrade package_name

# Or use pip-audit to auto-fix
pip install pip-audit
pip-audit --fix
```

##### 5.1.6 Remove Hardcoded Secrets
```python
# Before - Hardcoded secrets ❌
DATABASE_URL = "postgresql://user:password@localhost/db"
API_KEY = "sk-1234567890abcdef"

# After - Use environment variables ✅
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
API_KEY = os.getenv("API_KEY")

# Validate
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable not set")
if not API_KEY:
    raise ValueError("API_KEY environment variable not set")
```

##### 5.1.7 Add Security Headers
```python
# api/middleware/security.py
"""Security middleware"""

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to responses"""
    
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        
        return response

# Add to app
from api.middleware.security import SecurityHeadersMiddleware
app.add_middleware(SecurityHeadersMiddleware)
```

##### 5.1.8 Add Input Validation
```python
# Before - No validation ❌
@app.post("/api/v1/attacks")
async def create_attack(target: str):
    # Direct use without validation
    result = execute_attack(target)
    return result

# After - Proper validation ✅
from pydantic import BaseModel, validator, HttpUrl
import re

class AttackRequest(BaseModel):
    target: HttpUrl
    
    @validator("target")
    def validate_target(cls, v):
        # Additional validation
        url_str = str(v)
        
        # Block internal IPs
        if re.search(r'(127\.0\.0\.1|localhost|192\.168\.|10\.)', url_str):
            raise ValueError("Internal IPs not allowed")
        
        # Block file:// protocol
        if url_str.startswith("file://"):
            raise ValueError("File protocol not allowed")
        
        return v

@app.post("/api/v1/attacks")
async def create_attack(request: AttackRequest):
    result = execute_attack(str(request.target))
    return result
```

#### ผลลัพธ์ที่คาดหวัง
- ✅ No critical vulnerabilities
- ✅ No hardcoded secrets
- ✅ Security headers implemented
- ✅ Input validation complete

---

### 5.2 Authentication & Authorization Audit

#### เป้าหมาย
ตรวจสอบและปรับปรุง auth system

#### ขั้นตอนการดำเนินการ

##### 5.2.1 Review Authentication
```python
# api/auth/jwt.py
"""JWT authentication"""

from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
import os

# Configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def create_access_token(data: dict, expires_delta: timedelta = None):
    """Create JWT access token"""
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    
    return encoded_jwt

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password"""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Hash password"""
    return pwd_context.hash(password)
```

##### 5.2.2 Implement RBAC
```python
# api/auth/rbac.py
"""Role-Based Access Control"""

from enum import Enum
from typing import List
from fastapi import Depends, HTTPException, status

class Role(str, Enum):
    """User roles"""
    ADMIN = "admin"
    USER = "user"
    VIEWER = "viewer"

class Permission(str, Enum):
    """Permissions"""
    CREATE_ATTACK = "create_attack"
    VIEW_ATTACK = "view_attack"
    DELETE_ATTACK = "delete_attack"
    MANAGE_USERS = "manage_users"

# Role permissions mapping
ROLE_PERMISSIONS = {
    Role.ADMIN: [
        Permission.CREATE_ATTACK,
        Permission.VIEW_ATTACK,
        Permission.DELETE_ATTACK,
        Permission.MANAGE_USERS
    ],
    Role.USER: [
        Permission.CREATE_ATTACK,
        Permission.VIEW_ATTACK
    ],
    Role.VIEWER: [
        Permission.VIEW_ATTACK
    ]
}

def require_permission(permission: Permission):
    """Decorator to require permission"""
    def decorator(func):
        async def wrapper(*args, current_user = Depends(get_current_user), **kwargs):
            user_permissions = ROLE_PERMISSIONS.get(current_user.role, [])
            
            if permission not in user_permissions:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions"
                )
            
            return await func(*args, current_user=current_user, **kwargs)
        
        return wrapper
    return decorator

# Usage
@app.post("/api/v1/attacks")
@require_permission(Permission.CREATE_ATTACK)
async def create_attack(request: AttackRequest, current_user: User):
    # Only users with CREATE_ATTACK permission can access
    pass
```

##### 5.2.3 Add Rate Limiting
```python
# api/middleware/rate_limit.py
"""Rate limiting middleware"""

from fastapi import Request, HTTPException, status
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)

# Add to app
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Usage
@app.get("/api/v1/agents")
@limiter.limit("100/minute")
async def list_agents(request: Request):
    pass

@app.post("/api/v1/attacks")
@limiter.limit("10/minute")
async def create_attack(request: Request, attack: AttackRequest):
    pass
```

#### ผลลัพธ์ที่คาดหวัง
- ✅ JWT authentication implemented
- ✅ RBAC implemented
- ✅ Rate limiting active
- ✅ Password hashing secure

---

## 📋 Phase 6: Documentation Audit (สัปดาห์ 6)

### 6.1 Code Documentation

#### เป้าหมาย
ตรวจสอบและปรับปรุง code documentation

#### ขั้นตอนการดำเนินการ

##### 6.1.1 Check Docstring Coverage
```python
# scripts/check_docstrings.py
"""Check docstring coverage"""

import ast
from pathlib import Path

def check_docstrings():
    """Check docstring coverage"""
    
    stats = {
        "total_functions": 0,
        "documented_functions": 0,
        "total_classes": 0,
        "documented_classes": 0,
        "total_modules": 0,
        "documented_modules": 0
    }
    
    for py_file in Path(".").rglob("*.py"):
        if "venv" in str(py_file):
            continue
        
        try:
            tree = ast.parse(py_file.read_text())
            
            # Check module docstring
            stats["total_modules"] += 1
            if ast.get_docstring(tree):
                stats["documented_modules"] += 1
            
            for node in ast.walk(tree):
                # Check class docstrings
                if isinstance(node, ast.ClassDef):
                    stats["total_classes"] += 1
                    if ast.get_docstring(node):
                        stats["documented_classes"] += 1
                
                # Check function docstrings
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    stats["total_functions"] += 1
                    if ast.get_docstring(node):
                        stats["documented_functions"] += 1
        except:
            pass
    
    # Print summary
    print("Docstring Coverage:")
    print("=" * 80)
    print(f"Modules: {stats['documented_modules']}/{stats['total_modules']} "
          f"({stats['documented_modules']/stats['total_modules']*100:.1f}%)")
    print(f"Classes: {stats['documented_classes']}/{stats['total_classes']} "
          f"({stats['documented_classes']/stats['total_classes']*100:.1f}%)")
    print(f"Functions: {stats['documented_functions']}/{stats['total_functions']} "
          f"({stats['documented_functions']/stats['total_functions']*100:.1f}%)")

if __name__ == "__main__":
    check_docstrings()
```

##### 6.1.2 Generate API Documentation
```bash
# Install sphinx
pip install sphinx sphinx-rtd-theme sphinx-autodoc-typehints

# Initialize sphinx
sphinx-quickstart docs

# Configure autodoc in docs/conf.py
# Generate documentation
cd docs
make html

# View documentation
open _build/html/index.html
```

##### 6.1.3 Add Docstrings
```python
# Example: Proper docstring format

def execute_attack(
    target: str,
    attack_type: str,
    agents: List[str] = None,
    timeout: int = 3600
) -> Dict[str, Any]:
    """
    Execute penetration testing attack on target.
    
    This function orchestrates multiple agents to perform a comprehensive
    penetration test on the specified target. It supports various attack
    types and can be customized with specific agents.
    
    Args:
        target: Target URL or IP address to attack
        attack_type: Type of attack (web, network, mobile, cloud)
        agents: Optional list of specific agents to use. If None, all
                applicable agents for the attack type will be used
        timeout: Maximum time in seconds for the attack. Must be between
                 60 and 86400 seconds (1 minute to 24 hours)
    
    Returns:
        Dictionary containing attack results with the following keys:
        - attack_id: Unique identifier for this attack
        - status: Current status (pending, running, completed, failed)
        - progress: Progress percentage (0-100)
        - results: List of results from each agent
        - errors: List of any errors encountered
    
    Raises:
        ValueError: If target is invalid or timeout is out of range
        RuntimeError: If attack execution fails
    
    Example:
        >>> result = execute_attack(
        ...     target="https://example.com",
        ...     attack_type="web",
        ...     agents=["nmap", "nuclei"],
        ...     timeout=1800
        ... )
        >>> print(result["status"])
        'completed'
    
    Note:
        This function requires proper authentication and authorization.
        Ensure you have permission to test the target system.
    """
    # Implementation
    pass
```

#### ผลลัพธ์ที่คาดหวัง
- ✅ Docstring coverage > 90%
- ✅ API documentation generated
- ✅ All public APIs documented

---

### 6.2 User Documentation

#### เป้าหมาย
สร้างและปรับปรุง user documentation

#### ขั้นตอนการดำเนินการ

##### 6.2.1 Create User Guide
```markdown
# docs/user_guide.md

# Manus AI Attack Platform - User Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [Basic Usage](#basic-usage)
4. [Advanced Features](#advanced-features)
5. [Troubleshooting](#troubleshooting)

## Introduction

Manus AI Attack Platform is an AI-driven penetration testing platform...

## Getting Started

### Prerequisites
- Python 3.11+
- PostgreSQL 15+
- Redis 7+

### Installation

#### Option 1: Docker (Recommended)
```bash
docker-compose up -d
```

#### Option 2: Manual Installation
```bash
# Clone repository
git clone https://github.com/manus-aiattack/aiprojectattack.git
cd aiprojectattack

# Install dependencies
pip install -r requirements.txt

# Setup database
python scripts/setup_database.py

# Run application
python -m api.main
```

## Basic Usage

### Starting an Attack via CLI
```bash
manus attack https://example.com --type web
```

### Starting an Attack via API
```bash
curl -X POST http://localhost:8000/api/v1/attacks \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "attack_type": "web"
  }'
```

## Advanced Features

### Custom Workflows
...

### AI Configuration
...

## Troubleshooting

### Common Issues
...
```

##### 6.2.2 Create API Reference
```markdown
# docs/api_reference.md

# API Reference

## Authentication

All API requests require authentication using JWT tokens.

### Get Token
```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "username": "your_username",
  "password": "your_password"
}
```

## Attacks

### Create Attack
```http
POST /api/v1/attacks
Authorization: Bearer YOUR_TOKEN
Content-Type: application/json

{
  "target": "https://example.com",
  "attack_type": "web",
  "agents": ["nmap", "nuclei"],
  "timeout": 3600
}
```

Response:
```json
{
  "attack_id": 123,
  "status": "pending",
  "created_at": "2025-10-26T10:00:00Z"
}
```

### Get Attack Status
```http
GET /api/v1/attacks/{attack_id}
Authorization: Bearer YOUR_TOKEN
```

...
```

#### ผลลัพธ์ที่คาดหวัง
- ✅ User guide complete
- ✅ API reference complete
- ✅ Troubleshooting guide complete

---

## 📋 Phase 7: Deployment Readiness (สัปดาห์ 7)

### 7.1 Environment Configuration

#### เป้าหมาย
ตรวจสอบและจัดการ environment configuration

#### ขั้นตอนการดำเนินการ

##### 7.1.1 Create Environment Templates
```bash
# .env.example
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/manus_ai_attack
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=40

# Redis
REDIS_URL=redis://localhost:6379/0
REDIS_MAX_CONNECTIONS=100

# JWT
JWT_SECRET_KEY=your-secret-key-here
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30

# AI Models
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=mixtral:8x7b

# Logging
LOG_LEVEL=INFO
LOG_FILE=/var/log/manus/app.log

# Performance
MAX_WORKERS=4
REQUEST_TIMEOUT=300
```

##### 7.1.2 Validate Configuration
```python
# scripts/validate_config.py
"""Validate environment configuration"""

import os
from typing import Dict, Any

REQUIRED_VARS = [
    "DATABASE_URL",
    "REDIS_URL",
    "JWT_SECRET_KEY",
    "OLLAMA_URL"
]

OPTIONAL_VARS = {
    "LOG_LEVEL": "INFO",
    "MAX_WORKERS": "4",
    "REQUEST_TIMEOUT": "300"
}

def validate_config() -> Dict[str, Any]:
    """Validate configuration"""
    
    errors = []
    warnings = []
    
    # Check required variables
    for var in REQUIRED_VARS:
        if not os.getenv(var):
            errors.append(f"Missing required variable: {var}")
    
    # Check optional variables
    for var, default in OPTIONAL_VARS.items():
        if not os.getenv(var):
            warnings.append(f"Using default for {var}: {default}")
    
    # Validate values
    if os.getenv("JWT_SECRET_KEY") and len(os.getenv("JWT_SECRET_KEY")) < 32:
        errors.append("JWT_SECRET_KEY must be at least 32 characters")
    
    # Print results
    if errors:
        print("Configuration Errors:")
        for error in errors:
            print(f"  ❌ {error}")
    
    if warnings:
        print("\nConfiguration Warnings:")
        for warning in warnings:
            print(f"  ⚠️  {warning}")
    
    if not errors:
        print("✅ Configuration valid")
    
    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings
    }

if __name__ == "__main__":
    validate_config()
```

#### ผลลัพธ์ที่คาดหวัง
- ✅ Environment templates created
- ✅ Configuration validation working
- ✅ All required variables documented

---

### 7.2 Health Checks

#### เป้าหมาย
สร้าง health check endpoints

#### ขั้นตอนการดำเนินการ

```python
# api/health.py
"""Health check endpoints"""

from fastapi import APIRouter, status
from typing import Dict, Any
import asyncio

router = APIRouter()

@router.get("/health", status_code=status.HTTP_200_OK)
async def health_check() -> Dict[str, str]:
    """Basic health check"""
    return {"status": "healthy"}

@router.get("/ready", status_code=status.HTTP_200_OK)
async def readiness_check() -> Dict[str, Any]:
    """Readiness check - verify all dependencies"""
    
    checks = {
        "database": await check_database(),
        "redis": await check_redis(),
        "ollama": await check_ollama()
    }
    
    all_healthy = all(check["healthy"] for check in checks.values())
    
    return {
        "ready": all_healthy,
        "checks": checks
    }

async def check_database() -> Dict[str, Any]:
    """Check database connection"""
    try:
        # Try to execute simple query
        await db.execute("SELECT 1")
        return {"healthy": True}
    except Exception as e:
        return {"healthy": False, "error": str(e)}

async def check_redis() -> Dict[str, Any]:
    """Check Redis connection"""
    try:
        await redis.ping()
        return {"healthy": True}
    except Exception as e:
        return {"healthy": False, "error": str(e)}

async def check_ollama() -> Dict[str, Any]:
    """Check Ollama connection"""
    try:
        # Try to connect to Ollama
        response = await http_client.get(f"{OLLAMA_URL}/api/tags")
        return {"healthy": response.status_code == 200}
    except Exception as e:
        return {"healthy": False, "error": str(e)}
```

#### ผลลัพธ์ที่คาดหวัง
- ✅ Health check endpoint working
- ✅ Readiness check endpoint working
- ✅ All dependencies checked

---

## 📊 Summary & Metrics

### Overall Audit Goals

| Category | Current | Target | Priority |
|----------|---------|--------|----------|
| **Code Quality** | 6.5/10 | 9.0/10 | 🔴 Critical |
| **Test Coverage** | 3.4% | 85% | 🔴 Critical |
| **Documentation** | 60% | 95% | 🟡 High |
| **Performance** | Good | Excellent | 🟡 High |
| **Security** | Fair | Excellent | 🔴 Critical |
| **Deployment Ready** | 70% | 100% | 🟡 High |

### Timeline Summary

| Phase | Duration | Status |
|-------|----------|--------|
| Phase 1: Code Quality | Week 1 | 🔄 In Progress |
| Phase 2: Architecture | Week 2 | ⏳ Pending |
| Phase 3: Testing | Week 3 | ⏳ Pending |
| Phase 4: Performance | Week 4 | ⏳ Pending |
| Phase 5: Security | Week 5 | ⏳ Pending |
| Phase 6: Documentation | Week 6 | ⏳ Pending |
| Phase 7: Deployment | Week 7 | ⏳ Pending |

### Success Criteria

- ✅ Pylint score > 8.0/10
- ✅ Test coverage > 85%
- ✅ No critical security vulnerabilities
- ✅ API response time < 100ms (p95)
- ✅ Documentation coverage > 95%
- ✅ All health checks passing
- ✅ Zero hardcoded secrets
- ✅ All TODOs resolved

---

## 🎯 Next Steps

### Immediate Actions (Week 1)
1. Run static code analysis tools
2. Fix critical issues from pylint/flake8
3. Replace print() with logging
4. Remove hardcoded secrets
5. Start writing unit tests

### Short Term (Weeks 2-4)
1. Complete test coverage to 85%
2. Optimize performance bottlenecks
3. Fix security vulnerabilities
4. Complete API documentation

### Long Term (Weeks 5-7)
1. Security audit and hardening
2. Complete user documentation
3. Deployment readiness checks
4. Final QA and testing

---

**จัดทำโดย:** Manus AI  
**วันที่:** 26 ตุลาคม 2568  
**เวอร์ชัน:** 1.0.0  
**Repository:** https://github.com/manus-aiattack/aiprojectattack

