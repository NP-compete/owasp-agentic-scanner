# Architecture

Overview of how the OWASP Agentic AI Scanner works.

## Directory Structure

```
src/owasp_agentic_scanner/
├── cli.py              # CLI entry point (typer)
├── rules/
│   ├── base.py         # BaseRule, Finding, DetectionPattern
│   ├── goal_hijack.py  # AA01
│   ├── tool_misuse.py  # AA02
│   └── ...             # AA03-AA10
└── reporters/
    ├── console.py      # Rich console output
    ├── json_reporter.py
    └── sarif_reporter.py
```

## Core Components

### 1. Rules Engine (`rules/base.py`)

```
BaseRule
├── rule_id: str (e.g., "AA01")
├── rule_name: str
├── owasp_category: str
├── description: str
├── file_extensions: list[str]
└── _get_patterns() -> list[DetectionPattern]
```

Each rule defines regex patterns with:
- `pattern`: Compiled regex
- `message`: Finding description
- `recommendation`: How to fix
- `severity`: critical/high/medium/low/info
- `confidence`: high/medium/low

### 2. Scanner Flow

```
CLI Input
    ↓
Load Rules (filter by --rules)
    ↓
Discover Files (by extension)
    ↓
Parallel Scan (ThreadPoolExecutor)
    ↓
Pattern Matching (regex)
    ↓
Filter Findings (noqa, severity)
    ↓
Report (console/json/sarif)
```

### 3. Pattern Matching

```python
for line_num, line in enumerate(file_content.split("\n"), 1):
    if noqa_pattern.search(line):  # Skip suppressed
        continue
    for pattern in rule.patterns:
        if pattern.regex.search(line):
            findings.append(Finding(...))
```

### 4. Reporters

| Reporter | Output | Use Case |
|----------|--------|----------|
| Console | Rich tables | Local development |
| JSON | Structured data | Programmatic access |
| SARIF | Static analysis format | CI/CD integration |

## Performance

- **Parallel scanning**: Uses `ThreadPoolExecutor` with configurable workers
- **Early filtering**: Skip non-matching file extensions
- **Compiled regex**: Patterns compiled once, reused

## Extensibility

Add new rules by:
1. Creating a new file in `rules/`
2. Inheriting from `BaseRule`
3. Defining patterns in `_get_patterns()`
4. Registering in `rules/__init__.py`
