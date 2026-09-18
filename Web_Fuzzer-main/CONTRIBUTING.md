# Contributing to WebSeeker Pro

First off, thanks for considering contributing to WebSeeker Pro! 

## How Can I Contribute?

### 1. Reporting Bugs
Create an issue on GitHub detailing:
- The bug and how to reproduce it.
- Your OS, Python version, and network setup.

### 2. Suggesting Enhancements
We welcome new vulnerability checks and UI improvements! Check the issues list to ensure it hasn't already been proposed.

### 3. Adding New Scanners
If you want to add a new security scanner (e.g., SSRF, XXE):
1. Create a module in `scanners/your_scanner.py`.
2. Ensure it follows the interface: `def scan(url): -> return list of findings`.
3. Add your payloads to the `Payloads/` directory.
4. Integrate the scanner call into `core/engine.py` and `main.py`.

## Development Setup

1. Check out the repository.
2. Ensure you have Python 3.9+ and Docker installed.
3. Install development dependencies:
   ```bash
   pip install -e .[dev]
   ```
4. Run tests:
   ```bash
   pytest tests/
   ```
5. Ensure your code is formatted with Black and passes Flake8 before submitting a PR.
