# Python Black Box Fuzzer

A powerful and flexible black box fuzzing tool designed to find vulnerabilities in various types of applications and interfaces. This fuzzer supports multiple input generation strategies, intelligent mutation techniques, coverage tracking, and detailed crash analysis.

## Features

- **Multiple Input Generation Strategies**
  - Random generation
  - Mutation-based generation
  - Template-based generation
  - Corpus-based evolution
  - Predefined attack patterns (SQL injection, buffer overflow, etc.)

- **Advanced Mutation Techniques**
  - Bit flipping
  - Byte flipping
  - Byte increment/decrement
  - Chunk replacement
  - String insertion

- **Coverage Tracking**
  - Line coverage analysis
  - Coverage-guided corpus evolution
  - HTML coverage reports
  - Coverage statistics by input

- **Comprehensive Crash Analysis**
  - Automatic crash categorization
  - Stack trace analysis
  - Unique crash hashing
  - Detailed crash reports
  - Timeline tracking

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/python-fuzzer.git
cd python-fuzzer
```

2. Install required packages:
```bash
pip install coverage
```

## Basic Usage

1. Create a test file (e.g., `my_test.py`):
```python
from fuzzer import Fuzzer, FuzzConfig

# Define target function
def target_function(input_str: str):
    # Your code to test here
    if len(input_str) > 1000:
        raise ValueError("Buffer overflow!")
    return True

# Configure and run fuzzer
config = FuzzConfig(
    min_length=1,
    max_length=2000,
    iterations=1000
)

fuzzer = Fuzzer(target_function, config)
fuzzer.run()
```

2. Run the test:
```bash
python my_test.py
```

## Use Cases and Examples

### 1. Testing File Parsers

```python
# test_parser.py
from fuzzer import Fuzzer, FuzzConfig

def parse_file(content):
    # Your parser code
    pass

def main():
    config = FuzzConfig(
        min_length=1,
        max_length=2000,
        char_types=['ascii_letters', 'special'],
        iterations=1000
    )
    
    fuzzer = Fuzzer(parse_file, config)
    fuzzer.run()

main()
```

### 2. Testing Web APIs

```python
# test_api.py
from fuzzer import Fuzzer, FuzzConfig
import requests

def main():
    def test_api(input_str):
        response = requests.get(f'http://localhost:8080/api?param={input_str}')
        return response.text

    config = FuzzConfig(
        min_length=1,
        max_length=100,
        char_types=['ascii_letters', 'sql_injection'],
        iterations=500
    )
    
    fuzzer = Fuzzer(test_api, config)
    fuzzer.run()

main()
```

### 3. Testing Network Protocols

```python
# test_network.py
from fuzzer import Fuzzer, FuzzConfig
import socket

def main():
    def test_network(input_str):
        with socket.socket() as sock:
            sock.connect(('localhost', 12345))
            sock.send(input_str.encode())
            return sock.recv(1024)

    config = FuzzConfig(
        min_length=1,
        max_length=1000,
        char_types=['ascii_letters', 'buffer_overflow'],
        iterations=500
    )
    
    fuzzer = Fuzzer(test_network, config)
    fuzzer.run()

main()
```

## Configuration Options

### FuzzConfig Parameters

- `min_length`: Minimum length of generated inputs
- `max_length`: Maximum length of generated inputs
- `iterations`: Number of fuzzing iterations
- `char_types`: Types of characters to use in generation
- `mutation_rate`: Rate of mutation for mutation strategy
- `corpus_dir`: Directory for input corpus
- `crash_dir`: Directory for crash information
- `coverage_dir`: Directory for coverage reports

Available character types:
- `ascii_letters`
- `digits`
- `punctuation`
- `whitespace`
- `special`
- `format_strings`
- `sql_injection`
- `buffer_overflow`

## Best Practices

1. **Target Function Design**
   - Make your target function self-contained
   - Handle all exceptions appropriately
   - Return meaningful results
   - Clean up resources properly

2. **Configuration Tips**
   - Start with small iterations for testing
   - Use appropriate character types for your target
   - Adjust mutation rate based on results
   - Monitor coverage to ensure thorough testing

3. **Analyzing Results**
   - Check crashes directory for detected vulnerabilities
   - Review coverage reports to identify untested code
   - Examine crash reports for patterns
   - Use timeline data to track progress

## Advanced Usage

### Custom Character Sets
```python
config = FuzzConfig(
    char_types=['ascii_letters', 'sql_injection'],
    # Add specific characters for your needs
)
```

### Coverage-Guided Fuzzing
```python
config = FuzzConfig(
    corpus_dir='my_corpus',
    coverage_dir='my_coverage'
)
```

### Crash Analysis
```python
report = fuzzer.run()
print(f"Unique crashes: {report['stats']['unique_crashes']}")
print(f"Coverage: {report['stats']['coverage']}")
```

## Analyzing Results

1. Check `crashes/` directory for:
   - Crash details in JSON format
   - Stack traces
   - Input that caused the crash
   - Timeline of discoveries

2. Review `coverage/` directory for:
   - HTML coverage reports
   - Line-by-line analysis
   - Uncovered code sections

3. Examine `corpus/` directory for:
   - Interesting inputs
   - New coverage patterns
   - Evolution of test cases

## Tips for Effective Fuzzing

1. **Target Selection**
   - Identify critical code paths
   - Focus on user input handling
   - Test boundary conditions
   - Include error handling code

2. **Input Strategy**
   - Use appropriate character sets
   - Combine multiple strategies
   - Adjust mutation rates
   - Monitor corpus evolution

3. **Resource Management**
   - Set appropriate timeouts
   - Handle cleanup properly
   - Monitor memory usage
   - Save and restore state

4. **Result Analysis**
   - Review all unique crashes
   - Check coverage reports
   - Look for patterns
   - Document findings

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and feature requests, please create an issue in the GitHub repository.
