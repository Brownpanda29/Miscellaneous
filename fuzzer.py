import random
import string
import logging
import argparse
from typing import List, Optional, Union, Callable, Dict, Set, Tuple
from dataclasses import dataclass
import time
import sys
import json
import hashlib
import coverage
import signal
from collections import defaultdict
import os
import pickle

@dataclass
class FuzzConfig:
    """Configuration settings for fuzzing operations."""
    min_length: int = 1
    max_length: int = 100
    char_types: List[str] = None
    iterations: int = 1000
    seed: Optional[int] = None
    output_file: Optional[str] = "fuzzer_output.txt"
    mutation_rate: float = 0.2
    corpus_dir: str = "corpus"
    crash_dir: str = "crashes"
    coverage_dir: str = "coverage"

class InputGenerator:
    """Advanced input generator with multiple generation strategies."""
    
    def __init__(self, config: FuzzConfig):
        self.config = config
        if config.seed is not None:
            random.seed(config.seed)
        
        self.char_pools = {
            'ascii_letters': string.ascii_letters,
            'digits': string.digits,
            'punctuation': string.punctuation,
            'whitespace': string.whitespace,
            'special': ''.join([chr(i) for i in range(128, 256)]),
            'format_strings': ['%s', '%d', '%x', '%p', '%n'],
            'sql_injection': ["'", '"', ';', '--', '1=1'],
            'buffer_overflow': ['A' * 256, 'A' * 1024, 'A' * 4096]
        }
        
        self.interesting_values = [
            "",                    # Empty string
            "0",                   # Zero
            "-1",                  # Negative
            "4294967295",         # UINT_MAX
            "2147483647",         # INT_MAX
            "-2147483648",        # INT_MIN
            "1.0",                # Float
            "true",               # Boolean
            "null",               # Null
            "../",                # Path traversal
            "<?xml>",             # XML injection
            "<script>",           # XSS
        ]
        
        if not config.char_types:
            self.char_pool = ''.join(self.char_pools[k] for k in 
                                   ['ascii_letters', 'digits', 'punctuation'])
        else:
            self.char_pool = ''.join(self.char_pools[t] for t in config.char_types
                                   if t in self.char_pools)
        
        self.corpus = []
        self.load_or_create_corpus()

    def load_or_create_corpus(self):
        """Load existing corpus or create initial one."""
        os.makedirs(self.config.corpus_dir, exist_ok=True)
        corpus_files = os.listdir(self.config.corpus_dir)
        
        if corpus_files:
            for file in corpus_files:
                with open(os.path.join(self.config.corpus_dir, file), 'r') as f:
                    self.corpus.append(f.read())
        else:
            # Create initial corpus with interesting values
            self.corpus.extend(self.interesting_values)
            for value in self.corpus:
                self.save_to_corpus(value)

    def save_to_corpus(self, input_str: str):
        """Save new input to corpus directory."""
        input_hash = hashlib.md5(input_str.encode()).hexdigest()
        with open(os.path.join(self.config.corpus_dir, f"input_{input_hash}"), 'w') as f:
            f.write(input_str)

    def generate_input(self, strategy: str = "random") -> str:
        """Generate input using various strategies."""
        strategies = {
            "random": self._generate_random,
            "mutation": self._generate_mutation,
            "interesting": self._generate_interesting,
            "template": self._generate_template
        }
        return strategies.get(strategy, self._generate_random)()

    def _generate_random(self) -> str:
        """Generate completely random input."""
        length = random.randint(self.config.min_length, self.config.max_length)
        return ''.join(random.choice(self.char_pool) for _ in range(length))

    def _generate_mutation(self) -> str:
        """Generate input by mutating existing corpus entry."""
        if not self.corpus:
            return self._generate_random()
            
        base_input = random.choice(self.corpus)
        mutations = [
            self._bit_flip,
            self._byte_flip,
            self._byte_increment,
            self._byte_decrement,
            self._chunk_replacement,
            self._string_insertion
        ]
        
        num_mutations = max(1, int(len(base_input) * self.config.mutation_rate))
        result = base_input
        
        for _ in range(num_mutations):
            mutation = random.choice(mutations)
            result = mutation(result)
            
        return result

    def _bit_flip(self, input_str: str) -> str:
        """Flip random bit in string."""
        if not input_str:
            return input_str
        pos = random.randint(0, len(input_str) - 1)
        char = input_str[pos]
        bit_pos = random.randint(0, 7)
        new_char = chr(ord(char) ^ (1 << bit_pos))
        return input_str[:pos] + new_char + input_str[pos + 1:]

    def _byte_flip(self, input_str: str) -> str:
        """Flip random byte in string."""
        if not input_str:
            return input_str
        pos = random.randint(0, len(input_str) - 1)
        new_char = chr(random.randint(0, 255))
        return input_str[:pos] + new_char + input_str[pos + 1:]

    def _byte_increment(self, input_str: str) -> str:
        """Increment random byte in string."""
        if not input_str:
            return input_str
        pos = random.randint(0, len(input_str) - 1)
        char = input_str[pos]
        new_char = chr((ord(char) + 1) % 256)
        return input_str[:pos] + new_char + input_str[pos + 1:]

    def _byte_decrement(self, input_str: str) -> str:
        """Decrement random byte in string."""
        if not input_str:
            return input_str
        pos = random.randint(0, len(input_str) - 1)
        char = input_str[pos]
        new_char = chr((ord(char) - 1) % 256)
        return input_str[:pos] + new_char + input_str[pos + 1:]

    def _chunk_replacement(self, input_str: str) -> str:
        """Replace chunk of input with random data."""
        if not input_str:
            return input_str
        chunk_size = random.randint(1, max(1, len(input_str) // 4))
        start = random.randint(0, max(0, len(input_str) - chunk_size))
        chunk = ''.join(random.choice(self.char_pool) for _ in range(chunk_size))
        return input_str[:start] + chunk + input_str[start + chunk_size:]

    def _string_insertion(self, input_str: str) -> str:
        """Insert interesting string at random position."""
        if not self.interesting_values:
            return input_str
        pos = random.randint(0, len(input_str))
        insert_str = random.choice(self.interesting_values)
        return input_str[:pos] + insert_str + input_str[pos:]

    def _generate_interesting(self) -> str:
        """Generate input using predefined interesting values."""
        if random.random() < 0.5:
            return random.choice(self.interesting_values)
        else:
            # Combine multiple interesting values
            num_values = random.randint(2, 4)
            values = random.choices(self.interesting_values, k=num_values)
            return ''.join(values)

    def _generate_template(self) -> str:
        """Generate input based on templates."""
        templates = [
            "USER_{}_ADMIN",
            "SELECT * FROM {} WHERE id={}",
            "https://{}/{}?id={}",
            "<{}>{}</{}>",
            "function {}({}) { return {} }"
        ]
        
        template = random.choice(templates)
        filled_template = template.format(
            *[self._generate_random() for _ in range(template.count("{}"))]
        )
        return filled_template

class CoverageTracker:
    """Tracks code coverage during fuzzing."""
    
    def __init__(self, config: FuzzConfig):
        self.config = config
        self.cov = coverage.Coverage()
        self.covered_lines = set()
        self.coverage_by_input = defaultdict(set)
        os.makedirs(config.coverage_dir, exist_ok=True)
        
    def start(self):
        """Start coverage tracking."""
        self.cov.start()
        
    def stop(self):
        """Stop coverage tracking and save results."""
        self.cov.stop()
        self.cov.save()
        
    def get_new_coverage(self, input_str: str) -> Set[Tuple[str, int]]:
        """Get new lines covered by input."""
        self.cov.save()
        data = self.cov.get_data()
        new_lines = set()
        
        for filename in data.measured_files():
            for lineno in data.lines(filename):
                line_info = (filename, lineno)
                if line_info not in self.covered_lines:
                    new_lines.add(line_info)
                    self.covered_lines.add(line_info)
                    self.coverage_by_input[input_str].add(line_info)
                    
        return new_lines
        
    def save_coverage_report(self):
        """Generate and save coverage report."""
        report_path = os.path.join(self.config.coverage_dir, 'coverage_report.html')
        self.cov.html_report(directory=self.config.coverage_dir)
        
        # Save detailed coverage information
        coverage_data = {
            'total_lines': len(self.covered_lines),
            'coverage_by_input': {
                input_str: list(lines) 
                for input_str, lines in self.coverage_by_input.items()
            }
        }
        
        with open(os.path.join(self.config.coverage_dir, 'coverage_data.json'), 'w') as f:
            json.dump(coverage_data, f, indent=2)

class CrashAnalyzer:
    """Analyzes and categorizes crashes."""
    
    def __init__(self, config: FuzzConfig):
        self.config = config
        self.crashes = defaultdict(list)
        os.makedirs(config.crash_dir, exist_ok=True)
        
    def analyze_crash(self, input_str: str, exception: Exception) -> str:
        """Analyze crash and return crash ID."""
        crash_hash = self._generate_crash_hash(exception)
        crash_info = {
            'input': input_str,
            'exception_type': type(exception).__name__,
            'exception_message': str(exception),
            'timestamp': time.time(),
            'stack_trace': self._get_stack_trace(exception)
        }
        
        self.crashes[crash_hash].append(crash_info)
        self._save_crash(crash_hash, crash_info)
        return crash_hash
        
    def _generate_crash_hash(self, exception: Exception) -> str:
        """Generate unique hash for crash type."""
        return hashlib.md5(
            f"{type(exception).__name__}:{str(exception)}".encode()
        ).hexdigest()
        
    def _get_stack_trace(self, exception: Exception) -> str:
        """Get formatted stack trace."""
        import traceback
        return ''.join(traceback.format_tb(exception.__traceback__))
        
    def _save_crash(self, crash_hash: str, crash_info: dict):
        """Save crash information to file."""
        crash_path = os.path.join(self.config.crash_dir, f"crash_{crash_hash}.json")
        with open(crash_path, 'w') as f:
            json.dump(crash_info, f, indent=2)
            
    def generate_report(self) -> dict:
        """Generate comprehensive crash report."""
        report = {
            'total_unique_crashes': len(self.crashes),
            'crashes_by_type': defaultdict(int),
            'crashes_by_hash': {}
        }
        
        for crash_hash, crash_list in self.crashes.items():
            crash_type = crash_list[0]['exception_type']
            report['crashes_by_type'][crash_type] += 1
            report['crashes_by_hash'][crash_hash] = {
                'type': crash_type,
                'count': len(crash_list),
                'first_seen': min(c['timestamp'] for c in crash_list),
                'last_seen': max(c['timestamp'] for c in crash_list),
                'sample_input': crash_list[0]['input']
            }
            
        return report

class Fuzzer:
    """Enhanced fuzzer with coverage tracking and crash analysis."""
    
    def __init__(self, target_function: Callable, config: FuzzConfig):
        self.target_function = target_function
        self.config = config
        self.generator = InputGenerator(config)
        self.coverage_tracker = CoverageTracker(config)
        self.crash_analyzer = CrashAnalyzer(config)
        self.setup_logging()
        
    def setup_logging(self):
        """Configure logging settings."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.config.output_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
    def test_input(self, fuzz_input: str) -> Tuple[bool, Optional[Exception]]:
        """Test a single input and return crash status and exception."""
        try:
            self.coverage_tracker.start()
            self.target_function(fuzz_input)
            new_coverage = self.coverage_tracker.get_new_coverage(fuzz_input)
            self.coverage_tracker.stop()
            
            if new_coverage:
                self.generator.save_to_corpus(fuzz_input)
                logging.info(f"New coverage found with input: {fuzz_input}")
                
            return False, None
            
        except Exception as e:
            self.coverage_tracker.stop()
            crash_hash = self.crash_analyzer.analyze_crash(fuzz_input, e)
            logging.error(f"Crash {crash_hash} found with input: {fuzz_input}")
            logging.error(f"Exception: {str(e)}")
            return True, e
            
    def run(self) -> Dict:
        """Run the fuzzing process with enhanced strategies."""
        start_time = time.time()
        crashes = []
        stats = defaultdict(int)
        
        logging.info(f"Starting fuzzing with {self.config.iterations} iterations")
        
        strategies = ["random", "mutation", "interesting", "template"]
        
        for i in range(self.config.iterations):
            if i % 100 == 0:
                logging.info(f"Completed {i} iterations...")
                
            # Rotate through strategies
            strategy = strategies[i % len(strategies)]
            stats[f'strategy_{strategy}'] += 1
            
            fuzz_input = self.generator.generate_input(strategy)
            crashed, exception = self.test_input(fuzz_input)
            
            if crashed:
                crashes.append((fuzz_input, exception))
                stats['crashes'] += 1
            
            stats['total_executions'] += 1
                
        duration = time.time() - start_time
        
        # Generate final reports
        self.coverage_tracker.save_coverage_report()
        crash_report = self.crash_analyzer.generate_report()
        
        # Compile final statistics
        final_stats = {
            'duration': f"{duration:.2f} seconds",
            'total_executions': stats['total_executions'],
            'unique_crashes': len(crash_report['crashes_by_hash']),
            'total_crashes': stats['crashes'],
            'coverage': len(self.coverage_tracker.covered_lines),
            'strategy_distribution': {
                k: v for k, v in stats.items() 
                if k.startswith('strategy_')
            }
        }
        
        # Save final report
        report = {
            'stats': final_stats,
            'crash_report': crash_report
        }
        
        report_path = os.path.join(self.config.crash_dir, 'fuzzing_report.json')
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
            
        logging.info("Fuzzing completed. Final statistics:")
        for key, value in final_stats.items():
            logging.info(f"{key}: {value}")
            
        return report

def main():
    parser = argparse.ArgumentParser(description='Enhanced Python Black Box Fuzzer')
    parser.add_argument('--min-length', type=int, default=1,
                      help='Minimum length of generated inputs')
    parser.add_argument('--max-length', type=int, default=100,
                      help='Maximum length of generated inputs')
    parser.add_argument('--iterations', type=int, default=1000,
                      help='Number of fuzzing iterations')
    parser.add_argument('--seed', type=int, help='Random seed for reproducibility')
    parser.add_argument('--output', type=str, default='fuzzer_output.txt',
                      help='Output file for logging')
    parser.add_argument('--char-types', nargs='+', 
                      choices=['ascii_letters', 'digits', 'punctuation', 
                              'whitespace', 'special', 'format_strings',
                              'sql_injection', 'buffer_overflow'],
                      help='Character types to use in generation')
    parser.add_argument('--mutation-rate', type=float, default=0.2,
                      help='Rate of mutation for mutation strategy')
    parser.add_argument('--corpus-dir', type=str, default='corpus',
                      help='Directory for input corpus')
    parser.add_argument('--crash-dir', type=str, default='crashes',
                      help='Directory for crash information')
    parser.add_argument('--coverage-dir', type=str, default='coverage',
                      help='Directory for coverage reports')
    
    args = parser.parse_args()
    
    # Example target function with various vulnerability types
    def example_target(input_str: str):
        # Buffer overflow simulation
        if len(input_str) > 1000:
            raise MemoryError("Buffer overflow!")
            
        # SQL injection simulation
        if any(keyword in input_str.lower() for keyword in ['select', 'union', 'drop']):
            raise ValueError("SQL Injection detected!")
            
        # Format string vulnerability simulation
        try:
            _ = input_str % tuple(range(10))
        except:
            if '%n' in input_str:
                raise ValueError("Format string vulnerability!")
                
        # Division by zero simulation
        if 'divide_by_zero' in input_str:
            x = 1 / 0
            
        # Null pointer simulation
        if 'null_pointer' in input_str:
            raise AttributeError("Null pointer dereference!")
            
        # Path traversal simulation
        if '../' in input_str or '..\\' in input_str:
            raise PermissionError("Path traversal detected!")
    
    config = FuzzConfig(
        min_length=args.min_length,
        max_length=args.max_length,
        iterations=args.iterations,
        seed=args.seed,
        output_file=args.output,
        char_types=args.char_types,
        mutation_rate=args.mutation_rate,
        corpus_dir=args.corpus_dir,
        crash_dir=args.crash_dir,
        coverage_dir=args.coverage_dir
    )
    
    fuzzer = Fuzzer(example_target, config)
    report = fuzzer.run()
    
    print("\nFuzzing completed! Summary:")
    print(f"Total executions: {report['stats']['total_executions']}")
    print(f"Unique crashes found: {report['stats']['unique_crashes']}")
    print(f"Lines covered: {report['stats']['coverage']}")
    print(f"\nDetailed reports have been saved to:")
    print(f"- Crashes: {args.crash_dir}/fuzzing_report.json")
    print(f"- Coverage: {args.coverage_dir}/coverage_report.html")

if __name__ == "__main__":
    main()
