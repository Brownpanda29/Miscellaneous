# fuzzing_test.py
import subprocess
from fuzzer import Fuzzer, FuzzConfig

def main():
    def target_function(input_str):
        try:
            # Test a command-line program
            # IMPORTANT: Be careful with command injection!
            result = subprocess.run(
                ['./vulnerable_program', input_str],
                capture_output=True,
                timeout=1
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            raise Exception("Program hanged")
        except Exception as e:
            raise Exception(f"Program crashed: {str(e)}")
    
    config = FuzzConfig(
        min_length=1,
        max_length=100,
        iterations=1000
    )
    
    fuzzer = Fuzzer(target_function, config)
    fuzzer.run()

main()
