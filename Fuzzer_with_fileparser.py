# vulnerable_parser.py (The program we want to test)
def parse_config_file(content):
    if len(content) > 1000:  # Vulnerable to buffer overflow
        return content.upper()
    
    if "system(" in content:  # Vulnerable to command injection
        eval(content)  # Very unsafe!
    
    return content.split(',')

# fuzzing_test.py (Our fuzzing script)
from fuzzer import Fuzzer, FuzzConfig

def main():
    # Create a wrapper function that calls our target program
    def target_function(input_str):
        return parse_config_file(input_str)
    
    config = FuzzConfig(
        min_length=1,
        max_length=2000,  # Large enough to trigger buffer overflow
        iterations=1000,
        char_types=['ascii_letters', 'special']
    )
    
    fuzzer = Fuzzer(target_function, config)
    fuzzer.run()

main()
