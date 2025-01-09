# fuzzing_test.py
import socket
from fuzzer import Fuzzer, FuzzConfig

def main():
    def target_function(input_str):
        # Test a network service
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(('localhost', 12345))
            sock.send(input_str.encode())
            response = sock.recv(1024)
            return response
        except Exception as e:
            raise Exception(f"Network error: {str(e)}")
        finally:
            sock.close()
    
    config = FuzzConfig(
        min_length=1,
        max_length=1000,
        char_types=['ascii_letters', 'special', 'buffer_overflow'],
        iterations=500
    )
    
    fuzzer = Fuzzer(target_function, config)
    fuzzer.run()

main()
