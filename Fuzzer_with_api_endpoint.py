# vulnerable_api.py (The API we want to test)
from flask import Flask, request

app = Flask(__name__)

@app.route('/api/user')
def get_user():
    user_id = request.args.get('id')
    # Vulnerable to SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query

# fuzzing_test.py
from fuzzer import Fuzzer, FuzzConfig
from vulnerable_api import app

def main():
    # Create a test client
    client = app.test_client()
    
    def target_function(input_str):
        # Send requests to our API with fuzzed input
        response = client.get(f'/api/user?id={input_str}')
        return response.data
    
    config = FuzzConfig(
        min_length=1,
        max_length=100,
        char_types=['digits', 'sql_injection'],  # Include SQL injection patterns
        iterations=500
    )
    
    fuzzer = Fuzzer(target_function, config)
    fuzzer.run()

main()
