"""Example utilities with intentional issues for testing code review."""

import pickle
import subprocess
import os


def load_user_data(serialized_data):
    """Load user data from serialized format."""
    # Security issue: unsafe pickle deserialization
    return pickle.loads(serialized_data)


def run_command(user_input):
    """Run a shell command based on user input."""
    # Security issue: command injection
    result = subprocess.run(f"echo {user_input}", shell=True, capture_output=True)
    return result.stdout.decode()


def read_file(filename):
    """Read a file from disk."""
    # Security issue: path traversal
    path = f"/data/{filename}"
    with open(path, "r") as f:
        return f.read()


def divide_numbers(a, b):
    """Divide two numbers."""
    # Code quality issue: no zero division check
    return a / b


def process_items(items):
    """Process a list of items."""
    results = []
    for i in range(len(items)):
        # Code quality issue: inefficient iteration
        for j in range(len(items)):
            if items[i] == items[j]:
                results.append(items[i])
    return results


def get_user_by_id(user_id, connection):
    """Get user from database."""
    # Security issue: SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return connection.execute(query)
