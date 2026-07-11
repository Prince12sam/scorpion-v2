import subprocess


def run_user_command(user_input: str) -> str:
    result = subprocess.run(user_input, shell=True, capture_output=True, text=True)
    return result.stdout


def evaluate(expr: str):
    return eval(expr)
